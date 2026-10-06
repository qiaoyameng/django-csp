"""
Read-only analyzer for Content Security Policies.

The analyzer accepts either a structured policy (a directives dict, or a
django-csp config dict with a ``"DIRECTIVES"`` key) or a complete policy
string, and explains how a browser would interpret it at a given CSP level.

It reports duplicate directives, invalid source expressions, and incompatible
keyword combinations, then resolves the effective source list for script
elements, script attributes, styles, and common resource types -- including
which values are ignored by the rules of the CSP version in use and which
values come from a fallback directive (usually ``default-src``).

The output is descriptive only. It is not a security audit and deliberately
avoids scoring policies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Union

from csp.constants import NONCE, Nonce

CSP2 = 2
CSP3 = 3
SUPPORTED_VERSIONS = (CSP2, CSP3)

DISCLAIMER = (
    "This report describes Content Security Policy directive semantics only. "
    "It is not a security audit and does not assign a security score."
)

# Placeholder used when the NONCE sentinel appears in a structured config.
NONCE_PLACEHOLDER = "'nonce-*'"

# Directives that take a source list, mapped to the CSP level that
# introduced them.
FETCH_DIRECTIVES = {
    "base-uri": CSP2,
    "child-src": CSP2,
    "connect-src": CSP2,
    "default-src": CSP2,
    "font-src": CSP2,
    "form-action": CSP2,
    "frame-ancestors": CSP2,
    "frame-src": CSP2,
    "img-src": CSP2,
    "manifest-src": CSP3,
    "media-src": CSP2,
    "object-src": CSP2,
    "prefetch-src": CSP3,
    "script-src": CSP2,
    "script-src-attr": CSP3,
    "script-src-elem": CSP3,
    "style-src": CSP2,
    "style-src-attr": CSP3,
    "style-src-elem": CSP3,
    "worker-src": CSP3,
}

# Known directives that do not take a source list.
OTHER_DIRECTIVES = {
    "block-all-mixed-content": CSP2,
    "navigate-to": CSP3,
    "plugin-types": CSP2,
    "report-to": CSP3,
    "report-uri": CSP2,
    "require-sri-for": CSP2,
    "require-trusted-types-for": CSP3,
    "sandbox": CSP2,
    "trusted-types": CSP3,
    "upgrade-insecure-requests": CSP2,
    "webrtc": CSP2,
}

# Keyword sources mapped to the CSP level that introduced them.
KEYWORD_SOURCES = {
    "'self'": CSP2,
    "'none'": CSP2,
    "'unsafe-inline'": CSP2,
    "'unsafe-eval'": CSP2,
    "'strict-dynamic'": CSP3,
    "'unsafe-hashes'": CSP3,
    "'report-sample'": CSP3,
    "'unsafe-allow-redirects'": CSP3,
    "'wasm-unsafe-eval'": CSP3,
    "'inline-speculation-rules'": CSP3,
}

# Directives in which a nonce or hash source has an effect.
NONCE_HASH_DIRECTIVES = {
    "script-src",
    "script-src-elem",
    "script-src-attr",
    "style-src",
    "style-src-elem",
    "style-src-attr",
}

# Directives in which specific keyword sources have an effect.
KEYWORD_APPLICABILITY = {
    "'unsafe-inline'": {"script-src", "script-src-elem", "script-src-attr", "style-src", "style-src-elem", "style-src-attr"},
    "'unsafe-eval'": {"script-src", "script-src-elem"},
    "'wasm-unsafe-eval'": {"script-src", "script-src-elem"},
    "'strict-dynamic'": {"script-src", "script-src-elem"},
    "'unsafe-hashes'": {"script-src", "script-src-attr"},
    "'report-sample'": {"script-src", "script-src-elem", "script-src-attr", "style-src", "style-src-elem", "style-src-attr"},
}

# Fallback chains for the resource types the analyzer resolves. Each chain is
# consulted in order; entries are filtered by the CSP level in use.
RESOURCE_CHAINS = {
    "script-elem": ("script-src-elem", "script-src", "default-src"),
    "script-attr": ("script-src-attr", "script-src", "default-src"),
    "style-elem": ("style-src-elem", "style-src", "default-src"),
    "style-attr": ("style-src-attr", "style-src", "default-src"),
    "img": ("img-src", "default-src"),
    "font": ("font-src", "default-src"),
    "connect": ("connect-src", "default-src"),
    "media": ("media-src", "default-src"),
    "object": ("object-src", "default-src"),
    "manifest": ("manifest-src", "default-src"),
    "prefetch": ("prefetch-src", "default-src"),
    "frame": ("frame-src", "child-src", "default-src"),
    "worker": ("worker-src", "child-src", "script-src", "default-src"),
    "base-uri": ("base-uri",),
    "form-action": ("form-action",),
    "frame-ancestors": ("frame-ancestors",),
}

_DIRECTIVE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]*$")
_NONCE_RE = re.compile(r"^'nonce-[A-Za-z0-9+/_*-]+={0,2}'$")
_HASH_RE = re.compile(r"^'(?:sha256|sha384|sha512)-[A-Za-z0-9+/_-]+={0,2}'$")
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:$")
_HOST_RE = re.compile(
    r"^(?:[A-Za-z][A-Za-z0-9+.-]*://)?"  # optional scheme
    r"(?:\*|\*\.[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)"  # host
    r"(?::(?:\*|\d+))?"  # optional port
    r"(?:/\S*)?$"  # optional path
)
_QUOTED_RE = re.compile(r"^'[^']*'$")


def classify_source(value: str) -> str:
    """Classify a single source expression.

    Returns one of: ``"keyword"``, ``"nonce"``, ``"hash"``, ``"scheme"``,
    ``"host"``, ``"keyword-unknown"`` (quoted like a keyword but not
    recognized -- possibly an extension), or ``"invalid"``.
    """
    if value in KEYWORD_SOURCES:
        return "keyword"
    if _NONCE_RE.match(value):
        return "nonce"
    if _HASH_RE.match(value):
        return "hash"
    if _SCHEME_RE.match(value):
        return "scheme"
    if _HOST_RE.match(value):
        return "host"
    if _QUOTED_RE.match(value):
        return "keyword-unknown"
    return "invalid"


@dataclass(frozen=True)
class Issue:
    """A single problem or observation about a policy."""

    code: str
    message: str
    directive: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class SourceVerdict:
    """How one source expression in an effective source list is treated."""

    value: str
    status: str  # "effective" | "ignored" | "unknown"
    reason: str = ""


@dataclass
class DirectiveReport:
    """Analysis of one directive as written in the policy."""

    name: str
    values: list[str]
    known: bool
    issues: list[Issue] = field(default_factory=list)
    ignored: list[tuple[str, str]] = field(default_factory=list)  # (value, reason)

    @property
    def empty(self) -> bool:
        return not self.values


@dataclass
class ResourceReport:
    """The effective constraint for one resource type."""

    resource: str
    chain: list[str]  # fallback chain consulted, in order
    directive: str | None  # directive that supplied the effective source list
    via_fallback: bool
    sources: list[SourceVerdict] = field(default_factory=list)
    note: str = ""


@dataclass
class PolicyReport:
    """Analysis of a single policy."""

    index: int
    origin: str  # "text" | "config"
    version: int
    directives: list[DirectiveReport]
    resources: list[ResourceReport]
    issues: list[Issue]

    def directive(self, name: str) -> DirectiveReport | None:
        for report in self.directives:
            if report.name == name:
                return report
        return None

    def resource(self, name: str) -> ResourceReport | None:
        for report in self.resources:
            if report.resource == name:
                return report
        return None


@dataclass
class AnalysisReport:
    """Combined analysis of one or more policies."""

    version: int
    policies: list[PolicyReport]
    combined: list[str]
    disclaimer: str = DISCLAIMER


@dataclass(frozen=True)
class _ParsedDirective:
    name: str
    values: list[str]


def parse_policy_text(text: str) -> tuple[list[_ParsedDirective], list[Issue]]:
    """Parse a complete policy string into directives.

    Duplicate directives are reported; per the CSP spec only the first
    occurrence is used.
    """
    directives: list[_ParsedDirective] = []
    issues: list[Issue] = []
    seen: set[str] = set()
    for part in text.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        values = tokens[1:]
        if not _DIRECTIVE_NAME_RE.match(name):
            issues.append(Issue("invalid-directive", f"{tokens[0]!r} is not a valid directive name.", directive=tokens[0]))
            continue
        if name in seen:
            issues.append(
                Issue(
                    "duplicate-directive",
                    f"Directive {name!r} appears more than once; only the first occurrence is used.",
                    directive=name,
                )
            )
            continue
        seen.add(name)
        directives.append(_ParsedDirective(name, values))
    return directives, issues


def parse_config(config: dict[str, Any]) -> tuple[list[_ParsedDirective], list[Issue]]:
    """Normalize a structured policy into directives.

    Accepts a plain directives dict or a django-csp config dict with a
    ``"DIRECTIVES"`` key. ``None``/``False`` values mean "not set", ``True``
    means a valueless directive, and the ``NONCE`` sentinel becomes a
    placeholder nonce token.
    """
    if "DIRECTIVES" in config and isinstance(config["DIRECTIVES"], dict):
        config = config["DIRECTIVES"]
    directives: list[_ParsedDirective] = []
    issues: list[Issue] = []
    for raw_name, value in config.items():
        name = str(raw_name).lower()
        if value is None or value is False:
            continue
        if value is True:
            values: list[str] = []
        elif isinstance(value, (list, tuple, set)):
            values = [_normalize_value(v) for v in value]
        else:
            values = [_normalize_value(value)]
        values = [v for v in values if v]
        if not _DIRECTIVE_NAME_RE.match(name):
            issues.append(Issue("invalid-directive", f"{raw_name!r} is not a valid directive name.", directive=str(raw_name)))
            continue
        directives.append(_ParsedDirective(name, values))
    return directives, issues


def _normalize_value(value: Any) -> str:
    if value is NONCE or isinstance(value, Nonce):
        return NONCE_PLACEHOLDER
    return str(value).strip()


def _ignored_values(name: str, values: list[str], version: int) -> list[tuple[str, str]]:
    """Compute which values of a fetch directive are ignored, and why."""
    ignored: list[tuple[str, str]] = []
    if "'none'" in values and len(values) > 1:
        ignored.append(("'none'", "'none' has no effect when combined with other source expressions"))
    for value in values:
        min_version = KEYWORD_SOURCES.get(value)
        if min_version is not None and min_version > version:
            ignored.append((value, f"{value} requires CSP Level {min_version} and is ignored at Level {version}"))
    if version >= CSP3:
        kinds = {value: classify_source(value) for value in values}
        if "'strict-dynamic'" in values and name in ("script-src", "script-src-elem"):
            for value in values:
                if kinds[value] == "host" or kinds[value] == "scheme" or value == "'self'":
                    ignored.append((value, "ignored because 'strict-dynamic' is present (CSP Level 3)"))
        if name in ("script-src", "script-src-elem", "style-src", "style-src-elem"):
            has_nonce_or_hash = any(kinds[value] in ("nonce", "hash") for value in values)
            if has_nonce_or_hash and "'unsafe-inline'" in values:
                ignored.append(("'unsafe-inline'", "ignored because a nonce or hash source is present (CSP Level 3)"))
    return ignored


def _validate_directive(parsed: _ParsedDirective, version: int) -> DirectiveReport:
    name = parsed.name
    values = parsed.values
    issues: list[Issue] = []
    known = name in FETCH_DIRECTIVES or name in OTHER_DIRECTIVES
    if not known:
        issues.append(Issue("unknown-directive", f"{name!r} is not a recognized CSP directive; it is kept with unknown status.", directive=name))
        return DirectiveReport(name=name, values=values, known=False, issues=issues)

    min_version = FETCH_DIRECTIVES.get(name) or OTHER_DIRECTIVES.get(name) or CSP2
    if min_version > version:
        issues.append(
            Issue(
                "unsupported-version",
                f"{name!r} requires CSP Level {min_version} and is ignored at Level {version}.",
                directive=name,
            )
        )

    ignored: list[tuple[str, str]] = []
    if name in FETCH_DIRECTIVES:
        if not values:
            issues.append(
                Issue(
                    "empty-directive",
                    f"{name!r} is present with an empty source list; it blocks all matching loads, like 'none'.",
                    directive=name,
                )
            )
        for value in values:
            kind = classify_source(value)
            if kind == "invalid":
                issues.append(Issue("invalid-source", f"{value!r} is not a valid source expression.", directive=name, value=value))
            elif kind == "keyword-unknown":
                issues.append(
                    Issue(
                        "unknown-keyword",
                        f"{value!r} is not a recognized CSP keyword; it is kept with unknown status (possibly an extension).",
                        directive=name,
                        value=value,
                    )
                )
            else:
                keyword_min = KEYWORD_SOURCES.get(value)
                if keyword_min is not None and keyword_min > version:
                    issues.append(
                        Issue(
                            "unsupported-version",
                            f"{value} requires CSP Level {keyword_min} and is ignored at Level {version}.",
                            directive=name,
                            value=value,
                        )
                    )
                applicable = KEYWORD_APPLICABILITY.get(value)
                if applicable is not None and name not in applicable:
                    issues.append(
                        Issue("misplaced-source", f"{value} has no effect in the {name!r} directive.", directive=name, value=value)
                    )
                if kind in ("nonce", "hash") and name not in NONCE_HASH_DIRECTIVES:
                    issues.append(
                        Issue("misplaced-source", f"A {kind} source has no effect in the {name!r} directive.", directive=name, value=value)
                    )
        ignored = _ignored_values(name, values, version)
    return DirectiveReport(name=name, values=values, known=known, issues=issues, ignored=ignored)


def _source_verdicts(report: DirectiveReport) -> list[SourceVerdict]:
    ignored = dict(report.ignored)
    verdicts = []
    for value in report.values:
        if value in ignored:
            verdicts.append(SourceVerdict(value=value, status="ignored", reason=ignored[value]))
            continue
        kind = classify_source(value)
        if kind == "invalid":
            verdicts.append(SourceVerdict(value=value, status="unknown", reason="not a valid source expression"))
        elif kind == "keyword-unknown":
            verdicts.append(SourceVerdict(value=value, status="unknown", reason="unrecognized keyword; possibly an extension"))
        else:
            verdicts.append(SourceVerdict(value=value, status="effective"))
    return verdicts


def _analyze_resources(directives: dict[str, DirectiveReport], version: int) -> list[ResourceReport]:
    reports = []
    for resource, chain in RESOURCE_CHAINS.items():
        chain = [name for name in chain if FETCH_DIRECTIVES.get(name, CSP3) <= version]
        effective = next((name for name in chain if name in directives), None)
        if effective is None:
            reports.append(
                ResourceReport(
                    resource=resource,
                    chain=chain,
                    directive=None,
                    via_fallback=False,
                    note="no directive in the fallback chain is set; this resource type is not restricted by this policy",
                )
            )
            continue
        report = directives[effective]
        note = ""
        if report.empty:
            note = f"{effective!r} is present with an empty source list; all loads of this type are blocked, like 'none'"
        reports.append(
            ResourceReport(
                resource=resource,
                chain=chain,
                directive=effective,
                via_fallback=effective != chain[0],
                sources=_source_verdicts(report),
                note=note,
            )
        )
    return reports


def _analyze_policy(index: int, origin: str, parsed: list[_ParsedDirective], parse_issues: list[Issue], version: int) -> PolicyReport:
    directive_reports = [_validate_directive(p, version) for p in parsed]
    known_fetch = {r.name: r for r in directive_reports if r.known and r.name in FETCH_DIRECTIVES}
    resources = _analyze_resources(known_fetch, version)
    issues = list(parse_issues)
    for report in directive_reports:
        issues.extend(report.issues)
    return PolicyReport(index=index, origin=origin, version=version, directives=directive_reports, resources=resources, issues=issues)


def _combine(policies: list[PolicyReport]) -> list[str]:
    if len(policies) < 2:
        return []
    notes = [
        f"{len(policies)} policies are active simultaneously; a load must be allowed by every policy (intersection semantics)."
    ]
    for resource in RESOURCE_CHAINS:
        parts = []
        for policy in policies:
            report = policy.resource(resource)
            if report is None:
                continue
            if report.directive is None:
                parts.append(f"policy {policy.index}: unrestricted")
            elif not report.sources:
                parts.append(f"policy {policy.index}: blocked by empty {report.directive!r}")
            else:
                parts.append(f"policy {policy.index}: constrained by {report.directive!r}")
        notes.append(f"{resource}: " + "; ".join(parts))
    return notes


PolicyInput = Union[str, dict[str, Any]]


def analyze(policies: PolicyInput | list[PolicyInput], version: int = CSP3) -> AnalysisReport:
    """Analyze one or more CSP policies without modifying them.

    ``policies`` may be a single policy or a list of policies, where each
    policy is either a complete policy string or a structured config dict.
    When several policies are given, the report explains the intersection
    semantics browsers apply.
    """
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported CSP version {version!r}; expected one of {SUPPORTED_VERSIONS}.")
    if isinstance(policies, (str, dict)):
        policies = [policies]
    reports = []
    for index, policy in enumerate(policies):
        if isinstance(policy, str):
            parsed, issues = parse_policy_text(policy)
            origin = "text"
        elif isinstance(policy, dict):
            parsed, issues = parse_config(policy)
            origin = "config"
        else:
            raise TypeError(f"Unsupported policy input of type {type(policy).__name__!r}; expected str or dict.")
        reports.append(_analyze_policy(index, origin, parsed, issues, version))
    return AnalysisReport(version=version, policies=reports, combined=_combine(reports))


def render_text(report: AnalysisReport) -> str:
    """Render an analysis report as human-readable text."""
    lines = [f"CSP analysis (Level {report.version})", report.disclaimer]
    for policy in report.policies:
        lines.append("")
        lines.append(f"Policy {policy.index} ({policy.origin}):")
        if policy.issues:
            lines.append("  Issues:")
            for issue in policy.issues:
                location = f" [{issue.directive}]" if issue.directive else ""
                lines.append(f"    - {issue.code}{location}: {issue.message}")
        else:
            lines.append("  Issues: none")
        lines.append("  Effective constraints:")
        for resource in policy.resources:
            if resource.directive is None:
                lines.append(f"    - {resource.resource}: unrestricted ({resource.note})")
                continue
            origin = resource.directive
            if resource.via_fallback:
                origin += " (via fallback: " + " -> ".join(resource.chain) + ")"
            lines.append(f"    - {resource.resource}: {origin}")
            if resource.note:
                lines.append(f"        {resource.note}")
            for source in resource.sources:
                suffix = f" -- {source.reason}" if source.reason else ""
                lines.append(f"        {source.status}: {source.value}{suffix}")
    if report.combined:
        lines.append("")
        lines.append("Combined policies:")
        for note in report.combined:
            lines.append(f"  - {note}")
    return "\n".join(lines)
