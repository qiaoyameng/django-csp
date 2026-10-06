from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from csp.constants import NONCE


FETCH_DIRECTIVES = {
    "child-src",
    "connect-src",
    "default-src",
    "font-src",
    "frame-src",
    "img-src",
    "manifest-src",
    "media-src",
    "object-src",
    "prefetch-src",
    "script-src",
    "script-src-attr",
    "script-src-elem",
    "style-src",
    "style-src-attr",
    "style-src-elem",
    "worker-src",
}

NAVIGATION_DIRECTIVES = {"base-uri", "form-action", "navigate-to"}
SOURCE_DIRECTIVES = FETCH_DIRECTIVES | NAVIGATION_DIRECTIVES
VALUELESS_DIRECTIVES = {"block-all-mixed-content", "upgrade-insecure-requests"}

KNOWN_DIRECTIVES = SOURCE_DIRECTIVES | {
    "block-all-mixed-content",
    "frame-ancestors",
    "plugin-types",
    "report-to",
    "report-uri",
    "require-sri-for",
    "require-trusted-types-for",
    "sandbox",
    "trusted-types",
    "upgrade-insecure-requests",
    "webrtc",
}

CSP1_DIRECTIVES = {
    "connect-src",
    "default-src",
    "font-src",
    "frame-src",
    "img-src",
    "media-src",
    "object-src",
    "plugin-types",
    "report-uri",
    "sandbox",
    "script-src",
    "style-src",
}
CSP2_DIRECTIVES = CSP1_DIRECTIVES | {
    "base-uri",
    "block-all-mixed-content",
    "child-src",
    "form-action",
    "frame-ancestors",
    "plugin-types",
    "upgrade-insecure-requests",
}
CSP3_DIRECTIVES = (CSP2_DIRECTIVES - {"plugin-types"}) | {
    "manifest-src",
    "navigate-to",
    "prefetch-src",
    "report-to",
    "require-sri-for",
    "require-trusted-types-for",
    "script-src-attr",
    "script-src-elem",
    "style-src-attr",
    "style-src-elem",
    "trusted-types",
    "webrtc",
    "worker-src",
}

KEYWORD_NONE = "'none'"
KEYWORD_SELF = "'self'"
KEYWORD_STRICT_DYNAMIC = "'strict-dynamic'"
KEYWORD_UNSAFE_INLINE = "'unsafe-inline'"

SCRIPT_KEYWORDS = {
    "'report-sample'",
    "'strict-dynamic'",
    "'unsafe-eval'",
    "'unsafe-hashes'",
    "'unsafe-inline'",
    "'wasm-unsafe-eval'",
}
STYLE_KEYWORDS = {"'report-sample'", "'unsafe-inline'"}
CSP3_SOURCE_KEYWORDS = {"'report-sample'", "'strict-dynamic'", "'unsafe-hashes'", "'wasm-unsafe-eval'"}
SANDBOX_TOKENS = {
    "allow-downloads",
    "allow-downloads-without-user-activation",
    "allow-forms",
    "allow-modals",
    "allow-orientation-lock",
    "allow-pointer-lock",
    "allow-popups",
    "allow-popups-to-escape-sandbox",
    "allow-presentation",
    "allow-same-origin",
    "allow-scripts",
    "allow-storage-access-by-user-activation",
    "allow-top-navigation",
    "allow-top-navigation-by-user-activation",
    "allow-top-navigation-to-custom-protocols",
}

SCHEME_SOURCE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:$")
HOST_SOURCE_RE = re.compile(
    r"^(?:[A-Za-z][A-Za-z0-9+.-]*://)?"
    r"(?:\*\.)?(?:\*|[A-Za-z0-9._~%=-]+|\[[^\]]+\])"
    r"(?::\*|:\d+)?(?:/[^\s']*)?$"
)
MEDIA_TYPE_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")
NONCE_RE = re.compile(r"^'nonce-([A-Za-z0-9+/=]+)'$")
HASH_RE = re.compile(r"^'(sha256|sha384|sha512)-([A-Za-z0-9+/=]+)'$")
HASH_LENGTHS = {"sha256": 32, "sha384": 48, "sha512": 64}

FindingSeverity = Literal["error", "warning", "info"]
TokenStatus = Literal["valid", "ignored", "invalid", "unknown"]
PolicyVersion = Literal[1, 2, 3]


@dataclass(frozen=True)
class SourceLocation:
    policy_index: int
    directive: str
    directive_occurrence: int = 0
    value_index: int | None = None
    start: int = -1
    end: int = -1

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_index": self.policy_index,
            "directive": self.directive,
            "directive_occurrence": self.directive_occurrence,
            "value_index": self.value_index,
            "start": self.start,
            "end": self.end,
        }


@dataclass
class Finding:
    code: str
    message: str
    severity: FindingSeverity
    locations: list[SourceLocation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
            "locations": [location.to_dict() for location in self.locations],
        }


@dataclass
class LocatedToken:
    value: str
    location: SourceLocation
    kind: str = "unknown"
    status: TokenStatus = "valid"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "kind": self.kind,
            "status": self.status,
            "reasons": list(self.reasons),
            "location": self.location.to_dict(),
        }


@dataclass
class DirectiveOccurrence:
    name: str
    raw_name: str
    location: SourceLocation
    values: list[LocatedToken]
    explicitly_empty: bool = False
    ignored: bool = False
    ignore_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "raw_name": self.raw_name,
            "explicitly_empty": self.explicitly_empty,
            "ignored": self.ignored,
            "ignore_reason": self.ignore_reason,
            "location": self.location.to_dict(),
            "values": [value.to_dict() for value in self.values],
        }


@dataclass
class ParsedDirective:
    name: str
    occurrences: list[DirectiveOccurrence] = field(default_factory=list)

    @property
    def effective_occurrence(self) -> DirectiveOccurrence | None:
        for occurrence in self.occurrences:
            if not occurrence.ignored:
                return occurrence
        return self.occurrences[0] if self.occurrences else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "occurrences": [occurrence.to_dict() for occurrence in self.occurrences],
        }


@dataclass
class EffectiveConstraint:
    target: str
    label: str
    status: Literal["allowed-by-default", "defined", "fallback", "empty", "unknown"]
    directive: str | None = None
    fallback_chain: list[str] = field(default_factory=list)
    values: list[LocatedToken] = field(default_factory=list)
    ignored_values: list[LocatedToken] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "label": self.label,
            "status": self.status,
            "directive": self.directive,
            "fallback_chain": list(self.fallback_chain),
            "values": [value.to_dict() for value in self.values],
            "ignored_values": [value.to_dict() for value in self.ignored_values],
            "notes": list(self.notes),
        }


@dataclass
class PolicyAnalysis:
    index: int
    name: str
    disposition: Literal["enforce", "report-only", "unknown"]
    source_type: Literal["text", "structured"]
    text: str | None
    directives: dict[str, ParsedDirective]
    findings: list[Finding]
    effective_constraints: dict[str, EffectiveConstraint]

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "disposition": self.disposition,
            "source_type": self.source_type,
            "text": self.text,
            "directives": {name: directive.to_dict() for name, directive in self.directives.items()},
            "findings": [finding.to_dict() for finding in self.findings],
            "effective_constraints": {
                target: constraint.to_dict() for target, constraint in self.effective_constraints.items()
            },
        }


@dataclass
class AnalysisReport:
    version: PolicyVersion
    policies: list[PolicyAnalysis]
    description: str = (
        "Read-only interpretation of the supplied CSP syntax and source-list rules; "
        "this is not a comprehensive security assessment or score."
    )

    def findings(self) -> list[tuple[int, Finding]]:
        return [(policy.index, finding) for policy in self.policies for finding in policy.findings]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "description": self.description,
            "policies": [policy.to_dict() for policy in self.policies],
        }


@dataclass(frozen=True)
class _PolicyInput:
    name: str
    disposition: Literal["enforce", "report-only", "unknown"]
    source_type: Literal["text", "structured"]
    value: str | Mapping[str, Any]


DIRECTIVES_BY_VERSION = {1: CSP1_DIRECTIVES, 2: CSP2_DIRECTIVES, 3: CSP3_DIRECTIVES}


def normalize_version(version: int | str) -> PolicyVersion:
    if isinstance(version, str):
        normalized = version.lower().strip()
        if normalized.startswith("csp"):
            normalized = normalized[3:]
        if normalized not in {"1", "2", "3"}:
            raise ValueError("CSP version must be one of 1, 2, or 3.")
        numeric_version = int(normalized)
    else:
        numeric_version = version
    if numeric_version not in (1, 2, 3):
        raise ValueError("CSP version must be one of 1, 2, or 3.")
    return numeric_version  # type: ignore[return-value]


def analyze_policy(
    policy: str | Mapping[str, Any],
    *,
    version: int | str = 3,
    name: str = "policy-1",
    policy_index: int = 0,
    disposition: Literal["enforce", "report-only", "unknown"] = "enforce",
) -> PolicyAnalysis:
    """Analyze one complete policy text value or structured directives mapping."""

    csp_version = normalize_version(version)
    if isinstance(policy, str):
        return _analyze_text_policy(policy, csp_version, name, policy_index, disposition)
    return _analyze_structured_policy(policy, csp_version, name, policy_index, disposition)


def analyze_csp(
    policy: str | Mapping[str, Any] | Sequence[str | Mapping[str, Any]],
    *,
    version: int | str = 3,
) -> AnalysisReport:
    """Analyze one policy or several independently delivered CSP policy values."""

    csp_version = normalize_version(version)
    inputs = _coerce_policy_inputs(policy)
    return AnalysisReport(
        version=csp_version,
        policies=[
            analyze_policy(
                item.value,
                version=csp_version,
                name=item.name,
                policy_index=index,
                disposition=item.disposition,
            )
            for index, item in enumerate(inputs)
        ],
    )


def _coerce_policy_inputs(
    policy: str | Mapping[str, Any] | Sequence[str | Mapping[str, Any]],
) -> list[_PolicyInput]:
    if isinstance(policy, (str, Mapping)):
        policies: str | Mapping[str, Any] | Sequence[str | Mapping[str, Any]] = [policy]
    elif isinstance(policy, Sequence):
        policies = policy
    else:
        raise TypeError("Policy must be text, a directives mapping, or a sequence of policies.")

    inputs: list[_PolicyInput] = []
    for index, item in enumerate(policies):
        if isinstance(item, str):
            inputs.append(_PolicyInput(f"policy-{index + 1}", "enforce", "text", item))
        elif isinstance(item, Mapping):
            inputs.append(_PolicyInput(f"policy-{index + 1}", "enforce", "structured", item))
        else:
            raise TypeError("Each policy must be text or a structured directives mapping.")
    return inputs


def _analyze_text_policy(
    text: str,
    version: PolicyVersion,
    name: str,
    index: int,
    disposition: Literal["enforce", "report-only", "unknown"],
) -> PolicyAnalysis:
    directives: dict[str, ParsedDirective] = {}
    findings: list[Finding] = []

    for start, end, raw_segment in _split_policy(text):
        stripped = raw_segment.strip()
        if not stripped:
            continue

        match = re.search(r"\s+", stripped)
        raw_name = stripped[: match.start()] if match else stripped
        value_text = stripped[match.end() :] if match else ""
        directive_name = raw_name.lower()
        name_start = start + (len(raw_segment) - len(raw_segment.lstrip()))
        occurrence_index = len(directives.get(directive_name, ParsedDirective(directive_name)).occurrences)
        location = SourceLocation(index, directive_name, occurrence_index, start=name_start, end=name_start + len(raw_name))
        values = [
            LocatedToken(
                token_text,
                SourceLocation(
                    index,
                    directive_name,
                    occurrence_index,
                    token_index,
                    name_start + match.end() + token_match.start(),
                    name_start + match.end() + token_match.end(),
                ),
            )
            for token_index, (token_text, token_match) in enumerate(_token_matches(value_text))
        ]
        occurrence = DirectiveOccurrence(
            directive_name,
            raw_name,
            location,
            values,
            explicitly_empty=bool(raw_name and not value_text.strip()),
        )
        _append_occurrence(directives, findings, occurrence)

    if not text.strip():
        findings.append(
            Finding(
                "empty-policy",
                "The policy is explicitly empty and imposes no directives by itself.",
                "info",
                [SourceLocation(index, "", start=0, end=len(text))],
            )
        )

    return _finalize_policy(text, directives, findings, version, name, index, disposition, "text")


def _append_occurrence(
    directives: dict[str, ParsedDirective],
    findings: list[Finding],
    occurrence: DirectiveOccurrence,
) -> None:
    parsed = directives.setdefault(occurrence.name, ParsedDirective(occurrence.name))
    if parsed.occurrences:
        occurrence.ignored = True
        occurrence.ignore_reason = "duplicate-directive"
        findings.append(
            Finding(
                "duplicate-directive",
                f"Duplicate directive {occurrence.name!r} is ignored; the first occurrence is used.",
                "warning",
                [occurrence.location, parsed.occurrences[0].location],
            )
        )
    parsed.occurrences.append(occurrence)


def _split_policy(text: str) -> list[tuple[int, int, str]]:
    segments: list[tuple[int, int, str]] = []
    start = 0
    for match in re.finditer(";", text):
        end = match.start()
        segments.append((start, end, text[start:end]))
        start = match.end()
    segments.append((start, len(text), text[start:]))
    return segments


def _token_matches(value_text: str) -> list[tuple[str, re.Match[str]]]:
    return [(match.group(), match) for match in re.finditer(r"\S+", value_text)]


def _analyze_structured_policy(
    config: Mapping[str, Any],
    version: PolicyVersion,
    name: str,
    index: int,
    disposition: Literal["enforce", "report-only", "unknown"],
) -> PolicyAnalysis:
    if "DIRECTIVES" in config:
        raw_directives = config["DIRECTIVES"]
    elif "directives" in config:
        raw_directives = config["directives"]
    else:
        raw_directives = config

    if not isinstance(raw_directives, Mapping):
        raise TypeError("Structured policy directives must be a mapping.")

    directives: dict[str, ParsedDirective] = {}
    findings: list[Finding] = []

    for key, raw_value in raw_directives.items():
        raw_name = str(key)
        directive_name = raw_name.lower()
        occurrence_index = len(directives.get(directive_name, ParsedDirective(directive_name)).occurrences)
        location = SourceLocation(index, directive_name, occurrence_index)
        if raw_value is None or raw_value is False:
            continue

        values: list[LocatedToken] = []
        explicitly_empty = False
        if raw_value is True:
            explicitly_empty = directive_name in VALUELESS_DIRECTIVES
            if not explicitly_empty:
                findings.append(
                    Finding(
                        "invalid-directive-value",
                        f"{directive_name!r} does not accept a valueless boolean configuration.",
                        "error",
                        [location],
                    )
                )
        elif isinstance(raw_value, str):
            if raw_value == "":
                explicitly_empty = True
            else:
                values.append(_structured_token(raw_value, index, directive_name, occurrence_index, 0))
        elif isinstance(raw_value, Mapping):
            findings.append(
                Finding(
                    "invalid-directive-value",
                    f"{directive_name!r} values must be a string, list, tuple, or set.",
                    "error",
                    [location],
                )
            )
        elif isinstance(raw_value, Sequence):
            ordered_values = (
                sorted(raw_value, key=_sortable_structured_value) if isinstance(raw_value, set) else raw_value
            )
            for value_index, raw_token in enumerate(ordered_values):
                if raw_token is None:
                    continue
                if isinstance(raw_token, str) and raw_token == "":
                    explicitly_empty = True
                    continue
                values.append(_structured_token(raw_token, index, directive_name, occurrence_index, value_index))
            if not values and not explicitly_empty:
                explicitly_empty = True
        else:
            values.append(_structured_token(raw_value, index, directive_name, occurrence_index, 0))

        occurrence = DirectiveOccurrence(directive_name, raw_name, location, values, explicitly_empty=explicitly_empty)
        _append_occurrence(directives, findings, occurrence)

    return _finalize_policy(None, directives, findings, version, name, index, disposition, "structured")


def _sortable_structured_value(value: Any) -> str:
    return repr(value)


def _structured_token(
    value: Any,
    policy_index: int,
    directive: str,
    occurrence: int,
    value_index: int,
) -> LocatedToken:
    if value is NONCE:
        token = LocatedToken(
            "'nonce-<request>",
            SourceLocation(policy_index, directive, occurrence, value_index),
            kind="nonce-placeholder",
        )
        token.reasons.append("Django NONCE sentinel; the request nonce is inserted while building the header.")
        return token
    return LocatedToken(str(value), SourceLocation(policy_index, directive, occurrence, value_index))


def _finalize_policy(
    text: str | None,
    directives: dict[str, ParsedDirective],
    findings: list[Finding],
    version: PolicyVersion,
    name: str,
    index: int,
    disposition: Literal["enforce", "report-only", "unknown"],
    source_type: Literal["text", "structured"],
) -> PolicyAnalysis:
    known_directives = DIRECTIVES_BY_VERSION[version]
    for directive in directives.values():
        for occurrence in directive.occurrences:
            if occurrence.ignored:
                continue
            if directive.name not in KNOWN_DIRECTIVES:
                occurrence.ignored = True
                occurrence.ignore_reason = "unknown-directive"
                for token in occurrence.values:
                    token.kind = "unknown-extension"
                    token.status = "unknown"
                findings.append(
                    Finding(
                        "unknown-directive",
                        f"{directive.name!r} is not a directive recognized by this analyzer and is retained as unknown.",
                        "info",
                        [occurrence.location],
                    )
                )
            elif directive.name not in known_directives:
                occurrence.ignored = True
                occurrence.ignore_reason = f"unsupported-csp{version}"
                findings.append(
                    Finding(
                        "unsupported-directive-version",
                        f"{directive.name!r} is not defined in CSP level {version} and is ignored by browsers at that level.",
                        "warning",
                        [occurrence.location],
                    )
                )
                _classify_directive_tokens(occurrence, version, findings, enforce=False)
            else:
                _classify_directive_tokens(occurrence, version, findings, enforce=True)

    effective_constraints = _interpret_constraints(directives, version)
    return PolicyAnalysis(
        index=index,
        name=name,
        disposition=disposition,
        source_type=source_type,
        text=text,
        directives=directives,
        findings=findings,
        effective_constraints=effective_constraints,
    )


def _classify_directive_tokens(
    occurrence: DirectiveOccurrence,
    version: PolicyVersion,
    findings: list[Finding],
    *,
    enforce: bool,
) -> None:
    directive = occurrence.name
    if directive in SOURCE_DIRECTIVES:
        for token in occurrence.values:
            _classify_source_token(token, directive, version, enforce)
    elif directive == "frame-ancestors":
        for token in occurrence.values:
            _classify_frame_ancestor_token(token, enforce)
    elif directive == "sandbox":
        for token in occurrence.values:
            _classify_sandbox_token(token, enforce)
    elif directive == "require-sri-for":
        for token in occurrence.values:
            if token.value not in {"script", "style"}:
                _invalidate(token, "invalid-sri-token", enforce)
    elif directive == "require-trusted-types-for":
        for token in occurrence.values:
            if token.value != "'script'":
                _invalidate(token, "invalid-trusted-types-token", enforce)
    elif directive == "trusted-types":
        for token in occurrence.values:
            if not (token.value == "'allow-duplicates'" or _is_policy_name(token.value)):
                _invalidate(token, "invalid-trusted-types-policy", enforce)
    elif directive == "webrtc":
        for token in occurrence.values:
            if token.value not in {"'allow'", "'block'"}:
                _invalidate(token, "invalid-webrtc-token", enforce)
    elif directive in VALUELESS_DIRECTIVES:
        for token in occurrence.values:
            _invalidate(token, "valueless-directive-value", enforce)
    elif directive == "plugin-types":
        for token in occurrence.values:
            if not MEDIA_TYPE_RE.match(token.value):
                _invalidate(token, "invalid-media-type", enforce)
    elif directive in {"report-uri"}:
        for token in occurrence.values:
            if not _is_uri_reference(token.value):
                _invalidate(token, "invalid-report-uri", enforce)
    elif directive == "report-to":
        for token in occurrence.values:
            if re.search(r"\s", token.value) or token.value.startswith("'"):
                _invalidate(token, "invalid-report-to-group", enforce)

    if (
        occurrence.explicitly_empty
        and directive not in SOURCE_DIRECTIVES | {"sandbox"} | VALUELESS_DIRECTIVES
    ):
        findings.append(
            Finding(
                "invalid-empty-directive",
                f"{directive!r} requires a value; an explicitly empty directive is not a valid configuration.",
                "error",
                [occurrence.location],
            )
        )

    for token in occurrence.values:
        if token.status == "invalid":
            findings.append(
                Finding(
                    token.reasons[-1] if token.reasons else "invalid-token",
                    f"{token.value!r} is not a valid value for {directive!r} in CSP level {version}.",
                    "error",
                    [token.location],
                )
            )

    if not enforce:
        return
    if directive in SOURCE_DIRECTIVES and occurrence.values:
        _check_source_incompatibilities(occurrence, findings)


def _classify_source_token(token: LocatedToken, directive: str, version: PolicyVersion, enforce: bool) -> None:
    value = token.value
    if value == KEYWORD_NONE or value == KEYWORD_SELF:
        token.kind = "keyword"
    elif NONCE_RE.match(value):
        token.kind = "nonce"
        if version == 1:
            _invalidate(token, "unsupported-nonce-csp1", enforce)
    elif HASH_RE.match(value):
        token.kind = "hash"
        if version == 1:
            _invalidate(token, "unsupported-hash-csp1", enforce)
        elif not _valid_hash_payload(value):
            _invalidate(token, "invalid-hash-encoding", enforce)
    elif token.kind == "nonce-placeholder":
        pass
    elif SCHEME_SOURCE_RE.match(value):
        token.kind = "scheme"
    elif value in SCRIPT_KEYWORDS or value in STYLE_KEYWORDS:
        token.kind = "keyword"
        if value in CSP3_SOURCE_KEYWORDS and version < 3:
            _invalidate(token, "unsupported-keyword-version", enforce)
        is_script_keyword = value in SCRIPT_KEYWORDS
        is_style_keyword = value in STYLE_KEYWORDS
        if is_script_keyword and is_style_keyword:
            applies_to_script_or_style = directive.startswith(("script-src", "style-src"))
            if not (applies_to_script_or_style or directive == "default-src"):
                _invalidate(token, "keyword-not-allowed-for-directive", enforce)
        elif is_script_keyword:
            if not (directive.startswith("script-src") or directive == "default-src"):
                _invalidate(token, "keyword-not-allowed-for-directive", enforce)
        elif is_style_keyword and not (directive.startswith("style-src") or directive == "default-src"):
            _invalidate(token, "keyword-not-allowed-for-directive", enforce)
        if directive == "default-src" and value in {
            "'report-sample'",
            "'strict-dynamic'",
            "'unsafe-hashes'",
        }:
            _invalidate(token, "keyword-not-allowed-for-directive", enforce)
    elif value.startswith("'"):
        token.kind = "invalid-keyword"
        _invalidate(token, "invalid-source-token", enforce)
    elif HOST_SOURCE_RE.match(value):
        token.kind = "host"
    else:
        token.kind = "invalid-source"
        _invalidate(token, "invalid-source-token", enforce)

    if directive in NAVIGATION_DIRECTIVES and token.kind in {"nonce", "hash"}:
        _invalidate(token, "keyword-not-allowed-for-directive", enforce)
    if token.kind == "nonce-placeholder" and directive not in SOURCE_DIRECTIVES:
        _invalidate(token, "keyword-not-allowed-for-directive", enforce)


def _classify_frame_ancestor_token(token: LocatedToken, enforce: bool) -> None:
    if token.value in {KEYWORD_NONE, KEYWORD_SELF}:
        token.kind = "keyword"
    elif HOST_SOURCE_RE.match(token.value) and not SCHEME_SOURCE_RE.match(token.value):
        token.kind = "host"
    else:
        token.kind = "invalid-source"
        _invalidate(token, "invalid-frame-ancestor-source", enforce)


def _classify_sandbox_token(token: LocatedToken, enforce: bool) -> None:
    if token.value in SANDBOX_TOKENS:
        token.kind = "sandbox-token"
    else:
        token.kind = "unknown-sandbox-token"
        token.status = "unknown" if enforce else "invalid"
        if not enforce:
            token.reasons.append("Sandbox token is not interpreted for the selected CSP version.")


def _invalidate(token: LocatedToken, code: str, enforce: bool) -> None:
    token.status = "invalid" if enforce else "ignored"
    token.reasons.append(code)


def _valid_hash_payload(value: str) -> bool:
    match = HASH_RE.match(value)
    if match is None:
        return False
    algorithm, payload = match.groups()
    try:
        decoded = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) == HASH_LENGTHS[algorithm]


def _is_policy_name(value: str) -> bool:
    return bool(value) and not value.startswith("'") and not re.search(r"[;,\s]", value)


def _is_uri_reference(value: str) -> bool:
    return bool(value) and not re.search(r"\s", value)


def _check_source_incompatibilities(occurrence: DirectiveOccurrence, findings: list[Finding]) -> None:
    directive = occurrence.name
    tokens = [token for token in occurrence.values if token.status == "valid"]
    none_tokens = [token for token in tokens if token.value == KEYWORD_NONE]
    if none_tokens and len(tokens) > 1:
        for token in none_tokens:
            token.status = "ignored"
            token.reasons.append("none-ignored-with-other-sources")
        findings.append(
            Finding(
                "none-mixed-with-sources",
                f"'none' is ignored in {directive!r} because other source tokens are present.",
                "warning",
                [token.location for token in none_tokens] + [token.location for token in tokens if token.value != KEYWORD_NONE][:1],
            )
        )

    active_tokens = [token for token in tokens if token.status == "valid" and token.value != KEYWORD_NONE]
    nonce_or_hash = [token for token in active_tokens if token.kind in {"nonce", "hash", "nonce-placeholder"}]
    inline_tokens = [token for token in active_tokens if token.value == KEYWORD_UNSAFE_INLINE]
    strict_dynamic_tokens = [token for token in active_tokens if token.value == KEYWORD_STRICT_DYNAMIC]

    if directive.startswith(("script-src", "style-src")) and nonce_or_hash and inline_tokens:
        for token in inline_tokens:
            token.status = "ignored"
            token.reasons.append("unsafe-inline-ignored-with-nonce-or-hash")
        findings.append(
            Finding(
                "unsafe-inline-ignored",
                f"'unsafe-inline' is ignored in {directive!r} because a nonce or hash is present.",
                "warning",
                [token.location for token in inline_tokens] + [nonce_or_hash[0].location],
            )
        )

    if directive == "script-src-attr" and strict_dynamic_tokens:
        for token in strict_dynamic_tokens:
            token.status = "ignored"
            token.reasons.append("strict-dynamic-not-applicable-to-script-attributes")
        findings.append(
            Finding(
                "strict-dynamic-script-attr",
                "'strict-dynamic' does not govern inline event handler attributes.",
                "warning",
                [token.location for token in strict_dynamic_tokens],
            )
        )

    active_strict_dynamic = [
        token for token in strict_dynamic_tokens if token.status == "valid"
    ]
    if directive in {"script-src", "script-src-elem"} and active_strict_dynamic:
        if not nonce_or_hash:
            for token in active_strict_dynamic:
                token.status = "ignored"
                token.reasons.append("strict-dynamic-requires-nonce-or-hash")
            findings.append(
                Finding(
                    "strict-dynamic-without-nonce-or-hash",
                    "'strict-dynamic' is ignored unless the source list also contains a nonce or hash.",
                    "error",
                    [token.location for token in active_strict_dynamic],
                )
            )
        else:
            ignored_kinds = {"host", "scheme"}
            for token in active_tokens:
                if token.kind in ignored_kinds or token.value == KEYWORD_SELF:
                    token.status = "ignored"
                    token.reasons.append("source-ignored-by-strict-dynamic")
            findings.append(
                Finding(
                    "strict-dynamic-ignores-host-sources",
                    "With a nonce or hash, 'strict-dynamic' makes host, scheme, and 'self' sources ineffective.",
                    "info",
                    [token.location for token in active_strict_dynamic] + [nonce_or_hash[0].location],
                )
            )


def _interpret_constraints(
    directives: dict[str, ParsedDirective],
    version: PolicyVersion,
) -> dict[str, EffectiveConstraint]:
    targets = {
        "script-elements": (
            "Script elements and dynamically inserted scripts",
            {
                1: ["script-src"],
                2: ["script-src"],
                3: ["script-src-elem", "script-src", "default-src"],
            },
        ),
        "script-attributes": (
            "Inline event handler attributes",
            {
                1: ["script-src"],
                2: ["script-src"],
                3: ["script-src-attr", "script-src", "default-src"],
            },
        ),
        "script-evaluation": (
            "eval, Function(), and WebAssembly compilation",
            {
                1: ["script-src", "default-src"],
                2: ["script-src", "default-src"],
                3: ["script-src", "default-src"],
            },
        ),
        "style-elements": (
            "Style elements, external stylesheets, and XSLT",
            {
                1: ["style-src"],
                2: ["style-src"],
                3: ["style-src-elem", "style-src", "default-src"],
            },
        ),
        "style-attributes": (
            "Inline style attributes",
            {
                1: ["style-src"],
                2: ["style-src"],
                3: ["style-src-attr", "style-src", "default-src"],
            },
        ),
        "child-frames": (
            "Frames and iframes",
            {
                1: ["frame-src", "default-src"],
                2: ["frame-src", "child-src", "default-src"],
                3: ["frame-src", "child-src", "default-src"],
            },
        ),
        "workers": (
            "Workers and shared workers",
            {
                1: ["script-src", "default-src"],
                2: ["child-src", "default-src"],
                3: ["worker-src", "child-src", "default-src"],
            },
        ),
        "images": ("Images", {1: ["img-src", "default-src"], 2: ["img-src", "default-src"], 3: ["img-src", "default-src"]}),
        "fonts": ("Fonts", {1: ["font-src", "default-src"], 2: ["font-src", "default-src"], 3: ["font-src", "default-src"]}),
        "connections": (
            "Fetch, XHR, WebSocket, EventSource, and beacon connections",
            {1: ["connect-src", "default-src"], 2: ["connect-src", "default-src"], 3: ["connect-src", "default-src"]},
        ),
        "media": ("Audio and video", {1: ["media-src", "default-src"], 2: ["media-src", "default-src"], 3: ["media-src", "default-src"]}),
        "objects": (
            "Object, embed, and applet resources",
            {1: ["object-src", "default-src"], 2: ["object-src", "default-src"], 3: ["object-src", "default-src"]},
        ),
        "manifests": (
            "Application manifests",
            {1: [], 2: [], 3: ["manifest-src", "default-src"]},
        ),
        "base-uri": ("Base element URLs", {1: [], 2: ["base-uri"], 3: ["base-uri"]}),
        "form-action": ("Form submissions", {1: [], 2: ["form-action"], 3: ["form-action"]}),
        "navigations": (
            "General document navigations",
            {1: [], 2: [], 3: ["navigate-to"]},
        ),
        "frame-ancestors": (
            "Resources allowed to embed this page",
            {1: [], 2: ["frame-ancestors"], 3: ["frame-ancestors"]},
        ),
    }

    return {
        target: _resolve_constraint(target, label, chains[version], directives)
        for target, (label, chains) in targets.items()
    }


def _resolve_constraint(
    target: str,
    label: str,
    chain: list[str],
    directives: dict[str, ParsedDirective],
) -> EffectiveConstraint:
    occurrence: DirectiveOccurrence | None = None
    used_chain: list[str] = []
    for directive_name in chain:
        used_chain.append(directive_name)
        parsed = directives.get(directive_name)
        if parsed is None:
            continue
        candidate = parsed.effective_occurrence
        if candidate is not None and not candidate.ignored:
            occurrence = candidate
            break

    if not chain:
        return EffectiveConstraint(
            target,
            label,
            "unknown",
            None,
            used_chain,
            notes=["No applicable directive was defined in the selected CSP level."],
        )
    if occurrence is None:
        if chain[-1] == "default-src":
            return EffectiveConstraint(
                target,
                label,
                "allowed-by-default",
                None,
                used_chain,
                notes=["No listed directive was present; no CSP restriction is expressed for this target."],
            )
        return EffectiveConstraint(target, label, "allowed-by-default", None, used_chain, notes=["No applicable directive was present."])

    constraint = EffectiveConstraint(target, label, "fallback", occurrence.name, used_chain)
    if chain[0] == occurrence.name:
        constraint.status = "defined"
    elif occurrence.explicitly_empty:
        constraint.status = "empty"

    for token in occurrence.values:
        copied = replace(token)
        if copied.status == "invalid":
            copied.status = "ignored"
            copied.reasons.append("invalid tokens do not create an allowed source")
        _interpret_token_for_target(
            copied,
            target,
            has_unsafe_hashes=any(token.value == "'unsafe-hashes'" for token in occurrence.values),
        )
        if copied.status == "ignored":
            constraint.ignored_values.append(copied)
        else:
            constraint.values.append(copied)

    if occurrence.explicitly_empty:
        constraint.status = "empty"
        constraint.notes.append("The selected directive has an explicit empty source list.")
    if constraint.directive != "default-src" and chain[-1] == "default-src":
        constraint.notes.append(f"No applicable specialized directive was present before {occurrence.name!r}.")
    return constraint


def _interpret_token_for_target(
    token: LocatedToken,
    target: str,
    *,
    has_unsafe_hashes: bool,
) -> None:
    if token.status == "unknown":
        token.reasons.append("extension token retained as unknown")
        return
    if token.status == "ignored":
        return

    source_kinds = {"host", "scheme"}
    if target in {"script-elements"}:
        if token.kind == "keyword" and token.value == "'unsafe-hashes'":
            _ignore_for_target(token, "unsafe-hashes governs inline handlers, not script element URLs")
        elif token.value == "'report-sample'":
            _ignore_for_target(token, "report-sample modifies violation reports, not script loading")
        elif token.value in {"'unsafe-eval'", "'wasm-unsafe-eval'"}:
            token.reasons.append("script modifier; does not by itself authorize a script element URL")
    elif target == "script-attributes":
        if token.value == "'unsafe-hashes'":
            token.reasons.append("enables matching hashes for inline event handler attributes")
        elif token.kind == "hash":
            pass
        elif token.value in {"'unsafe-inline'", KEYWORD_NONE}:
            pass
        elif token.value in {"'unsafe-eval'", "'wasm-unsafe-eval'"}:
            token.reasons.append("script modifier; does not by itself authorize an inline event handler")
        elif token.value == "'report-sample'":
            _ignore_for_target(token, "report-sample modifies violation reports, not inline handlers")
        else:
            _ignore_for_target(token, "not applicable to inline event handler attributes")
    elif target == "script-evaluation":
        if token.value in {KEYWORD_NONE, "'unsafe-eval'", "'wasm-unsafe-eval'"}:
            pass
        elif token.value == "'strict-dynamic'":
            _ignore_for_target(token, "'strict-dynamic' governs propagated script trust, not eval")
        else:
            _ignore_for_target(token, "not an eval keyword for this target")
    elif target == "style-elements":
        if token.value == "'report-sample'":
            _ignore_for_target(token, "report-sample modifies violation reports, not style loading")
        elif token.kind == "keyword" and token.value not in {KEYWORD_NONE, KEYWORD_SELF, "'unsafe-inline'"}:
            _ignore_for_target(token, "not applicable to style elements")
    elif target == "style-attributes":
        if token.kind == "hash" or token.value in {KEYWORD_NONE, "'unsafe-inline'"}:
            pass
        elif token.value == "'report-sample'":
            _ignore_for_target(token, "report-sample modifies violation reports, not inline styles")
        else:
            _ignore_for_target(token, "not applicable to inline style attributes")
    elif target == "workers":
        if token.kind in source_kinds or token.value in {KEYWORD_NONE, KEYWORD_SELF}:
            pass
        else:
            _ignore_for_target(token, "workers are loaded as external URL resources")
    elif target in {"images", "fonts", "connections", "media", "objects", "manifests", "child-frames"}:
        if token.kind in source_kinds or token.value in {KEYWORD_NONE, KEYWORD_SELF}:
            pass
        else:
            _ignore_for_target(token, "not an external resource source expression")
    elif target in {"base-uri", "form-action", "frame-ancestors", "navigations"}:
        if token.kind in source_kinds or token.value in {KEYWORD_NONE, KEYWORD_SELF}:
            pass
        else:
            _ignore_for_target(token, "not applicable to this navigation or embedding directive")

    if target == "script-attributes" and token.kind == "hash":
        if has_unsafe_hashes:
            token.reasons.append("hash applies to inline event handlers because 'unsafe-hashes' is present")
        else:
            _ignore_for_target(
                token,
                "inline event handler hash requires 'unsafe-hashes' in the same source list",
            )


def _ignore_for_target(token: LocatedToken, reason: str) -> None:
    token.status = "ignored"
    token.reasons.append(reason)
