from __future__ import annotations

import base64
from bisect import bisect_right
import copy
import hashlib
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from itertools import chain
from typing import Any, Callable, Sequence

from django.conf import settings
from django.utils.encoding import force_str

from csp.constants import NONCE, SELF

DEFAULT_DIRECTIVES = {
    # Fetch Directives
    "child-src": None,
    "connect-src": None,
    "default-src": [SELF],
    "script-src": None,
    "script-src-attr": None,
    "script-src-elem": None,
    "object-src": None,
    "style-src": None,
    "style-src-attr": None,
    "style-src-elem": None,
    "font-src": None,
    "frame-src": None,
    "img-src": None,
    "manifest-src": None,
    "media-src": None,
    "prefetch-src": None,  # Deprecated.
    # Document Directives
    "base-uri": None,
    "plugin-types": None,  # Deprecated.
    "sandbox": None,
    # Navigation Directives
    "form-action": None,
    "frame-ancestors": None,
    "navigate-to": None,
    # Reporting Directives
    "report-uri": None,
    "report-to": None,
    "require-sri-for": None,
    # Trusted Types Directives
    "require-trusted-types-for": None,
    "trusted-types": None,
    # Other Directives
    "webrtc": None,
    "worker-src": None,
    # Directives Defined in Other Documents
    "upgrade-insecure-requests": False,
    "block-all-mixed-content": False,  # Deprecated.
}

DIRECTIVES_T = dict[str, Any]

SUPPORTED_HASH_ALGORITHMS = ("sha256", "sha384", "sha512")


@dataclass(frozen=True)
class InlineElement:
    tag: str
    directive: str
    start_offset: int
    end_offset: int
    line: int
    column: int
    content_start_offset: int
    content_end_offset: int
    content_line: int
    content_column: int


@dataclass(frozen=True)
class InlineHash:
    directive: str
    algorithm: str
    digest: str
    sources: tuple[InlineElement, ...]

    @property
    def value(self) -> str:
        return f"'{self.algorithm}-{self.digest}'"


HASH_MANIFEST_T = Sequence[InlineHash]

_RAW_TEXT_TAGS = {
    "script": "script-src",
    "style": "style-src",
}
_RAW_TEXT_END_TAGS = {
    tag: re.compile(
        rf"</{re.escape(tag)}(?:[\t\n\f\r />][\s\S]*?)?>",
        re.IGNORECASE,
    )
    for tag in _RAW_TEXT_TAGS
}


class _InlineElementParser(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__(convert_charrefs=False)
        self.html = html
        self.browser_line_starts = [0]
        self.parser_line_starts = [0]
        for index, char in enumerate(html):
            if char in "\r\n" and not (
                char == "\n" and index > 0 and html[index - 1] == "\r"
            ):
                self.browser_line_starts.append(index + 1)
            if char == "\n":
                self.parser_line_starts.append(index + 1)
        self.elements: list[InlineElement] = []
        self._pending_tag: str | None = None
        self._pending_directive: str | None = None
        self._pending_start = 0
        self._pending_line = 0
        self._pending_column = 0
        self._pending_content_start = 0
        self._pending_content: list[str] = []

    def _position(self, offset: int) -> tuple[int, int]:
        line = bisect_right(self.browser_line_starts, offset)
        return line, offset - self.browser_line_starts[line - 1]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        directive = _RAW_TEXT_TAGS.get(tag)
        if directive is None:
            return

        opening_tag = self.get_starttag_text()
        if opening_tag is None:
            return

        parser_line, parser_column = self.getpos()
        start_offset = self._absolute_offset(parser_line, parser_column)
        line, column = self._position(start_offset)
        content_start = start_offset + len(opening_tag)

        if tag == "script" and any(name == "src" for name, _value in attrs):
            self._clear_pending()
            return

        self._pending_tag = tag
        self._pending_directive = directive
        self._pending_start = start_offset
        self._pending_line = line
        self._pending_column = column
        self._pending_content_start = content_start
        self._pending_content = []

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _RAW_TEXT_TAGS:
            self.handle_starttag(tag, attrs)

    def close(self) -> None:
        super().close()
        self._clear_pending()

    def handle_data(self, data: str) -> None:
        if self._pending_tag is not None:
            self._pending_content.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag != self._pending_tag or self._pending_directive is None:
            return

        content_start = self._pending_content_start
        content_end = content_start + len("".join(self._pending_content))
        end_tag = _RAW_TEXT_END_TAGS[tag]
        match = end_tag.search(self.html, content_end)
        if match is None or match.start() != content_end:
            self._clear_pending()
            return

        content_line, content_column = self._position(content_start)
        self.elements.append(
            InlineElement(
                tag=tag,
                directive=self._pending_directive,
                start_offset=self._pending_start,
                end_offset=match.end(),
                line=self._pending_line,
                column=self._pending_column,
                content_start_offset=content_start,
                content_end_offset=content_end,
                content_line=content_line,
                content_column=content_column,
            )
        )
        self._clear_pending()

    def _clear_pending(self) -> None:
        self._pending_tag = None
        self._pending_directive = None
        self._pending_start = 0
        self._pending_line = 0
        self._pending_column = 0
        self._pending_content_start = 0
        self._pending_content = []

    def _absolute_offset(self, line: int, column: int) -> int:
        return self.parser_line_starts[line - 1] + column


def build_hash_manifest(
    html: str,
    algorithms: Sequence[str] = ("sha256",),
) -> list[InlineHash]:
    """Build deduplicated CSP hashes for inline script and style elements."""
    selected_algorithms = list(dict.fromkeys(algorithm.lower() for algorithm in algorithms))
    unsupported = sorted(set(selected_algorithms) - set(SUPPORTED_HASH_ALGORITHMS))
    if unsupported:
        raise ValueError(f"Unsupported CSP hash algorithm(s): {', '.join(unsupported)}")

    parser = _InlineElementParser(html)
    parser.feed(html)
    parser.close()

    grouped_elements: dict[tuple[str, str], list[InlineElement]] = {}
    for element in parser.elements:
        content = html[element.content_start_offset:element.content_end_offset]
        normalized_content = content.replace("\r\n", "\n").replace("\r", "\n")
        key = (element.directive, normalized_content)
        grouped_elements.setdefault(key, []).append(element)

    manifest: list[InlineHash] = []
    for (directive, content), sources in grouped_elements.items():
        encoded_content = content.encode("utf-8")
        for algorithm in selected_algorithms:
            digest = base64.b64encode(hashlib.new(algorithm, encoded_content).digest()).decode("ascii")
            manifest.append(
                InlineHash(
                    directive=directive,
                    algorithm=algorithm,
                    digest=digest,
                    sources=tuple(sources),
                )
            )

    return manifest


def _hash_manifest_updates(hash_manifest: HASH_MANIFEST_T | None) -> dict[str, tuple[str, ...]]:
    updates: dict[str, list[str]] = {}
    for inline_hash in hash_manifest or ():
        directive = inline_hash.directive
        updates.setdefault(directive, []).append(inline_hash.value)
    return {directive: tuple(dict.fromkeys(values)) for directive, values in updates.items()}


def default_config(csp: DIRECTIVES_T | None) -> DIRECTIVES_T | None:
    if csp is None:
        return None
    # Make a copy of the passed in config to avoid mutating it, and also to drop any unknown keys.
    config = {}
    for key, value in DEFAULT_DIRECTIVES.items():
        config[key] = csp.get(key, value)
    return config


def build_policy(
    config: DIRECTIVES_T | None = None,
    update: DIRECTIVES_T | None = None,
    replace: DIRECTIVES_T | None = None,
    nonce: str | None = None,
    report_only: bool = False,
    hash_manifest: HASH_MANIFEST_T | None = None,
) -> str:
    """Builds the policy as a string from the settings."""

    if config is None:
        if report_only:
            config = getattr(settings, "CONTENT_SECURITY_POLICY_REPORT_ONLY", {})
            config = default_config(config.get("DIRECTIVES", {})) if config else None
        else:
            config = getattr(settings, "CONTENT_SECURITY_POLICY", {})
            config = default_config(config.get("DIRECTIVES", {})) if config else None

    # If config is still `None`, return empty policy.
    if config is None:
        return ""

    update = update if update is not None else {}
    replace = replace if replace is not None else {}
    update = {**update, **_hash_manifest_updates(hash_manifest)}

    csp = {}

    for k in set(chain(config, replace)):
        if k in replace:
            v = replace[k]
        else:
            v = config[k]
        if v is not None:
            v = copy.copy(v)
            if isinstance(v, set):
                v = sorted(v)
            if not isinstance(v, (list, tuple)):
                v = (v,)
            csp[k] = v

    for k, v in update.items():
        if v is not None:
            v = copy.copy(v)
            if isinstance(v, set):
                v = sorted(v)
            if not isinstance(v, (list, tuple)):
                v = (v,)
            if csp.get(k) is None:
                csp[k] = v
            else:
                csp[k] += tuple(v)

    report_uri = csp.pop("report-uri", None)

    policy_parts = {}

    for key, value in csp.items():
        # Check for boolean directives.
        if len(value) == 1 and isinstance(value[0], bool):
            if value[0] is True:
                policy_parts[key] = ""
            continue
        if NONCE in value:
            if nonce:
                value = [f"'nonce-{nonce}'" if v == NONCE else v for v in value]
            else:
                # Strip the `NONCE` sentinel value if no nonce is provided.
                value = [v for v in value if v != NONCE]

        value = list(dict.fromkeys(value))  # Deduplicate
        policy_parts[key] = " ".join(value)

    if report_uri:
        report_uri = map(force_str, report_uri)
        policy_parts["report-uri"] = " ".join(report_uri)

    return "; ".join([f"{k} {val}".strip() for k, val in policy_parts.items()])


def _default_attr_mapper(attr_name: str, val: str) -> str:
    if val:
        return f' {attr_name}="{val}"'
    else:
        return ""


def _bool_attr_mapper(attr_name: str, val: bool) -> str:
    # Only return the bare word if the value is truthy
    # ie - defer=False should actually return an empty string
    if val:
        return f" {attr_name}"
    else:
        return ""


def _async_attr_mapper(attr_name: str, val: str | bool) -> str:
    """The `async` attribute works slightly different than the other bool
    attributes. It can be set explicitly to `false` with no surrounding quotes
    according to the spec."""
    if val in [False, "False"]:
        return f" {attr_name}=false"
    elif val:
        return f" {attr_name}"
    else:
        return ""


# Allow per-attribute customization of returned string template
SCRIPT_ATTRS: dict[str, Callable[[str, Any], str]] = {
    "nonce": _default_attr_mapper,
    "id": _default_attr_mapper,
    "src": _default_attr_mapper,
    "type": _default_attr_mapper,
    "async": _async_attr_mapper,
    "defer": _bool_attr_mapper,
    "integrity": _default_attr_mapper,
    "nomodule": _bool_attr_mapper,
}

# Generates an interpolatable string of valid attrs eg - '{nonce}{id}...'
ATTR_FORMAT_STR = "".join([f"{{{a}}}" for a in SCRIPT_ATTRS])


_script_tag_contents_re = re.compile(
    r"""<script        # match the opening script tag
            [\s|\S]*?> # minimally match attrs and spaces in opening script tag
    ([\s|\S]+)         # greedily capture the script tag contents
    </script>          # match the closing script tag
""",
    re.VERBOSE,
)


def _unwrap_script(text: str) -> str:
    """Extract content defined between script tags"""
    matches = re.search(_script_tag_contents_re, text)
    if matches and len(matches.groups()):
        return matches.group(1).strip()

    return text


def build_script_tag(content: str | None = None, **kwargs: Any) -> str:
    data = {}
    # Iterate all possible script attrs instead of kwargs to make
    # interpolation as easy as possible below
    for attr_name, mapper in SCRIPT_ATTRS.items():
        data[attr_name] = mapper(attr_name, kwargs.get(attr_name))

    # Don't render block contents if the script has a 'src' attribute
    c = _unwrap_script(content) if content and not kwargs.get("src") else ""
    attrs = ATTR_FORMAT_STR.format(**data).rstrip()
    return f"<script{attrs}>{c}</script>".strip()
