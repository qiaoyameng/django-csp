from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Iterable

# Hash algorithms supported by CSP hash-source expressions.
SUPPORTED_ALGORITHMS = ("sha256", "sha384", "sha512")

# Raw text elements whose inline content is subject to CSP hashes.
# NOTE: event handler attributes and style attributes are intentionally
# out of scope for this first version.
INLINE_ELEMENTS = ("script", "style")

DIRECTIVE_FOR_ELEMENT = {"script": "script-src", "style": "style-src"}


@dataclass(frozen=True)
class ElementSource:
    """Locates a single inline element within the source HTML document."""

    element: str  # "script" or "style"
    index: int  # 1-based position amongst hashed elements of the same type
    line: int  # 1-based line number of the opening tag
    column: int  # 1-based column of the opening tag


@dataclass
class HashEntry:
    """A single digest plus every element that produced it."""

    algorithm: str
    digest: str  # base64-encoded
    element: str  # "script" or "style"
    sources: list[ElementSource] = field(default_factory=list)

    @property
    def source_expression(self) -> str:
        """The CSP source expression, e.g. 'sha256-...'."""
        return f"'{self.algorithm}-{self.digest}'"


@dataclass
class HashManifest:
    """The hashes of every inline script/style element in a document."""

    entries: list[HashEntry] = field(default_factory=list)

    def source_expressions(self, element: str | None = None) -> list[str]:
        """Sorted, deduplicated CSP source expressions, optionally per element."""
        expressions = {entry.source_expression for entry in self.entries if element is None or entry.element == element}
        return sorted(expressions)

    def directive_sources(self) -> dict[str, list[str]]:
        """Map of script-src/style-src to their hash source expressions."""
        sources = {}
        for element, directive in DIRECTIVE_FOR_ELEMENT.items():
            expressions = self.source_expressions(element)
            if expressions:
                sources[directive] = expressions
        return sources


@dataclass
class _CollectedElement:
    element: str
    index: int
    line: int
    column: int
    content: str


class _InlineContentParser(HTMLParser):
    """Collects the raw text content of inline <script> and <style> elements.

    HTMLParser treats <script> and <style> as CDATA elements, so their
    contents are delivered verbatim via handle_data without entity decoding.
    convert_charrefs=False additionally guarantees that no character
    reference conversion happens anywhere.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.collected: list[_CollectedElement] = []
        self._capture: dict | None = None
        self._counters = {"script": 0, "style": 0}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in INLINE_ELEMENTS or self._capture is not None:
            return
        attr_names = {name for name, _ in attrs}
        if tag == "script" and "src" in attr_names:
            # External script: browsers ignore any inline content.
            return
        line, column = self.getpos()
        self._counters[tag] += 1
        self._capture = {
            "element": tag,
            "index": self._counters[tag],
            "line": line,
            "column": column + 1,
            "chunks": [],
        }

    def handle_data(self, data: str) -> None:
        if self._capture is not None:
            self._capture["chunks"].append(data)

    def handle_endtag(self, tag: str) -> None:
        if self._capture is not None and tag == self._capture["element"]:
            self._flush()

    def close(self) -> None:
        super().close()
        # An unclosed element at EOF still executes in browsers.
        if self._capture is not None:
            self._flush()

    def _flush(self) -> None:
        assert self._capture is not None
        capture = self._capture
        self._capture = None
        # Browsers normalize CR and CRLF to LF while tokenizing.
        content = "".join(capture["chunks"]).replace("\r\n", "\n").replace("\r", "\n")
        if not content:
            # Empty elements execute nothing, so no hash is required.
            return
        self.collected.append(
            _CollectedElement(
                element=capture["element"],
                index=capture["index"],
                line=capture["line"],
                column=capture["column"],
                content=content,
            )
        )


def generate_hash_manifest(html: str, algorithms: Iterable[str] = ("sha256",)) -> HashManifest:
    """Build a manifest of CSP hashes for the inline elements in html.

    Pure function: parses html, extracts the contents of genuine inline
    <script> and <style> elements (skipping external scripts, comments and
    plain text), and computes UTF-8 digests using each of the given
    algorithms. Entries are deduplicated while retaining the list of
    source locations.
    """
    algorithms = tuple(dict.fromkeys(algorithms))
    unsupported = [a for a in algorithms if a not in SUPPORTED_ALGORITHMS]
    if unsupported:
        raise ValueError(
            f"Unsupported hash algorithm(s): {', '.join(unsupported)}. "
            f"Supported: {', '.join(SUPPORTED_ALGORITHMS)}."
        )

    parser = _InlineContentParser()
    parser.feed(html)
    parser.close()

    entries: dict[tuple[str, str, str], HashEntry] = {}
    for element in parser.collected:
        data = element.content.encode("utf-8")
        source = ElementSource(
            element=element.element,
            index=element.index,
            line=element.line,
            column=element.column,
        )
        for algorithm in algorithms:
            digest = base64.b64encode(hashlib.new(algorithm, data).digest()).decode("ascii")
            key = (algorithm, digest, element.element)
            entry = entries.get(key)
            if entry is None:
                entries[key] = HashEntry(
                    algorithm=algorithm,
                    digest=digest,
                    element=element.element,
                    sources=[source],
                )
            else:
                entry.sources.append(source)

    return HashManifest(entries=list(entries.values()))
