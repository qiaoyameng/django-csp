import base64
import hashlib

import pytest

from csp.constants import NONCE, SELF
from csp.utils import build_hash_manifest, build_policy


HTML = """\
<!doctype html>
<!-- <script>commented();</script> -->
<script src="/external.js">ignored();</script>
<button onclick="ignored()">OK</button>
<p style="ignored: true">OK</p>
<script id="inline">
console.log('&amp;');
</script>
<script>
console.log('&amp;');
</script>
<style>
a { color: red; }
</style>
<script></script>
plain <script>not a real tag</style> text
"""


def csp_digest(content: str, algorithm: str = "sha256") -> str:
    return base64.b64encode(hashlib.new(algorithm, content.encode("utf-8")).digest()).decode("ascii")


def test_build_hash_manifest_standard_empty_digest() -> None:
    manifest = build_hash_manifest("<script></script>")

    assert len(manifest) == 1
    assert manifest[0].algorithm == "sha256"
    assert manifest[0].digest == "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    assert manifest[0].value == "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='"


def test_build_hash_manifest_extracts_only_real_inline_elements() -> None:
    manifest = build_hash_manifest(HTML, algorithms=("sha256", "sha384"))

    tags = [entry.sources[0].tag for entry in manifest if entry.algorithm == "sha256"]

    assert tags == ["script", "style", "script"]
    source_slices = [
        HTML[source.start_offset:source.end_offset]
        for entry in manifest
        for source in entry.sources
    ]
    assert not any("onclick" in source_slice for source_slice in source_slices)
    assert not any('style="ignored' in source_slice for source_slice in source_slices)


def test_build_hash_manifest_keeps_script_entities_raw() -> None:
    manifest = build_hash_manifest(HTML)
    script_hash = manifest[0]
    expected_content = "\nconsole.log('&amp;');\n"

    assert script_hash.digest == csp_digest(expected_content)
    assert script_hash.digest != csp_digest("\nconsole.log('&');\n")


def test_build_hash_manifest_hashes_utf8_bytes() -> None:
    content = "console.log('你好');"
    manifest = build_hash_manifest(f"<script>{content}</script>")

    assert manifest[0].digest == csp_digest(content)


def test_build_hash_manifest_normalizes_crlf_like_browser() -> None:
    html = "<script>\r\nconsole.log(1);\r</script><style>\r\na {}\r</style>"
    manifest = build_hash_manifest(html)

    assert [entry.digest for entry in manifest] == [
        csp_digest("\nconsole.log(1);\n"),
        csp_digest("\na {}\n"),
    ]


def test_build_hash_manifest_locations_count_cr_as_a_line_break() -> None:
    manifest = build_hash_manifest("<style>one\r\ntwo\rthree</style>")

    source = manifest[0].sources[0]
    assert (source.line, source.column) == (1, 0)
    assert (source.content_line, source.content_column) == (1, 7)


def test_build_hash_manifest_treats_script_self_closing_as_raw_text() -> None:
    manifest = build_hash_manifest('<script id="inline"/>content()</script>')

    assert len(manifest) == 1
    source = manifest[0].sources[0]
    assert source.start_offset == 0
    assert source.tag == "script"


def test_build_hash_manifest_deduplicates_and_keeps_sources() -> None:
    manifest = build_hash_manifest(HTML, algorithms=("sha256", "sha512"))
    sha256_entries = [entry for entry in manifest if entry.algorithm == "sha256"]

    assert len(sha256_entries) == 3
    duplicate = sha256_entries[0]
    assert len(duplicate.sources) == 2
    assert [source.tag for source in duplicate.sources] == ["script", "script"]
    assert [source.line for source in duplicate.sources] == [6, 9]


def test_build_hash_manifest_reports_locations() -> None:
    manifest = build_hash_manifest(HTML)
    source = manifest[0].sources[0]

    assert source.tag == "script"
    assert source.directive == "script-src"
    assert HTML[source.start_offset:source.end_offset].startswith('<script id="inline">')
    assert HTML[source.content_start_offset:source.content_end_offset] == "\nconsole.log('&amp;');\n"
    assert (source.line, source.column) == (6, 0)
    assert (source.content_line, source.content_column) == (6, 20)


def test_build_hash_manifest_rejects_unsupported_algorithm() -> None:
    with pytest.raises(ValueError, match="Unsupported CSP hash algorithm"):
        build_hash_manifest("<script>console.log(1);</script>", algorithms=("sha1",))


def test_build_policy_includes_manifest_hashes() -> None:
    html = "<script>\nconsole.log('&amp;');\n</script><style>\na { color: red; }\n</style>"
    manifest = build_hash_manifest(html)
    policy = build_policy(
        config={"default-src": [SELF], "script-src": [SELF], "style-src": [SELF]},
        hash_manifest=manifest,
    )
    assert sorted(policy.split("; ")) == sorted(
        [
            "default-src 'self'",
            f"script-src 'self' '{manifest[0].algorithm}-{manifest[0].digest}'",
            f"style-src 'self' '{manifest[1].algorithm}-{manifest[1].digest}'",
        ]
    )


def test_policy_hashes_match_final_html_body() -> None:
    html = "<script>\nconsole.log('&amp;');\n</script>"
    manifest = build_hash_manifest(html)
    policy = build_policy(config={"default-src": [SELF]}, hash_manifest=manifest)

    actual_body = html[
        manifest[0].sources[0].content_start_offset:manifest[0].sources[0].content_end_offset
    ].replace("\r\n", "\n").replace("\r", "\n")

    assert f"'sha256-{csp_digest(actual_body)}'" in policy


def test_build_policy_combines_nonce_and_hashes() -> None:
    manifest = build_hash_manifest("<script>console.log(1);</script>")
    policy = build_policy(
        config={"default-src": [SELF, NONCE]},
        hash_manifest=manifest,
        nonce="abc123",
    )

    assert sorted(policy.split("; ")) == sorted(
        [
            "default-src 'self' 'nonce-abc123'",
            f"script-src {manifest[0].value}",
        ]
    )
