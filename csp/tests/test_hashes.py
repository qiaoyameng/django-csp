import base64
import hashlib

import pytest
from django.test.utils import override_settings

from csp.hashes import generate_hash_manifest
from csp.tests.test_utils import policy_eq
from csp.utils import build_policy

# Reference digests, matching the well-known CSP specification examples and
# independently computed values.
SHA256_HELLO = "qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng="  # alert('Hello, world.');
SHA384_HELLO = "H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO"
SHA512_HELLO = "Q2bFTOhEALkN8hOms2FKTDLy7eugP2zFZ1T8LCvX42Fp3WoNr3bjZSAHeOsHrbV1Fu9/A0EzCinRE7Af1ofPrw=="
SHA256_STYLE = "XeYlw2NVzOfB1UCIJqCyGr+0n7bA4fFslFpvKu84IAw="  # body { color: red; }
SHA256_CRLF_SCRIPT = "uWPGzVmjGH2gOYzFrDJWsByhx9BoaMzQbDTCivmYUVQ="  # console.log('a');\nconsole.log('b');\n
SHA256_RAW_ENTITIES = "HRxA5wFjklU+4o8sdgAk9QE6I5K42ivLrVREHZpYIyk="  # literal &amp; text
SHA256_SPACE = "Nqnn8clbgv+5l0PgxcTOldg8mkMKrFn4TvPL+rYUUGg="  # " "


def digest_of(algorithm: str, content: str) -> str:
    return base64.b64encode(hashlib.new(algorithm, content.encode("utf-8")).digest()).decode("ascii")


def test_known_sha256_digest() -> None:
    manifest = generate_hash_manifest("<script>alert('Hello, world.');</script>")
    assert len(manifest.entries) == 1
    entry = manifest.entries[0]
    assert entry.algorithm == "sha256"
    assert entry.digest == SHA256_HELLO
    assert entry.element == "script"
    assert entry.source_expression == f"'sha256-{SHA256_HELLO}'"


def test_multiple_algorithms() -> None:
    manifest = generate_hash_manifest(
        "<script>alert('Hello, world.');</script>",
        algorithms=("sha256", "sha384", "sha512"),
    )
    digests = {(e.algorithm, e.digest) for e in manifest.entries}
    assert digests == {
        ("sha256", SHA256_HELLO),
        ("sha384", SHA384_HELLO),
        ("sha512", SHA512_HELLO),
    }


def test_unsupported_algorithm_rejected() -> None:
    with pytest.raises(ValueError, match="md5"):
        generate_hash_manifest("<script>x</script>", algorithms=("md5",))


def test_style_element() -> None:
    manifest = generate_hash_manifest("<style>body { color: red; }</style>")
    assert len(manifest.entries) == 1
    entry = manifest.entries[0]
    assert entry.element == "style"
    assert entry.digest == SHA256_STYLE


def test_external_script_ignored() -> None:
    html = """
    <script src="https://example.com/app.js"></script>
    <script src="https://example.com/other.js">alert('ignored');</script>
    """
    assert generate_hash_manifest(html).entries == []


def test_comments_and_text_ignored() -> None:
    html = """
    <!-- <script>alert('fake');</script> -->
    <!-- <style>.fake { color: red; }</style> -->
    <p>&lt;script&gt;alert('text')&lt;/script&gt;</p>
    plain text mentioning script and style elements
    """
    assert generate_hash_manifest(html).entries == []


def test_crlf_normalized_like_browsers() -> None:
    # Browsers normalize CR and CRLF to LF before executing inline content.
    html = "<script>console.log('a');\r\nconsole.log('b');\r\n</script>"
    manifest = generate_hash_manifest(html)
    assert [e.digest for e in manifest.entries] == [SHA256_CRLF_SCRIPT]
    assert SHA256_CRLF_SCRIPT == digest_of("sha256", "console.log('a');\nconsole.log('b');\n")


def test_lone_cr_normalized() -> None:
    html = "<script>console.log('a');\rconsole.log('b');</script>"
    manifest = generate_hash_manifest(html)
    expected = digest_of("sha256", "console.log('a');\nconsole.log('b');")
    assert [e.digest for e in manifest.entries] == [expected]


def test_script_entities_not_decoded() -> None:
    # script is a raw text element: entities must be hashed literally.
    content = "if (a &amp;&amp; b) { alert('x &amp; y'); }"
    manifest = generate_hash_manifest(f"<script>{content}</script>")
    assert [e.digest for e in manifest.entries] == [SHA256_RAW_ENTITIES]
    assert SHA256_RAW_ENTITIES == digest_of("sha256", content)


def test_empty_elements_skipped() -> None:
    html = '<script></script><script src="x.js"></script><style></style>'
    assert generate_hash_manifest(html).entries == []


def test_whitespace_only_content_hashed() -> None:
    # Browsers still execute whitespace-only inline scripts, so they need a hash.
    manifest = generate_hash_manifest("<script> </script>")
    assert [e.digest for e in manifest.entries] == [SHA256_SPACE]


def test_case_insensitive_tags() -> None:
    manifest = generate_hash_manifest("<SCRIPT>alert('Hello, world.');</SCRIPT>")
    assert [e.digest for e in manifest.entries] == [SHA256_HELLO]


def test_dedupe_keeps_all_sources() -> None:
    html = (
        "<html><head>\n"
        "<script>alert('Hello, world.');</script>\n"
        "</head><body>\n"
        "<script>alert('Hello, world.');</script>\n"
        "<script>alert('other');</script>\n"
        "</body></html>"
    )
    manifest = generate_hash_manifest(html)
    assert len(manifest.entries) == 2
    hello_entry = next(e for e in manifest.entries if e.digest == SHA256_HELLO)
    assert len(hello_entry.sources) == 2
    first, second = hello_entry.sources
    assert (first.element, first.index, first.line) == ("script", 1, 2)
    assert (second.element, second.index, second.line) == ("script", 2, 4)
    assert first.column == 1


def test_source_expressions_and_directive_sources() -> None:
    html = "<script>alert('Hello, world.');</script><style>body { color: red; }</style>"
    manifest = generate_hash_manifest(html)
    assert manifest.source_expressions("script") == [f"'sha256-{SHA256_HELLO}'"]
    assert manifest.source_expressions("style") == [f"'sha256-{SHA256_STYLE}'"]
    assert manifest.directive_sources() == {
        "script-src": [f"'sha256-{SHA256_HELLO}'"],
        "style-src": [f"'sha256-{SHA256_STYLE}'"],
    }


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'"],
        }
    }
)
def test_build_policy_includes_manifest_hashes() -> None:
    html = "<script>alert('Hello, world.');</script><style>body { color: red; }</style>"
    manifest = generate_hash_manifest(html)
    policy = build_policy(hash_manifest=manifest)
    policy_eq(
        "default-src 'self'; "
        f"script-src 'self' 'sha256-{SHA256_HELLO}'; "
        f"style-src 'self' 'sha256-{SHA256_STYLE}'",
        policy,
    )


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["'none'"]}})
def test_build_policy_creates_directives_for_hashes() -> None:
    html = "<script>alert('Hello, world.');</script>"
    policy = build_policy(hash_manifest=generate_hash_manifest(html))
    policy_eq(f"default-src 'none'; script-src 'sha256-{SHA256_HELLO}'", policy)


def test_build_policy_hashes_match_actual_content() -> None:
    # End-to-end: every hash in the header must verify against the real body.
    body = (
        "<!DOCTYPE html>\n"
        "<!-- <script>alert('comment')</script> -->\n"
        '<script src="https://example.com/app.js"></script>\n'
        "<script>console.log('a');\r\nconsole.log('b');\r\n</script>\n"
        "<style>body { color: red; }</style>\n"
        "<script></script>\n"
    )
    manifest = generate_hash_manifest(body, algorithms=("sha256", "sha384"))
    policy = build_policy(config={"default-src": ["'none'"]}, hash_manifest=manifest)

    script_content = "console.log('a');\nconsole.log('b');\n"
    style_content = "body { color: red; }"
    expected_script = {f"'{alg}-{digest_of(alg, script_content)}'" for alg in ("sha256", "sha384")}
    expected_style = {f"'{alg}-{digest_of(alg, style_content)}'" for alg in ("sha256", "sha384")}
    directives = dict(part.split(" ", 1) for part in policy.split("; "))
    assert set(directives["script-src"].split()) == expected_script
    assert set(directives["style-src"].split()) == expected_style
