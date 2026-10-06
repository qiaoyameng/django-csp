import pytest

from csp.analyzer import (
    CSP2,
    CSP3,
    DISCLAIMER,
    NONCE_PLACEHOLDER,
    AnalysisReport,
    analyze,
    classify_source,
    parse_config,
    parse_policy_text,
    render_text,
)
from csp.constants import NONCE


def codes(report):
    return [issue.code for issue in report.issues]


def test_classify_source() -> None:
    assert classify_source("'self'") == "keyword"
    assert classify_source("'nonce-abc123='") == "nonce"
    assert classify_source("'sha256-abcdef+/='") == "hash"
    assert classify_source("https:") == "scheme"
    assert classify_source("https://cdn.example.com:443/path") == "host"
    assert classify_source("*.example.com") == "host"
    assert classify_source("'future-keyword'") == "keyword-unknown"
    assert classify_source("not a source") == "invalid"


def test_parse_policy_text_duplicate_directive_first_wins() -> None:
    directives, issues = parse_policy_text("script-src 'self'; script-src 'none'")
    assert [d.name for d in directives] == ["script-src"]
    assert directives[0].values == ["'self'"]
    assert [i.code for i in issues] == ["duplicate-directive"]
    assert issues[0].directive == "script-src"


def test_parse_policy_text_skips_empty_segments() -> None:
    directives, issues = parse_policy_text("default-src 'self';; img-src https:;")
    assert [d.name for d in directives] == ["default-src", "img-src"]
    assert issues == []


def test_parse_config_directives_wrapper_and_nonce_sentinel() -> None:
    directives, issues = parse_config({"DIRECTIVES": {"script-src": ["'self'", NONCE], "img-src": None, "upgrade-insecure-requests": True}})
    assert issues == []
    by_name = {d.name: d.values for d in directives}
    assert by_name["script-src"] == ["'self'", NONCE_PLACEHOLDER]
    assert "img-src" not in by_name
    assert by_name["upgrade-insecure-requests"] == []


def test_none_mixed_with_other_sources() -> None:
    report = analyze("script-src 'none' 'self'").policies[0]
    assert "'none'" in [value for value, _reason in report.directive("script-src").ignored]
    resource = report.resource("script-elem")
    verdicts = {s.value: s for s in resource.sources}
    assert verdicts["'none'"].status == "ignored"
    assert "combined" in verdicts["'none'"].reason
    assert verdicts["'self'"].status == "effective"


def test_none_alone_is_effective() -> None:
    report = analyze("script-src 'none'").policies[0]
    resource = report.resource("script-elem")
    assert [(s.value, s.status) for s in resource.sources] == [("'none'", "effective")]


def test_strict_dynamic_ignores_host_sources_csp3() -> None:
    report = analyze("script-src 'self' https://cdn.example.com 'strict-dynamic' 'nonce-abc123'", version=CSP3).policies[0]
    resource = report.resource("script-elem")
    verdicts = {s.value: s for s in resource.sources}
    assert verdicts["'self'"].status == "ignored"
    assert "strict-dynamic" in verdicts["'self'"].reason
    assert verdicts["https://cdn.example.com"].status == "ignored"
    assert verdicts["'strict-dynamic'"].status == "effective"
    assert verdicts["'nonce-abc123'"].status == "effective"


def test_strict_dynamic_ignored_csp2() -> None:
    report = analyze("script-src 'self' 'strict-dynamic'", version=CSP2).policies[0]
    assert "unsupported-version" in codes(report)
    resource = report.resource("script-elem")
    verdicts = {s.value: s for s in resource.sources}
    assert verdicts["'strict-dynamic'"].status == "ignored"
    assert verdicts["'self'"].status == "effective"


def test_strict_dynamic_with_hash_keeps_hash_effective() -> None:
    report = analyze("script-src 'sha256-abcdef123456+/' 'strict-dynamic' example.com", version=CSP3).policies[0]
    resource = report.resource("script-elem")
    verdicts = {s.value: s for s in resource.sources}
    assert verdicts["'sha256-abcdef123456+/'"].status == "effective"
    assert verdicts["example.com"].status == "ignored"


def test_unsafe_inline_ignored_when_nonce_present_csp3() -> None:
    report = analyze("script-src 'unsafe-inline' 'nonce-abc123'", version=CSP3).policies[0]
    verdicts = {s.value: s for s in report.resource("script-elem").sources}
    assert verdicts["'unsafe-inline'"].status == "ignored"
    assert "nonce or hash" in verdicts["'unsafe-inline'"].reason


def test_unsafe_inline_effective_with_nonce_csp2() -> None:
    report = analyze("script-src 'unsafe-inline' 'nonce-abc123'", version=CSP2).policies[0]
    verdicts = {s.value: s for s in report.resource("script-elem").sources}
    assert verdicts["'unsafe-inline'"].status == "effective"


def test_explicit_empty_directive_blocks_all() -> None:
    report = analyze("img-src; default-src 'self'").policies[0]
    assert "empty-directive" in codes(report)
    resource = report.resource("img")
    assert resource.directive == "img-src"
    assert resource.via_fallback is False
    assert resource.sources == []
    assert "are blocked" in resource.note


def test_explicit_empty_directive_from_config() -> None:
    report = analyze({"DIRECTIVES": {"img-src": [], "default-src": ["'self'"]}}).policies[0]
    assert "empty-directive" in codes(report)
    assert report.resource("img").directive == "img-src"


def test_invalid_source_token_reported() -> None:
    report = analyze("script-src 'self' ** %").policies[0]
    invalid = [i for i in report.issues if i.code == "invalid-source"]
    assert len(invalid) == 2  # "**" and "%"
    assert all(i.directive == "script-src" for i in invalid)
    verdicts = {s.value: s for s in report.resource("script-elem").sources}
    assert verdicts["**"].status == "unknown"


def test_unknown_directive_and_keyword_kept_unknown() -> None:
    report = analyze("future-dir 'self'; script-src 'self' 'future-keyword'").policies[0]
    assert "unknown-directive" in codes(report)
    assert "unknown-keyword" in codes(report)
    directive = report.directive("future-dir")
    assert directive.known is False
    assert directive.values == ["'self'"]
    verdicts = {s.value: s for s in report.resource("script-elem").sources}
    assert verdicts["'future-keyword'"].status == "unknown"
    assert "extension" in verdicts["'future-keyword'"].reason


def test_misplaced_nonce_flagged() -> None:
    report = analyze("img-src 'nonce-abc123'").policies[0]
    misplaced = [i for i in report.issues if i.code == "misplaced-source"]
    assert len(misplaced) == 1
    assert misplaced[0].directive == "img-src"


def test_fallback_chain_reported() -> None:
    report = analyze("default-src 'self'; script-src https://scripts.example.com").policies[0]
    elem = report.resource("script-elem")
    assert elem.directive == "script-src"
    assert elem.via_fallback is True
    assert elem.chain == ["script-src-elem", "script-src", "default-src"]
    attr = report.resource("script-attr")
    assert attr.directive == "script-src"
    style = report.resource("style-elem")
    assert style.directive == "default-src"
    assert style.via_fallback is True
    worker = report.resource("worker")
    assert worker.chain == ["worker-src", "child-src", "script-src", "default-src"]
    assert worker.directive == "script-src"


def test_script_src_elem_wins_over_script_src_csp3() -> None:
    report = analyze("script-src-elem 'self'; script-src 'none'", version=CSP3).policies[0]
    elem = report.resource("script-elem")
    assert elem.directive == "script-src-elem"
    assert elem.via_fallback is False
    attr = report.resource("script-attr")
    assert attr.directive == "script-src"


def test_script_src_elem_ignored_csp2() -> None:
    report = analyze("script-src-elem 'self'; script-src https://scripts.example.com", version=CSP2).policies[0]
    assert "unsupported-version" in codes(report)
    elem = report.resource("script-elem")
    assert elem.chain == ["script-src", "default-src"]
    assert elem.directive == "script-src"


def test_unrestricted_resource() -> None:
    report = analyze("default-src 'self'").policies[0]
    resource = report.resource("form-action")
    assert resource.directive is None
    assert "not restricted" in resource.note


def test_multiple_policies_intersection() -> None:
    report = analyze([
        {"DIRECTIVES": {"default-src": ["'self'"], "script-src": ["'self'", "https://cdn.example.com"]}},
        "script-src 'none'; img-src https:",
    ])
    assert isinstance(report, AnalysisReport)
    assert len(report.policies) == 2
    assert report.policies[0].origin == "config"
    assert report.policies[1].origin == "text"
    assert report.policies[0].resource("script-elem").directive == "script-src"
    assert report.policies[1].resource("script-elem").directive == "script-src"
    combined = "\n".join(report.combined)
    assert "every policy" in combined
    assert "script-elem: policy 0: constrained by 'script-src'; policy 1: constrained by 'script-src'" in combined
    assert "img: policy 0: constrained by 'default-src'; policy 1: constrained by 'img-src'" in combined


def test_single_policy_has_no_combined_notes() -> None:
    report = analyze("default-src 'self'")
    assert report.combined == []


def test_disclaimer_present_and_no_score() -> None:
    report = analyze("default-src 'self'")
    assert report.disclaimer == DISCLAIMER
    text = render_text(report)
    assert "not a security audit" in text
    assert "score" not in text.lower().replace("security score", "")


def test_render_text_points_back_to_source() -> None:
    report = analyze("default-src 'self'; script-src 'strict-dynamic' https://cdn.example.com 'nonce-abc'")
    text = render_text(report)
    assert "Policy 0 (text)" in text
    assert "script-elem: script-src (via fallback: script-src-elem -> script-src -> default-src)" in text
    assert "ignored: https://cdn.example.com -- ignored because 'strict-dynamic' is present (CSP Level 3)" in text


def test_invalid_version_rejected() -> None:
    with pytest.raises(ValueError):
        analyze("default-src 'self'", version=1)


def test_invalid_input_type_rejected() -> None:
    with pytest.raises(TypeError):
        analyze(42)


def test_analysis_does_not_mutate_input() -> None:
    config = {"DIRECTIVES": {"script-src": ["'self'", NONCE], "img-src": []}}
    analyze(config)
    assert config == {"DIRECTIVES": {"script-src": ["'self'", NONCE], "img-src": []}}
