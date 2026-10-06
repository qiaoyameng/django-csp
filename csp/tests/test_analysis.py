from __future__ import annotations

import base64

from csp.analysis import analyze_csp, analyze_policy
from csp.constants import NONCE


SHA256 = f"'sha256-{base64.b64encode(b'x' * 32).decode('ascii')}'"


def finding_codes(policy: object) -> list[str]:
    return [finding.code for finding in getattr(policy, "findings")]


def constraint_values(policy: object, target: str) -> list[str]:
    return [token.value for token in policy.effective_constraints[target].values]


def ignored_values(policy: object, target: str) -> dict[str, list[str]]:
    constraint = policy.effective_constraints[target]
    return {token.value: token.reasons for token in constraint.ignored_values}


def test_text_policy_parses_directives_with_source_locations() -> None:
    policy = analyze_policy("default-src 'self'; img-src https://example.com")

    assert policy.source_type == "text"
    default_directive = policy.directives["default-src"].effective_occurrence
    assert default_directive is not None
    assert default_directive.location.start == 0
    assert default_directive.values[0].location.start == 12
    img_directive = policy.directives["img-src"].effective_occurrence
    assert img_directive is not None
    assert img_directive.values[0].location.start == 28


def test_structured_policy_accepts_directives_mapping() -> None:
    policy = analyze_policy({"DIRECTIVES": {"default-src": ["'self'"], "img-src": ("https://example.com",)}})

    assert policy.directives["default-src"].effective_occurrence.values[0].value == "'self'"
    assert policy.directives["img-src"].effective_occurrence.values[0].value == "https://example.com"


def test_duplicate_directive_keeps_first_and_links_both_locations() -> None:
    policy = analyze_policy("script-src 'self'; script-src https://cdn.example")

    assert "duplicate-directive" in finding_codes(policy)
    effective = policy.directives["script-src"].effective_occurrence
    assert effective is not None
    assert [token.value for token in effective.values] == ["'self'"]
    duplicate = policy.directives["script-src"].occurrences[1]
    assert duplicate.ignored is True
    assert duplicate.ignore_reason == "duplicate-directive"


def test_invalid_source_token_is_reported_and_does_not_allow_resource() -> None:
    policy = analyze_policy("img-src 'not-a-keyword'")

    token = policy.directives["img-src"].effective_occurrence.values[0]
    assert token.status == "invalid"
    assert "invalid-source-token" in token.reasons
    assert ignored_values(policy, "images")["'not-a-keyword'"]


def test_none_mixed_with_sources_is_ignored() -> None:
    policy = analyze_policy("default-src 'none' 'self' https://example.com")

    assert "none-mixed-with-sources" in finding_codes(policy)
    none_token = policy.directives["default-src"].effective_occurrence.values[0]
    assert none_token.status == "ignored"
    assert none_token.reasons == ["none-ignored-with-other-sources"]
    assert constraint_values(policy, "images") == ["'self'", "https://example.com"]


def test_strict_dynamic_with_nonce_ignores_host_self_and_scheme() -> None:
    policy = analyze_policy(
        "script-src 'self' https://cdn.example https: 'nonce-abc123' 'strict-dynamic'"
    )

    assert "strict-dynamic-ignores-host-sources" in finding_codes(policy)
    ignored = ignored_values(policy, "script-elements")
    assert "source-ignored-by-strict-dynamic" in ignored["'self'"]
    assert "source-ignored-by-strict-dynamic" in ignored["https://cdn.example"]
    assert "source-ignored-by-strict-dynamic" in ignored["https:"]
    assert constraint_values(policy, "script-elements") == ["'nonce-abc123'", "'strict-dynamic'"]


def test_strict_dynamic_with_hash_works_in_structured_policy() -> None:
    policy = analyze_policy({"DIRECTIVES": {"script-src": [SHA256, "'strict-dynamic'"]}})

    assert constraint_values(policy, "script-elements") == [SHA256, "'strict-dynamic'"]
    assert "strict-dynamic-without-nonce-or-hash" not in finding_codes(policy)


def test_strict_dynamic_without_nonce_or_hash_is_ignored() -> None:
    policy = analyze_policy("script-src 'self' 'strict-dynamic'")

    assert "strict-dynamic-without-nonce-or-hash" in finding_codes(policy)
    assert ignored_values(policy, "script-elements")["'strict-dynamic'"]


def test_style_unsafe_inline_is_accepted_when_nonce_is_present() -> None:
    policy = analyze_policy("style-src 'unsafe-inline' 'nonce-abc123'")

    assert "invalid-source-token" not in finding_codes(policy)
    assert "unsafe-inline-ignored" in finding_codes(policy)


def test_unsafe_inline_is_ignored_when_nonce_is_present() -> None:
    policy = analyze_policy("script-src 'unsafe-inline' 'nonce-abc123'")

    assert "unsafe-inline-ignored" in finding_codes(policy)
    assert ignored_values(policy, "script-elements")["'unsafe-inline'"]


def test_explicit_empty_directive_blocks_target() -> None:
    policy = analyze_policy("default-src 'self'; img-src")

    constraint = policy.effective_constraints["images"]
    assert constraint.status == "empty"
    assert constraint.directive == "img-src"
    assert constraint.values == []


def test_empty_structured_directive_is_explicitly_empty() -> None:
    policy = analyze_policy({"DIRECTIVES": {"img-src": []}})

    occurrence = policy.directives["img-src"].effective_occurrence
    assert occurrence is not None
    assert occurrence.explicitly_empty is True
    assert policy.effective_constraints["images"].status == "empty"


def test_specialized_directive_falls_back_to_default_src() -> None:
    policy = analyze_policy("default-src https://example.com")

    constraint = policy.effective_constraints["images"]
    assert constraint.status == "fallback"
    assert constraint.directive == "default-src"
    assert constraint.fallback_chain == ["img-src", "default-src"]
    assert constraint_values(policy, "images") == ["https://example.com"]


def test_script_src_elem_overrides_script_src_for_script_elements() -> None:
    policy = analyze_policy(
        "script-src 'none'; script-src-elem https://scripts.example; script-src-attr 'none'"
    )

    elements = policy.effective_constraints["script-elements"]
    attributes = policy.effective_constraints["script-attributes"]
    assert elements.directive == "script-src-elem"
    assert constraint_values(policy, "script-elements") == ["https://scripts.example"]
    assert attributes.directive == "script-src-attr"
    assert constraint_values(policy, "script-attributes") == ["'none'"]


def test_script_attribute_hash_requires_unsafe_hashes() -> None:
    policy = analyze_policy(f"script-src-attr {SHA256}")

    assert ignored_values(policy, "script-attributes")[SHA256]


def test_script_attribute_hash_is_effective_with_unsafe_hashes() -> None:
    policy = analyze_policy(f"script-src-attr 'unsafe-hashes' {SHA256}")

    assert constraint_values(policy, "script-attributes") == ["'unsafe-hashes'", SHA256]


def test_script_evaluation_targets_eval_keywords() -> None:
    policy = analyze_policy("script-src 'self' 'unsafe-eval'")

    assert constraint_values(policy, "script-evaluation") == ["'unsafe-eval'"]
    assert ignored_values(policy, "script-evaluation")["'self'"]


def test_csp2_ignores_script_src_elem_and_falls_back() -> None:
    policy = analyze_policy(
        "script-src 'none'; script-src-elem https://scripts.example",
        version=2,
    )

    assert "unsupported-directive-version" in finding_codes(policy)
    constraint = policy.effective_constraints["script-elements"]
    assert constraint.directive == "script-src"
    assert constraint_values(policy, "script-elements") == ["'none'"]


def test_csp3_plugin_types_is_unsupported() -> None:
    policy = analyze_policy("plugin-types application/pdf", version=3)

    assert "unsupported-directive-version" in finding_codes(policy)
    assert policy.directives["plugin-types"].effective_occurrence.ignored is True


def test_trailing_semicolon_is_not_an_empty_segment_finding() -> None:
    policy = analyze_policy("img-src 'self';")

    assert "empty-policy-segment" not in finding_codes(policy)


def test_unknown_extension_is_retained_as_unknown() -> None:
    policy = analyze_policy("default-src 'self'; future-src https://example.invalid")

    occurrence = policy.directives["future-src"].occurrences[0]
    assert occurrence.ignored is True
    assert occurrence.ignore_reason == "unknown-directive"
    assert all(token.status == "unknown" for token in occurrence.values)
    assert "unknown-directive" in finding_codes(policy)


def test_unknown_structured_extension_is_not_used_as_default_fallback() -> None:
    policy = analyze_policy({"DIRECTIVES": {"future-src": ["https://example.invalid"]}})

    assert policy.directives["future-src"].occurrences[0].values[0].status == "unknown"
    assert policy.effective_constraints["images"].directive is None


def test_multiple_policies_are_analyzed_independently_with_indices() -> None:
    report = analyze_csp(
        [
            "default-src 'self'",
            {"DIRECTIVES": {"default-src": ["'none'"], "script-src": ["'nonce-abc123'"]}},
        ]
    )

    assert len(report.policies) == 2
    assert report.policies[0].index == 0
    assert report.policies[1].index == 1
    assert report.policies[0].effective_constraints["images"].directive == "default-src"
    assert report.policies[1].directives["script-src"].occurrences[0].location.policy_index == 1
    assert "security score" not in report.description.lower()


def test_nonce_sentinel_is_structured_placeholder() -> None:
    policy = analyze_policy({"DIRECTIVES": {"script-src": [NONCE, "'strict-dynamic'"]}})

    token = policy.directives["script-src"].effective_occurrence.values[0]
    assert token.kind == "nonce-placeholder"
    assert constraint_values(policy, "script-elements") == ["'nonce-<request>", "'strict-dynamic'"]
