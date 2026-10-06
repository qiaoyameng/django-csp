from __future__ import annotations

import pickle

from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

from csp.constants import HEADER, HEADER_REPORT_ONLY, NONE, NONCE, SELF
from csp.decorators import csp, csp_replace, csp_update
from csp.middleware import CSPMiddleware
from csp.policies import PolicyParts, PolicyPartsCollection
from csp.tests.utils import response as response_factory


rf = RequestFactory()
mw = CSPMiddleware(response_factory())


def policies_for(header: str) -> list[str]:
    return [policy.strip() for policy in header.split(",")]


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {"default-src": [SELF]},
        "ADDITIONAL_POLICIES": [
            {"DIRECTIVES": {"default-src": [SELF], "script-src": ["cdn.example"]}},
            {"DIRECTIVES": {"default-src": [SELF], "script-src": ["payments.example"]}},
        ],
    }
)
def test_enforced_additional_policies_keep_script_sources_separate() -> None:
    response = HttpResponse()

    mw.process_response(rf.get("/"), response)

    assert policies_for(response[HEADER]) == [
        "default-src 'self'",
        "default-src 'self'; script-src cdn.example",
        "default-src 'self'; script-src payments.example",
    ]


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {"default-src": [SELF], "script-src": ["cdn.example", NONCE]},
        "ADDITIONAL_POLICIES": [
            {"DIRECTIVES": {"default-src": [SELF], "script-src": ["payments.example"]}}
        ],
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY={
        "DIRECTIVES": {"default-src": [SELF], "script-src": ["reports.example", NONCE]},
        "ADDITIONAL_POLICIES": [
            {"DIRECTIVES": {"default-src": [SELF], "script-src": ["reports-strict.example"]}}
        ],
    },
)
def test_nonce_is_processed_independently_in_each_policy() -> None:
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(request.csp_nonce)
    response = HttpResponse()

    mw.process_response(request, response)

    enforced = policies_for(response[HEADER])
    report_only = policies_for(response[HEADER_REPORT_ONLY])
    assert enforced == [
        f"default-src 'self'; script-src cdn.example 'nonce-{nonce}'",
        "default-src 'self'; script-src payments.example",
    ]
    assert report_only == [
        f"default-src 'self'; script-src reports.example 'nonce-{nonce}'",
        "default-src 'self'; script-src reports-strict.example",
    ]
    assert f"'nonce-{nonce}'" not in enforced[1]


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {"default-src": [SELF], "script-src": ["cdn.example"]},
        "ADDITIONAL_POLICIES": [
            {
                "DIRECTIVES": {
                    "default-src": [NONE],
                    "script-src": [
                        "'sha256-RFWPLDbv2BY+rCkDzsE+0fr8ylGr2R2faWMhq4lfEQc='",
                    ],
                    "frame-src": [],
                    "sandbox": [],
                }
            }
        ],
    }
)
def test_default_src_hash_and_empty_directive_are_per_policy() -> None:
    response = HttpResponse()

    mw.process_response(rf.get("/"), response)

    assert policies_for(response[HEADER]) == [
        "default-src 'self'; script-src cdn.example",
        "default-src 'none'; script-src 'sha256-RFWPLDbv2BY+rCkDzsE+0fr8ylGr2R2faWMhq4lfEQc='; frame-src; sandbox",
    ]


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {"default-src": [SELF], "script-src": ["cdn.example"]},
        "ADDITIONAL_POLICIES": [
            {"DIRECTIVES": {"default-src": [SELF], "script-src": ["payments.example"]}},
            {"DIRECTIVES": {"default-src": [SELF], "script-src": ["second.example"]}},
        ],
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY={
        "DIRECTIVES": {"default-src": [SELF], "script-src": ["reports.example"]},
        "ADDITIONAL_POLICIES": [
            {"DIRECTIVES": {"default-src": [SELF], "script-src": ["payments.example"]}}
        ],
    },
)
def test_decorator_update_and_replace_target_only_specified_policy() -> None:
    @csp_update({"script-src": ["newly-allowed.example"]})
    @csp_update({"script-src": ["payments-only.example"]}, POLICY_INDEX=1)
    @csp_replace({"script-src": ["second-replaced.example"]}, POLICY_INDEX=2)
    @csp_replace({"script-src": ["reports-replaced.example"]}, REPORT_ONLY=True)
    def view() -> HttpResponse:
        return HttpResponse()

    response = view()
    mw.process_response(rf.get("/"), response)

    assert policies_for(response[HEADER]) == [
        "default-src 'self'; script-src cdn.example newly-allowed.example",
        "default-src 'self'; script-src payments.example payments-only.example",
        "default-src 'self'; script-src second-replaced.example",
    ]
    assert policies_for(response[HEADER_REPORT_ONLY]) == [
        "default-src 'self'; script-src reports-replaced.example",
        "default-src 'self'; script-src payments.example",
    ]


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF], "script-src": ["cdn.example"]}})
def test_csp_decorator_can_add_explicit_additional_policy() -> None:
    @csp({"default-src": [SELF], "script-src": ["module.example"]}, POLICY_INDEX=1)
    def view() -> HttpResponse:
        return HttpResponse()

    response = view()
    mw.process_response(rf.get("/"), response)

    assert policies_for(response[HEADER]) == [
        "default-src 'self'; script-src cdn.example",
        "default-src 'self'; script-src module.example",
    ]


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {"default-src": [SELF], "script-src": ["cdn.example", "payments.example"]},
        "ADDITIONAL_POLICIES": [
            {"DIRECTIVES": {"default-src": [SELF], "script-src": ["payments.example"]}}
        ],
    }
)
def test_additional_policy_does_not_broaden_effective_permissions() -> None:
    response = HttpResponse()

    mw.process_response(rf.get("/"), response)

    enforced_policies = policies_for(response[HEADER])
    assert "script-src cdn.example payments.example" in enforced_policies[0]
    assert "script-src payments.example" in enforced_policies[1]
    assert "cdn.example" not in enforced_policies[1]


def test_policy_collection_round_trip_preserves_policy_structure() -> None:
    collection = PolicyPartsCollection(
        enforced=[
            PolicyParts(
                config={"default-src": [SELF], "script-src": {"cdn.example", NONCE}},
                update={"img-src": ("images.example",)},
                replace={"object-src": None},
                nonce="abc123",
            )
        ],
        report_only=[
            PolicyParts(
                config={"default-src": [NONE], "script-src": ["reports.example"]},
            )
        ],
    )

    restored = PolicyPartsCollection.from_json(collection.to_json())

    assert restored == collection
    assert restored.enforced[0].config["script-src"] == {"cdn.example", NONCE}
    assert restored.enforced[0].update["img-src"] == ("images.example",)
    assert pickle.loads(pickle.dumps(restored)) == collection


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {"default-src": [SELF]},
        "ADDITIONAL_POLICIES": [
            {"DIRECTIVES": {"default-src": [SELF], "img-src": ["images.example"]}}
        ],
    }
)
def test_legacy_get_policy_parts_override_still_affects_primary_policy() -> None:
    class CustomMiddleware(CSPMiddleware):
        def get_policy_parts(self, request, response, report_only=False):
            policy_parts = super().get_policy_parts(request, response, report_only)
            if not report_only:
                policy_parts.replace = {
                    **(policy_parts.replace or {}),
                    "object-src": ["objects.example"],
                }
            return policy_parts

    custom_middleware = CustomMiddleware(response_factory())
    response = HttpResponse()

    custom_middleware.process_response(rf.get("/"), response)

    assert policies_for(response[HEADER]) == [
        "default-src 'self'; object-src objects.example",
        "default-src 'self'; img-src images.example",
    ]
