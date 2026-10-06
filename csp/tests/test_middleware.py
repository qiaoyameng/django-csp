from django.http import (
    HttpResponse,
    HttpResponseNotFound,
    HttpResponseServerError,
)
from django.template import Context, Template, engines
from django.test import RequestFactory
from django.test.utils import override_settings

import pytest

from csp.constants import HEADER, HEADER_REPORT_ONLY, NONCE, SELF
from csp.exceptions import CSPNonceError
from csp.middleware import CheckableLazyObject, CSPMiddleware
from csp.tests.utils import response

mw = CSPMiddleware(response())
rf = RequestFactory()


def test_checkable_lazy_object() -> None:
    def generate_value() -> str:
        return "generated"

    lazy = CheckableLazyObject(generate_value)

    # Before wrapped object is initiated, lazy is falsy
    assert bool(lazy) is False

    # After str(lazy) calls generate_value, lazy is truthy
    assert str(lazy) == "generated"
    assert bool(lazy) is True


def test_add_header() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["example.com"]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_both_headers() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response
    assert HEADER_REPORT_ONLY in response


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": {"example.com"}}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": {SELF}}},
)
def test_directives_configured_as_sets() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response
    assert HEADER_REPORT_ONLY in response


def test_exempt() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_exempt", True)
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(CONTENT_SECURITY_POLICY={"EXCLUDE_URL_PREFIXES": ["/inlines-r-us"]})
def test_exclude() -> None:
    request = rf.get("/inlines-r-us/foo")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(
    CONTENT_SECURITY_POLICY=None,
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_report_only() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER not in response
    assert HEADER_REPORT_ONLY in response
    assert response[HEADER_REPORT_ONLY] == "default-src 'self'"


def test_dont_replace() -> None:
    request = rf.get("/")
    response = HttpResponse()
    response[HEADER] = "default-src example.com"
    mw.process_response(request, response)
    assert response[HEADER] == "default-src example.com"


def test_use_config() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_config", {"default-src": ["example.com"]})
    mw.process_response(request, response)
    assert response[HEADER] == "default-src example.com"


def test_use_update() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_update", {"default-src": ["example.com"]})
    mw.process_response(request, response)
    assert response[HEADER] == "default-src 'self' example.com"


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["foo.com"]}})
def test_use_replace() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_replace", {"img-src": ["bar.com"]})
    mw.process_response(request, response)
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'", "img-src bar.com"]


@override_settings(DEBUG=True)
def test_debug_errors_exempt() -> None:
    request = rf.get("/")
    response = HttpResponseServerError()
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(DEBUG=True)
def test_debug_notfound_exempt() -> None:
    request = rf.get("/")
    response = HttpResponseNotFound()
    mw.process_response(request, response)
    assert HEADER not in response


def test_nonce_created_when_accessed() -> None:
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    response = HttpResponse()
    mw.process_response(request, response)
    assert nonce in response[HEADER]
    assert response[HEADER] == f"default-src 'self' 'nonce-{nonce}'"


def test_nonce_is_false_before_access_and_true_after() -> None:
    request = rf.get("/")
    mw.process_request(request)
    assert bool(getattr(request, "csp_nonce")) is False
    nonce = str(getattr(request, "csp_nonce"))
    assert bool(getattr(request, "csp_nonce")) is True

    response = HttpResponse()
    mw.process_response(request, response)
    assert bool(getattr(request, "csp_nonce")) is True
    assert getattr(request, "csp_nonce") == nonce


def test_nonce_conditional_in_django_template() -> None:
    """An unset nonce is Falsy in a template context"""

    template = Template(
        """
        {% if request.csp_nonce %}
          The CSP nonce is {{ request.csp_nonce }}.
        {% else %}
          The CSP nonce is not set.
        {% endif %}
    """
    )
    request = rf.get("/")
    context = Context({"request": request})

    mw.process_request(request)
    rendered_unset = template.render(context).strip()
    assert rendered_unset == "The CSP nonce is not set."

    nonce = str(getattr(request, "csp_nonce"))
    rendered_set = template.render(context).strip()
    assert rendered_set == f"The CSP nonce is {nonce}."


def test_nonce_usage_in_django_template() -> None:
    """Reading a nonce in a template context generates the nonce"""

    template = Template("The CSP nonce is {{ request.csp_nonce }}.")
    request = rf.get("/")
    context = Context({"request": request})

    mw.process_request(request)
    nonce = getattr(request, "csp_nonce", None)
    assert bool(nonce) is False
    rendered = template.render(context)
    assert bool(nonce) is True
    assert rendered == f"The CSP nonce is {nonce}."


def test_nonce_conditional_in_jinja2_template() -> None:
    """An unset nonce is Falsy in a template context"""

    template = engines["jinja2"].from_string(
        """
        {% if request.csp_nonce %}
          The CSP nonce is {{ request.csp_nonce }}.
        {% else %}
          The CSP nonce is not set.
        {% endif %}
    """
    )
    request = rf.get("/")
    context = {"request": request}

    mw.process_request(request)
    rendered_unset = template.render(context).strip()
    assert rendered_unset == "The CSP nonce is not set."

    nonce = str(getattr(request, "csp_nonce"))
    rendered_set = template.render(context).strip()
    assert rendered_set == f"The CSP nonce is {nonce}."


def test_nonce_usage_in_jinja2_template() -> None:
    """Reading a nonce in a template context generates the nonce"""

    template = engines["jinja2"].from_string("The CSP nonce is {{ request.csp_nonce }}.")
    request = rf.get("/")
    context = {"request": request}

    mw.process_request(request)
    nonce = getattr(request, "csp_nonce", None)
    assert bool(nonce) is False
    rendered = template.render(context)
    assert bool(nonce) is True
    assert rendered == f"The CSP nonce is {nonce}."


def test_no_nonce_when_not_accessed() -> None:
    request = rf.get("/")
    mw.process_request(request)
    response = HttpResponse()
    mw.process_response(request, response)
    assert "nonce-" not in response[HEADER]
    assert response[HEADER] == "default-src 'self'"


def test_nonce_regenerated_on_new_request() -> None:
    request1 = rf.get("/")
    request2 = rf.get("/")
    mw.process_request(request1)
    mw.process_request(request2)
    nonce1 = str(getattr(request1, "csp_nonce"))
    nonce2 = str(getattr(request2, "csp_nonce"))
    assert nonce1 != nonce2

    response1 = HttpResponse()
    response2 = HttpResponse()
    mw.process_response(request1, response1)
    mw.process_response(request2, response2)
    assert nonce1 not in response2[HEADER]
    assert nonce2 not in response1[HEADER]


def test_no_nonce_access_after_middleware_is_attribute_error() -> None:
    # Test `CSPNonceError` is raised when accessing an unset nonce after the response has been processed.
    request = rf.get("/")
    mw.process_request(request)
    mw.process_response(request, HttpResponse())
    assert bool(getattr(request, "csp_nonce", True)) is False
    with pytest.raises(CSPNonceError):
        str(getattr(request, "csp_nonce"))


def test_set_nonce_access_after_middleware_is_ok() -> None:
    # Test accessing a set nonce after the response has been processed is OK.
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    mw.process_response(request, HttpResponse())
    assert bool(getattr(request, "csp_nonce", False)) is True
    assert str(getattr(request, "csp_nonce")) == nonce


def test_additional_policies() -> None:
    # Two policies allowing different script sources are output as separate
    # policies, each with its own default-src fallback.
    request = rf.get("/")
    response = HttpResponse()
    response._csp_additional = [{"script-src": ["https://cdn.example.com"]}]
    mw.process_response(request, response)
    policies = response[HEADER].split(", ")
    assert len(policies) == 2
    assert sorted(policies[0].split("; ")) == ["default-src 'self'"]
    assert sorted(policies[1].split("; ")) == [
        "default-src 'self'",
        "script-src https://cdn.example.com",
    ]


def test_additional_policies_multiple() -> None:
    request = rf.get("/")
    response = HttpResponse()
    response._csp_additional = [
        {"script-src": ["https://one.example.com"]},
        {"script-src": ["https://two.example.com"]},
    ]
    mw.process_response(request, response)
    policies = response[HEADER].split(", ")
    assert len(policies) == 3
    assert "script-src https://one.example.com" in policies[1]
    assert "script-src https://two.example.com" in policies[2]


def test_additional_policies_nonce_independent() -> None:
    # Each policy handles the nonce independently: a policy only gets the
    # nonce if its own directives opt in via the NONCE sentinel.
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    response = HttpResponse()
    response._csp_additional = [
        {"script-src": [SELF, NONCE]},
        {"script-src": [SELF]},
    ]
    mw.process_response(request, response)
    policies = response[HEADER].split(", ")
    assert len(policies) == 3
    # The main policy (default-src 'self' NONCE in settings) gets the nonce.
    assert f"'nonce-{nonce}'" in policies[0]
    # The first additional policy allows nonces, the second does not.
    assert f"'nonce-{nonce}'" in policies[1]
    assert "nonce-" not in policies[2]
    assert sorted(policies[2].split("; ")) == ["default-src 'self'", "script-src 'self'"]


def test_additional_policies_hash_and_empty_directive() -> None:
    # Hashes and empty directives are handled per policy.
    request = rf.get("/")
    response = HttpResponse()
    response._csp_additional = [
        {"script-src": ["'sha256-abc123'"]},
        {"sandbox": []},
    ]
    mw.process_response(request, response)
    policies = response[HEADER].split(", ")
    assert len(policies) == 3
    assert sorted(policies[1].split("; ")) == ["default-src 'self'", "script-src 'sha256-abc123'"]
    assert sorted(policies[2].split("; ")) == ["default-src 'self'", "sandbox"]


def test_additional_policies_report_only_separate() -> None:
    # Enforced and report-only additional policies are stored separately.
    request = rf.get("/")
    response = HttpResponse()
    response._csp_additional = [{"script-src": ["https://enforced.example.com"]}]
    response._csp_additional_ro = [{"script-src": ["https://report.example.com"]}]
    mw.process_response(request, response)
    assert "https://enforced.example.com" in response[HEADER]
    assert "https://report.example.com" not in response[HEADER]
    assert "https://report.example.com" in response[HEADER_REPORT_ONLY]
    assert "https://enforced.example.com" not in response[HEADER_REPORT_ONLY]


def test_additional_policies_not_affected_by_update_replace() -> None:
    # update/replace only apply to the main policy, never to additional ones.
    request = rf.get("/")
    response = HttpResponse()
    response._csp_update = {"script-src": ["https://update.example.com"]}
    response._csp_replace = {"img-src": ["https://replace.example.com"]}
    response._csp_additional = [{"script-src": [SELF], "img-src": [SELF]}]
    mw.process_response(request, response)
    policies = response[HEADER].split(", ")
    assert len(policies) == 2
    assert "script-src https://update.example.com" in policies[0]
    assert "img-src https://replace.example.com" in policies[0]
    assert sorted(policies[1].split("; ")) == [
        "default-src 'self'",
        "img-src 'self'",
        "script-src 'self'",
    ]


def test_additional_policies_only() -> None:
    # An additional policy is emitted even if the main policy is empty.
    request = rf.get("/")
    response = HttpResponse()
    response._csp_config = {}  # Empty config removes the main policy.
    response._csp_additional = [{"script-src": [SELF]}]
    mw.process_response(request, response)
    assert response[HEADER] == "default-src 'self'; script-src 'self'"
