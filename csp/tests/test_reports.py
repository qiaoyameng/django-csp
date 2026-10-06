from __future__ import annotations

import json
from typing import TYPE_CHECKING

from django.test import Client
from django.test.utils import override_settings
from django.urls import path

import pytest

from csp.reports import CSP_REPORT_CONTENT_TYPE, REPORTING_API_CONTENT_TYPE, CSPViolation
from csp.views import report_receiver

if TYPE_CHECKING:
    from django.http import HttpRequest

client = Client()
received_reports: list[list[CSPViolation]] = []


def collect_reports(request: HttpRequest, reports: list[CSPViolation]) -> None:
    received_reports.append(reports)


def dotted_collect_reports(request: HttpRequest, reports: list[CSPViolation]) -> None:
    collect_reports(request, reports)


urlpatterns = []


@pytest.fixture(autouse=True)
def clear_received_reports():
    received_reports.clear()
    yield
    received_reports.clear()


def csp_body(**overrides):
    body = {
        "documentURL": "https://doc-user:doc-pass@example.com/page?token=abc",
        "blockedURL": "https://user:password@cdn.example.com/evil.js",
        "referrer": "https://example.com/referrer",
        "violatedDirective": "script-src 'self'",
        "effectiveDirective": "script-src-elem 'self'",
        "originalPolicy": "default-src 'self'",
        "disposition": "enforce",
        "sourceFile": "https://user:secret@cdn.example.com/evil.js",
        "sample": "alert(1)\nignored-control",
        "statusCode": 200,
        "lineNumber": 12,
        "columnNumber": 4,
    }
    body.update(overrides)
    return body


def legacy_payload(**overrides):
    payload = {"csp-report": csp_body()}
    payload.update(overrides)
    return payload


def reporting_payload(*bodies):
    return [
        {
            "age": 1500,
            "type": "csp-violation",
            "url": "https://example.com/page",
            "user_agent": "Test browser",
            "body": body,
        }
        for body in bodies
    ]


def post(payload, content_type, path="/csp-report/", **extra):
    return client.post(path, data=json.dumps(payload), content_type=content_type, **extra)


@override_settings(ROOT_URLCONF="csp.tests.test_reports", CSP_REPORTS={"callback": collect_reports})
def test_legacy_report_accepted_and_normalized():
    response = post(legacy_payload(custom="unknown"), CSP_REPORT_CONTENT_TYPE)

    assert response.status_code == 202
    assert response["X-CSP-Invalid-Reports"] == "0"
    assert len(received_reports[0]) == 1
    report = received_reports[0][0]
    assert report.format == "csp-report"
    assert report.disposition == "enforce"
    assert report.report_only is False
    assert report.effective_directive == "script-src-elem 'self'"
    assert report.document_uri == "https://redacted@example.com/page?token=abc"
    assert "doc-pass" not in report.document_uri
    assert report.blocked_uri == "https://redacted@cdn.example.com/evil.js"
    assert report.source_file == "https://redacted@cdn.example.com/evil.js"
    assert report.sample == "alert(1)ignored-control"
    assert "password" not in report.blocked_uri
    assert "secret" not in report.source_file
    assert report.extensions["envelope"] == {"custom": "unknown"}
    assert report.occurred_at is None
    assert report.received_at is not None


@override_settings(ROOT_URLCONF="csp.tests.test_reports", CSP_REPORTS={"callback": collect_reports})
def test_legacy_hyphenated_fields_and_special_blocked_uri():
    payload = {
        "csp-report": {
            "document-uri": "https://example.com/page",
            "blocked-uri": "inline",
            "referrer": "",
            "violated-directive": "style-src-attr",
            "original-policy": "style-src 'none'",
        }
    }

    response = post(payload, CSP_REPORT_CONTENT_TYPE)

    assert response.status_code == 202
    report = received_reports[0][0]
    assert report.effective_directive == "style-src-attr"
    assert report.violated_directive == "style-src-attr"
    assert report.blocked_uri == "inline"
    assert report.referrer == ""
    assert report.disposition is None
    assert report.report_only is None


@override_settings(ROOT_URLCONF="csp.tests.test_reports", CSP_REPORTS={"callback": collect_reports})
def test_effective_directive_fills_missing_violated_directive():
    payload = {
        "csp-report": {
            "document-uri": "https://example.com/page",
            "violated-directive": "",
            "effective-directive": "img-src",
            "original-policy": "img-src 'self'",
        }
    }

    response = post(payload, CSP_REPORT_CONTENT_TYPE)

    assert response.status_code == 202
    report = received_reports[0][0]
    assert report.effective_directive == "img-src"
    assert report.violated_directive == "img-src"


@override_settings(ROOT_URLCONF="csp.tests.test_reports", CSP_REPORTS={"callback": collect_reports})
def test_reporting_api_array_preserves_disposition_and_time():
    body = csp_body(disposition="report")

    response = post(reporting_payload(body), REPORTING_API_CONTENT_TYPE)

    assert response.status_code == 202
    report = received_reports[0][0]
    assert report.format == "reporting-api"
    assert report.disposition == "report"
    assert report.report_only is True
    assert report.type == "csp-violation"
    assert report.age == 1500
    assert (report.received_at - report.occurred_at).total_seconds() == 1.5


@override_settings(ROOT_URLCONF="csp.tests.test_reports", CSP_REPORTS={"callback": collect_reports})
def test_invalid_array_entries_are_skipped_but_valid_entries_are_delivered():
    payload = reporting_payload(csp_body(), {"type": "csp-violation", "body": {}})

    response = post(payload, REPORTING_API_CONTENT_TYPE)

    assert response.status_code == 202
    assert response["X-CSP-Invalid-Reports"] == "1"
    assert len(received_reports[0]) == 1


@override_settings(ROOT_URLCONF="csp.tests.test_reports", CSP_REPORTS={"callback": collect_reports})
def test_normalized_url_length_is_limited():
    long_url = "https://example.com/" + ("a" * 64)
    response = post(legacy_payload(blockedURL=long_url), CSP_REPORT_CONTENT_TYPE)
    assert response.status_code == 202

    response = post(legacy_payload(blockedURL=long_url), CSP_REPORT_CONTENT_TYPE, path="/short-csp-report/")
    assert response.status_code == 400


@override_settings(ROOT_URLCONF="csp.tests.test_reports", CSP_REPORTS={"callback": collect_reports})
def test_unknown_extensions_are_sanitized_and_limited():
    payload = reporting_payload(csp_body(extension={"nested": ["value", {"x": 1}]}))
    payload[0]["envelopeExtension"] = "kept"
    response = post(payload, REPORTING_API_CONTENT_TYPE)

    assert response.status_code == 202
    assert received_reports[0][0].extensions["body"]["extension"] == {"nested": ["value", {"x": 1}]}
    assert received_reports[0][0].extensions["envelope"]["envelopeExtension"] == "kept"


@override_settings(
    ROOT_URLCONF="csp.tests.test_reports",
    CSP_REPORTS={"callback": "csp.tests.test_reports.dotted_collect_reports"},
)
def test_dotted_path_callback_from_settings():
    response = post(legacy_payload(), CSP_REPORT_CONTENT_TYPE)

    assert response.status_code == 202
    assert len(received_reports[0]) == 1


@override_settings(ROOT_URLCONF="csp.tests.test_reports", CSP_REPORTS={"callback": collect_reports})
def test_required_field_types_are_checked():
    bad_body = csp_body(documentURL=123, originalPolicy=True, lineNumber="1", disposition=True)

    response = post(reporting_payload(bad_body), REPORTING_API_CONTENT_TYPE)

    assert response.status_code == 400
    assert received_reports == []


@override_settings(ROOT_URLCONF="csp.tests.test_reports", CSP_REPORTS={"callback": collect_reports})
def test_non_integer_numeric_field_marks_only_that_report_invalid():
    payload = reporting_payload(csp_body(), csp_body(statusCode=200.5))

    response = post(payload, REPORTING_API_CONTENT_TYPE)

    assert response.status_code == 202
    assert response["X-CSP-Invalid-Reports"] == "1"
    assert len(received_reports[0]) == 1


@override_settings(ROOT_URLCONF="csp.tests.test_reports")
def test_default_callback_does_not_log_raw_body(caplog):
    caplog.set_level("INFO")
    response = post(legacy_payload(secret_extension="do-not-log-me"), CSP_REPORT_CONTENT_TYPE)

    assert response.status_code == 202
    assert "do-not-log-me" not in caplog.text
    assert received_reports == []


@override_settings(ROOT_URLCONF="csp.tests.test_reports", CSP_REPORTS={"callback": collect_reports})
def test_bad_json_and_all_invalid_reports_return_400():
    response = client.post(
        "/csp-report/",
        data=b'{"csp-report":}',
        content_type=CSP_REPORT_CONTENT_TYPE,
    )
    assert response.status_code == 400

    response = post(reporting_payload({}), REPORTING_API_CONTENT_TYPE)
    assert response.status_code == 400


@override_settings(ROOT_URLCONF="csp.tests.test_reports", CSP_REPORTS={"callback": collect_reports})
def test_body_size_and_array_count_are_limited():
    response = client.post(
        "/tiny-csp-report/",
        data=json.dumps(legacy_payload()),
        content_type=CSP_REPORT_CONTENT_TYPE,
    )
    assert response.status_code == 413

    response = post(
        reporting_payload(csp_body(), csp_body()),
        REPORTING_API_CONTENT_TYPE,
        path="/one-csp-report/",
    )
    assert response.status_code == 413


@override_settings(ROOT_URLCONF="csp.tests.test_reports", CSP_REPORTS={"callback": collect_reports})
def test_method_and_content_type_are_restricted():
    assert client.get("/csp-report/").status_code == 405
    assert post(legacy_payload(), "text/plain").status_code == 415


urlpatterns = [
    path("csp-report/", report_receiver()),
    path("short-csp-report/", report_receiver(max_string_length=32)),
    path("tiny-csp-report/", report_receiver(max_body_size=20)),
    path("one-csp-report/", report_receiver(max_reports=1)),
]
