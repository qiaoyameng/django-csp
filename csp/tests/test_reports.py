from __future__ import annotations

import json
import logging
import socket
from datetime import timedelta

import pytest
from django.test import Client
from django.test.utils import override_settings

from csp.contrib import reports
from csp.tests.report_callbacks import collect_callback, received

LEGACY_URL = "/csp-report/legacy"
REPORTING_URL = "/csp-report/reporting"
COLLECT_URL = "/csp-report/collect"

LEGACY_TYPE = "application/csp-report"
REPORTING_TYPE = "application/reports+json"


LEGACY_REPORT = {
    "document-uri": "http://example.com/page.html",
    "referrer": "http://referrer.example.com/",
    "violated-directive": "img-src 'self'",
    "effective-directive": "img-src",
    "original-policy": "default-src 'self'; img-src 'self';",
    "disposition": "report",
    "blocked-uri": "http://img.example.com/x.png",
    "line-number": 4,
    "column-number": 12,
    "source-file": "http://example.com/script.js",
    "status-code": 200,
    "script-sample": "",
    "x-deployment": {"region": ["us-east", 2], "build": 42},
}


def reporting_item(age: int = 5000, **body_overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "blockedURL": "http://img.example.com/x.png",
        "disposition": "enforce",
        "documentURL": "http://example.com/page.html",
        "effectiveDirective": "img-src",
        "originalPolicy": "default-src 'self';",
        "referrer": "",
        "sample": "",
        "statusCode": 200,
        "lineNumber": 4,
        "columnNumber": 12,
        "sourceFile": "http://example.com/script.js",
        "violatedDirective": "img-src 'self'",
    }
    body.update(body_overrides)
    return {
        "type": "csp-violation",
        "age": age,
        "url": "http://example.com/page.html",
        "userAgent": "TestAgent/1.0",
        "body": body,
    }


@pytest.fixture(autouse=True)
def _clear_received() -> None:
    received.clear()


client = Client()


def _post(path: str, payload: object, content_type: str) -> object:
    return client.post(path, data=json.dumps(payload), content_type=content_type)


def test_legacy_report_accepted_and_normalised() -> None:
    response = _post(COLLECT_URL, {"csp-report": LEGACY_REPORT}, LEGACY_TYPE)

    assert response.status_code == 202
    assert response.json() == {"status": "accepted", "accepted": 1, "rejected": 0}
    assert len(received) == 1
    violation = received[0]
    assert violation.source == "legacy"
    assert violation.document_uri == "http://example.com/page.html"
    assert violation.blocked_uri == "http://img.example.com/x.png"
    assert violation.effective_directive == "img-src"
    assert violation.disposition == "report"
    assert violation.violated_directive == "img-src 'self'"
    assert violation.line_number == 4
    assert violation.source_file == "http://example.com/script.js"
    assert violation.occurred_at is None
    assert violation.received_at is not None
    assert violation.body_extras == {"x-deployment": {"region": ["us-east", 2], "build": 42}}


def test_reporting_batch_accepted_and_normalised() -> None:
    response = _post(
        COLLECT_URL,
        [reporting_item(), reporting_item(age=0, disposition="report")],
        REPORTING_TYPE,
    )

    assert response.status_code == 202
    assert response.json() == {"status": "accepted", "accepted": 2, "rejected": 0}
    assert [v.source for v in received] == ["reporting", "reporting"]
    assert [v.disposition for v in received] == ["enforce", "report"]
    assert received[0].page_url == "http://example.com/page.html"
    assert received[0].user_agent == "TestAgent/1.0"
    delta = received[0].received_at - received[0].occurred_at
    assert timedelta(0) <= delta - timedelta(milliseconds=5000) < timedelta(seconds=1)


def test_effective_directive_falls_back_to_violated_directive_name() -> None:
    item = reporting_item()
    assert isinstance(item["body"], dict)
    del item["body"]["effectiveDirective"]

    response = _post(COLLECT_URL, [item], REPORTING_TYPE)

    assert response.status_code == 202
    assert received[0].effective_directive == "img-src"


def test_unknown_extension_fields_are_kept_but_bounded() -> None:
    item = reporting_item()
    assert isinstance(item["body"], dict)
    item["body"]["x-browser"] = {"flag": [True, None, 3.5]}
    item["x-experiment"] = "cohort-7"

    response = _post(COLLECT_URL, [item], REPORTING_TYPE)

    assert response.status_code == 202
    assert received[0].body_extras["x-browser"] == {"flag": [True, None, 3.5]}
    assert received[0].envelope_extras["x-experiment"] == "cohort-7"


@pytest.mark.parametrize(
    ("path", "content_type", "payload"),
    [
        (COLLECT_URL, LEGACY_TYPE, {"csp-report": {**LEGACY_REPORT, "blocked-uri": ""}}),
        (COLLECT_URL, REPORTING_TYPE, [reporting_item(blockedURL="")]),
    ],
)
def test_empty_blocked_uri_is_valid(path: str, content_type: str, payload: object) -> None:
    response = _post(path, payload, content_type)

    assert response.status_code == 202
    assert received[0].blocked_uri == ""


def test_overlong_extension_string_invalidates_report() -> None:
    item = reporting_item()
    assert isinstance(item["body"], dict)
    item["body"]["x-huge"] = "x" * 5000

    response = _post(COLLECT_URL, [item], REPORTING_TYPE)

    assert response.status_code == 202
    assert response.json()["accepted"] == 0
    assert response.json()["rejected"] == 1
    assert received == []


def test_uri_userinfo_fragment_and_case_are_normalised() -> None:
    payload = {
        "csp-report": {
            **LEGACY_REPORT,
            "document-uri": "https://user:secret@Example.COM/Page#frag",
            "blocked-uri": "http://img.example.com/x.png?token=abc#drop",
            "referrer": "https://Ref.example.com/",
        }
    }

    response = _post(COLLECT_URL, payload, LEGACY_TYPE)

    assert response.status_code == 202
    violation = received[0]
    assert violation.document_uri == "https://example.com/Page"
    assert violation.blocked_uri == "http://img.example.com/x.png?token=abc"
    assert violation.referrer == "https://ref.example.com/"


def test_overlong_url_is_rejected() -> None:
    long_uri = "http://example.com/" + "a" * 5000
    legacy_payload = {"csp-report": {**LEGACY_REPORT, "blocked-uri": long_uri}}

    response = _post(COLLECT_URL, legacy_payload, LEGACY_TYPE)
    assert response.status_code == 400
    assert received == []

    mixed_batch = [
        reporting_item(),
        reporting_item(blockedURL=long_uri),
    ]
    response = _post(COLLECT_URL, mixed_batch, REPORTING_TYPE)
    assert response.status_code == 202
    assert response.json() == {"status": "accepted", "accepted": 1, "rejected": 1}
    assert len(received) == 1
    assert received[0].blocked_uri == "http://img.example.com/x.png"


def test_mixed_good_and_bad_elements_keeps_good_ones() -> None:
    batch = [
        reporting_item(),
        {"type": "csp-violation", "age": 1},  # missing body
        {"type": "deprecation", "body": {"anticipatedRemoval": "x"}},
        "not-even-an-object",
        reporting_item(blockedURL="https://second.example.com/y.css"),
    ]

    response = _post(COLLECT_URL, batch, REPORTING_TYPE)

    assert response.status_code == 202
    assert response.json() == {"status": "accepted", "accepted": 2, "rejected": 3}
    assert [v.blocked_uri for v in received] == [
        "http://img.example.com/x.png",
        "https://second.example.com/y.css",
    ]


def test_missing_required_field_legacy_is_400() -> None:
    bad = {**LEGACY_REPORT}
    del bad["document-uri"]

    response = _post(COLLECT_URL, {"csp-report": bad}, LEGACY_TYPE)

    assert response.status_code == 400
    assert received == []


def test_wrong_field_type_legacy_is_400() -> None:
    response = _post(
        COLLECT_URL,
        {"csp-report": {**LEGACY_REPORT, "line-number": "4"}},
        LEGACY_TYPE,
    )

    assert response.status_code == 400
    assert received == []


def test_boolean_integer_field_is_400() -> None:
    response = _post(
        COLLECT_URL,
        {"csp-report": {**LEGACY_REPORT, "status-code": True}},
        LEGACY_TYPE,
    )

    assert response.status_code == 400


def test_control_characters_in_uri_are_rejected() -> None:
    response = _post(
        COLLECT_URL,
        [reporting_item(blockedURL="http://example.com/\nx.png")],
        REPORTING_TYPE,
    )

    assert response.status_code == 202
    assert response.json()["rejected"] == 1
    assert received == []


def test_content_length_over_limit_is_413() -> None:
    from django.test import RequestFactory

    request = RequestFactory().post(
        COLLECT_URL,
        data=b"[]",
        content_type=REPORTING_TYPE,
    )
    # RequestFactory derives Content-Length from the body; lie about it to
    # exercise the advertised-length check without sending a huge payload.
    request.META["CONTENT_LENGTH"] = str(reports.DEFAULT_MAX_BODY_BYTES + 1)

    response = reports.report_view(collect_callback)(request)

    assert response.status_code == 413


def test_actual_oversized_body_is_413() -> None:
    big = {"csp-report": {**LEGACY_REPORT, "original-policy": "x" * (64 * 1024)}}

    response = _post(COLLECT_URL, big, LEGACY_TYPE)

    assert response.status_code == 413
    assert received == []


def test_too_many_reports_is_413() -> None:
    batch = [reporting_item(age=1) for _ in range(reports.DEFAULT_MAX_REPORTS + 1)]

    response = _post(COLLECT_URL, batch, REPORTING_TYPE)

    assert response.status_code == 413
    assert received == []


def test_bad_json_is_400() -> None:
    response = client.post(COLLECT_URL, data=b"not json", content_type=LEGACY_TYPE)

    assert response.status_code == 400


def test_reporting_body_must_be_an_array() -> None:
    response = _post(COLLECT_URL, {"type": "csp-violation"}, REPORTING_TYPE)

    assert response.status_code == 400


def test_legacy_envelope_must_contain_csp_report() -> None:
    response = _post(COLLECT_URL, ["nope"], LEGACY_TYPE)

    assert response.status_code == 400


def test_unsupported_content_type_is_415() -> None:
    response = client.post(COLLECT_URL, data=b"{}", content_type="application/json")

    assert response.status_code == 415


def test_get_is_not_allowed() -> None:
    response = client.get(COLLECT_URL)

    assert response.status_code == 405


def test_post_does_not_require_csrf_token() -> None:
    response = _post(COLLECT_URL, {"csp-report": LEGACY_REPORT}, LEGACY_TYPE)

    assert response.status_code == 202


def test_uris_are_never_fetched(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("report URIs must never be fetched")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)

    payload = {
        "csp-report": {
            **LEGACY_REPORT,
            "document-uri": "http://192.0.2.10/admin",
            "blocked-uri": "http://198.51.100.7/track.gif",
        }
    }

    response = _post(COLLECT_URL, payload, LEGACY_TYPE)

    assert response.status_code == 202
    assert received[0].blocked_uri == "http://198.51.100.7/track.gif"


def test_acceptance_is_not_authentication_of_browser_origin() -> None:
    # Any client can post an arbitrary, well-formed report and get 202;
    # nothing here proves a real browser generated the event.
    fabricated = {"csp-report": {**LEGACY_REPORT, "document-uri": "http://victim.example/"}}

    response = _post(LEGACY_URL, fabricated, LEGACY_TYPE)

    assert response.status_code == 202


def test_default_callback_logs_redacted_summary(caplog: pytest.LogCaptureFixture) -> None:
    payload = {
        "csp-report": {
            **LEGACY_REPORT,
            "document-uri": "https://user:supersecret@example.com/page#frag",
            "original-policy": "secret-token-do-not-log",
            "x-secret": "secret-value-do-not-log",
        }
    }

    caplog.set_level(logging.INFO, logger="csp.reports")
    response = _post(LEGACY_URL, payload, LEGACY_TYPE)

    assert response.status_code == 202
    assert any("CSP violation" in line for line in caplog.messages)
    assert "supersecret" not in caplog.text
    assert "secret-token-do-not-log" not in caplog.text
    assert "secret-value-do-not-log" not in caplog.text


@override_settings(CSP_REPORT_CALLBACK="csp.tests.report_callbacks.collect_callback")
def test_callback_setting_dotted_path_is_used() -> None:
    response = _post(LEGACY_URL, {"csp-report": LEGACY_REPORT}, LEGACY_TYPE)

    assert response.status_code == 202
    assert len(received) == 1
