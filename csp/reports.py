from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from urllib.parse import quote, urlsplit, urlunsplit

CSP_REPORT_CONTENT_TYPE = "application/csp-report"
REPORTING_API_CONTENT_TYPE = "application/reports+json"


class ReportError(ValueError):
    pass


class ReportPayloadError(ReportError):
    pass


class ReportTooLargeError(ReportPayloadError):
    pass


class ReportValidationError(ReportError):
    pass


@dataclass(frozen=True)
class CSPViolation:
    format: Literal["csp-report", "reporting-api"]
    envelope_type: Literal["csp-report", "reporting-api"]
    disposition: Literal["enforce", "report"] | None
    report_only: bool | None
    document_uri: str
    blocked_uri: str
    referrer: str | None
    violated_directive: str
    effective_directive: str
    original_policy: str
    source_file: str | None
    sample: str | None
    status_code: int | None
    line_number: int | None
    column_number: int | None
    occurred_at: datetime | None
    received_at: datetime
    type: str | None = None
    url: str | None = None
    user_agent: str | None = None
    age: int | None = None
    extensions: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReportBatch:
    reports: list[CSPViolation]
    invalid_reports: int


def _invalid_constant(constant: str) -> None:
    raise ReportPayloadError(f"Invalid JSON constant: {constant}")


def _clean_string(value: str) -> str:
    unsafe_chars = ("\u2028", "\u2029")
    return "".join(
        character
        for character in value
        if ord(character) >= 32
        and ord(character) != 127
        and not 128 <= ord(character) <= 159
        and character not in unsafe_chars
    )


def _string(
    value: Any,
    field_name: str,
    max_length: int,
    *,
    required: bool = True,
    allow_empty: bool = False,
) -> str | None:
    if value is None:
        if required:
            raise ReportValidationError(f"Missing required field: {field_name}")
        return None
    if not isinstance(value, str):
        raise ReportValidationError(f"Field must be a string: {field_name}")
    value = _clean_string(value)
    if len(value) > max_length:
        raise ReportValidationError(f"Field is too long: {field_name}")
    if required and not allow_empty and not value:
        raise ReportValidationError(f"Field must not be empty: {field_name}")
    return value


def _integer(value: Any, field_name: str, *, maximum: int | None = None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReportValidationError(f"Field must be an integer: {field_name}")
    if value < 0 or (maximum is not None and value > maximum):
        raise ReportValidationError(f"Field is out of range: {field_name}")
    return value


def normalize_url(value: Any, field_name: str, max_length: int, *, required: bool = True) -> str | None:
    if value is None:
        if required:
            raise ReportValidationError(f"Missing required field: {field_name}")
        return None
    if not required and value == "":
        return ""
    value = _string(value, field_name, max_length, required=required)
    if value is None:
        return None

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ReportValidationError(f"Invalid URL: {field_name}") from error

    if hostname is not None:
        host = f"[{hostname}]" if ":" in hostname else hostname
        netloc = host
        if port is not None:
            netloc = f"{netloc}:{port}"
        if parsed.username is not None or parsed.password is not None:
            netloc = f"redacted@{netloc}"
    else:
        netloc = _clean_string(parsed.netloc)

    path_safe = "/:@!$&'()*+,;=-._~%"
    query_safe = f"{path_safe}?"
    normalized = urlunsplit(
        (
            parsed.scheme,
            netloc,
            quote(_clean_string(parsed.path), safe=path_safe),
            quote(_clean_string(parsed.query), safe=query_safe),
            "",
        )
    )
    if len(normalized) > max_length:
        raise ReportValidationError(f"Field is too long: {field_name}")
    return normalized


def _sanitize_extensions(value: Any, max_string_length: int, max_items: int, *, depth: int = 4) -> Any:
    if depth < 0:
        raise ReportValidationError("Extension data is nested too deeply")
    if isinstance(value, str):
        value = _clean_string(value)
        if len(value) > max_string_length:
            raise ReportValidationError("Extension field is too long")
        return value
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value
    if isinstance(value, list):
        if len(value) > max_items:
            raise ReportValidationError("Extension array is too large")
        return [_sanitize_extensions(item, max_string_length, max_items, depth=depth - 1) for item in value]
    if isinstance(value, dict):
        if len(value) > max_items:
            raise ReportValidationError("Extension object is too large")
        result = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReportValidationError("Extension field name must be a string")
            key = _clean_string(key)
            if len(key) > max_string_length:
                raise ReportValidationError("Extension field name is too long")
            result[key] = _sanitize_extensions(item, max_string_length, max_items, depth=depth - 1)
        return result
    raise ReportValidationError("Extension data contains an unsupported type")


def _value(data: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in data:
            return data[name]
    return None


def _extensions(data: dict[str, Any], known: set[str], max_string_length: int, max_items: int) -> dict[str, Any]:
    extra = {key: value for key, value in data.items() if key not in known}
    sanitized = _sanitize_extensions(extra, max_string_length, max_items)
    return sanitized if isinstance(sanitized, dict) else {}


def _csp_body(body: dict[str, Any], max_string_length: int, max_items: int) -> dict[str, Any]:
    known = {
        "documentURL",
        "document-uri",
        "blockedURL",
        "blocked-uri",
        "referrer",
        "violatedDirective",
        "violated-directive",
        "effectiveDirective",
        "effective-directive",
        "originalPolicy",
        "original-policy",
        "disposition",
        "sourceFile",
        "source-file",
        "statusCode",
        "status-code",
        "lineNumber",
        "line-number",
        "columnNumber",
        "column-number",
        "sample",
        "script-sample",
    }
    disposition = _value(body, "disposition")
    if disposition not in (None, "enforce", "report"):
        raise ReportValidationError("Field must be 'enforce' or 'report': disposition")

    violated_directive = _string(
        _value(body, "violatedDirective", "violated-directive"),
        "violated-directive",
        max_string_length,
        required=False,
    )
    effective_directive = _string(
        _value(body, "effectiveDirective", "effective-directive"),
        "effective-directive",
        max_string_length,
        required=False,
    )
    if effective_directive is None:
        effective_directive = violated_directive.split()[0] if violated_directive else None
    if not violated_directive:
        violated_directive = effective_directive
    if not effective_directive:
        raise ReportValidationError("Missing required field: effective-directive")

    return {
        "disposition": disposition,
        "report_only": None if disposition is None else disposition == "report",
        "document_uri": normalize_url(_value(body, "documentURL", "document-uri"), "document-uri", max_string_length),
        "blocked_uri": normalize_url(
            _value(body, "blockedURL", "blocked-uri"),
            "blocked-uri",
            max_string_length,
            required=False,
        )
        or "",
        "referrer": normalize_url(_value(body, "referrer"), "referrer", max_string_length, required=False),
        "violated_directive": violated_directive,
        "effective_directive": effective_directive,
        "original_policy": _string(_value(body, "originalPolicy", "original-policy"), "original-policy", max_string_length),
        "source_file": normalize_url(
            _value(body, "sourceFile", "source-file"),
            "source-file",
            max_string_length,
            required=False,
        ),
        "sample": _string(_value(body, "sample", "script-sample"), "script-sample", max_string_length, required=False),
        "status_code": _integer(_value(body, "statusCode", "status-code"), "status-code", maximum=599),
        "line_number": _integer(_value(body, "lineNumber", "line-number"), "line-number"),
        "column_number": _integer(_value(body, "columnNumber", "column-number"), "column-number"),
        "extensions": _extensions(body, known, max_string_length, max_items),
    }


def _legacy_report(data: dict[str, Any], max_string_length: int, max_items: int, received_at: datetime) -> CSPViolation:
    body = _value(data, "csp-report")
    if not isinstance(body, dict):
        raise ReportValidationError("Missing required field: csp-report")
    report = _csp_body(body, max_string_length, max_items)
    report["extensions"] = {
        "body": report["extensions"],
        "envelope": _extensions(data, {"csp-report"}, max_string_length, max_items),
    }
    return CSPViolation(
        format="csp-report",
        envelope_type="csp-report",
        occurred_at=None,
        received_at=received_at,
        **report,
    )


def _reporting_api_report(
    data: dict[str, Any],
    max_string_length: int,
    max_items: int,
    received_at: datetime,
) -> CSPViolation:
    known = {"body", "type", "url", "user_agent", "userAgent"}
    if _string(_value(data, "type"), "type", max_string_length) != "csp-violation":
        raise ReportValidationError("Field must be 'csp-violation': type")
    body = _value(data, "body")
    if not isinstance(body, dict):
        raise ReportValidationError("Missing required field: body")

    url = normalize_url(_value(data, "url"), "url", max_string_length)
    user_agent = _string(_value(data, "user_agent", "userAgent"), "user_agent", max_string_length)
    age = _integer(_value(data, "age"), "age")
    report = _csp_body(body, max_string_length, max_items)
    report["extensions"] = {
        "body": report["extensions"],
        "envelope": _extensions(data, known, max_string_length, max_items),
    }
    occurred_at = received_at - timedelta(milliseconds=age) if age is not None else None
    return CSPViolation(
        format="reporting-api",
        envelope_type="reporting-api",
        occurred_at=occurred_at,
        received_at=received_at,
        type="csp-violation",
        url=url,
        user_agent=user_agent,
        age=age,
        **report,
    )


def _parse_entry(
    entry: Any,
    content_type: str,
    max_string_length: int,
    max_items: int,
    received_at: datetime,
) -> CSPViolation:
    if not isinstance(entry, dict):
        raise ReportValidationError("Report must be an object")
    if content_type == CSP_REPORT_CONTENT_TYPE:
        return _legacy_report(entry, max_string_length, max_items, received_at)
    return _reporting_api_report(entry, max_string_length, max_items, received_at)


def parse_reports(body: bytes, content_type: str, max_string_length: int, max_reports: int) -> ReportBatch:
    if content_type not in (CSP_REPORT_CONTENT_TYPE, REPORTING_API_CONTENT_TYPE):
        raise ReportPayloadError("Unsupported content type")
    try:
        payload = json.loads(body.decode("utf-8"), parse_constant=_invalid_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise ReportPayloadError("Invalid JSON body") from error

    if content_type == CSP_REPORT_CONTENT_TYPE:
        if not isinstance(payload, dict):
            raise ReportPayloadError("CSP report body must be an object")
        entries = [payload]
    else:
        if not isinstance(payload, list):
            raise ReportPayloadError("Reporting API body must be an array")
        if len(payload) > max_reports:
            raise ReportTooLargeError("Too many reports")
        entries = payload

    reports: list[CSPViolation] = []
    invalid_reports = 0
    received_at = datetime.now(timezone.utc)
    for entry in entries:
        try:
            reports.append(_parse_entry(entry, content_type, max_string_length, max_reports, received_at))
        except ReportValidationError:
            invalid_reports += 1

    if not reports:
        raise ReportValidationError("No valid reports")
    return ReportBatch(reports=reports, invalid_reports=invalid_reports)
