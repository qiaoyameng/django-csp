"""Optional Django view for receiving Content-Security-Policy violation reports.

Browsers deliver violation reports in one of two shapes:

* ``application/csp-report`` -- the legacy body, a JSON object::

      {"csp-report": {"document-uri": ..., ...}}

* ``application/reports+json`` -- the Reporting API body, always a JSON
  *array* of report envelopes::

      [{"type": "csp-violation", "age": 42, "body": {...}}, ...]

The view validates and normalises both shapes, then hands each accepted event
to an application callback.  It never fetches any URI contained in a report;
URIs are parsed purely for normalisation and redaction.

Accepting a report (HTTP 202) only means the JSON payload was syntactically
valid; it is **not** proof that the report came from a real browser or that
the event actually happened.  The endpoint is unauthenticated and anyone who
can reach it can post fabricated reports.

Partial-failure policy for Reporting API batches
------------------------------------------------
Each array element is validated independently.  Accepted elements are passed
to the callback; elements that are not valid ``csp-violation`` reports are
skipped (counted in the response).  The batch as a whole is rejected with a
4xx response when it is not a JSON array, exceeds ``max_reports``, exceeds the
request-byte limit, is not JSON, or uses an unsupported content type.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

logger = logging.getLogger("csp.reports")


class ReportValidationError(ValueError):
    """A report (or one batch element) failed validation."""


# Default limits.  Override per view via ``report_view()`` or globally via the
# CSP_REPORT_* settings.
DEFAULT_MAX_BODY_BYTES = 64 * 1024
DEFAULT_MAX_REPORTS = 100
DEFAULT_MAX_STRING_LENGTH = 1024
# How deeply unknown extension values may nest.
MAX_EXTRAS_DEPTH = 5

ENFORCE = "enforce"
REPORT_ONLY = "report"
VALID_DISPOSITIONS = frozenset({ENFORCE, REPORT_ONLY})

LEGACY_MEDIA_TYPE = "application/csp-report"
REPORTING_MEDIA_TYPE = "application/reports+json"


@dataclass(frozen=True)
class CSPViolation:
    """One validated CSP violation event, handed to the application callback.

    Time fields are kept distinct:

    * ``received_at`` -- when this server received the request (always set).
    * ``occurred_at`` -- when the browser says the violation happened.  It is
      computed as ``received_at - age`` for Reporting API reports, and is
      ``None`` for legacy ``application/csp-report`` reports, which carry no
      age information.

    ``disposition`` is preserved separately from ``effective_directive``:
    ``"enforce"`` means the policy was enforced, ``"report"`` means the page
    was served under a report-only policy.
    """

    document_uri: str
    blocked_uri: str
    effective_directive: str
    disposition: str
    source: str
    received_at: datetime
    occurred_at: datetime | None
    violated_directive: str | None = None
    original_policy: str | None = None
    referrer: str | None = None
    line_number: int | None = None
    column_number: int | None = None
    source_file: str | None = None
    status_code: int | None = None
    sample: str | None = None
    page_url: str | None = None
    user_agent: str | None = None
    # Unknown extension fields, length-capped and never used for decisions.
    body_extras: dict[str, Any] = field(default_factory=dict)
    envelope_extras: dict[str, Any] = field(default_factory=dict)


ReportCallback = Callable[[HttpRequest, CSPViolation], None]


def _checked_unknown(value: Any, max_string_length: int, depth: int = 0) -> Any:
    """Recursively validate an unknown extension value.

    Strings are length-capped (an over-long extension string invalidates the
    report), dicts/lists are followed to a bounded depth, and every other
    scalar type is kept as-is.  Keys must be short strings.
    """
    if depth > MAX_EXTRAS_DEPTH:
        raise ReportValidationError("extension value nested too deeply")
    if isinstance(value, str):
        if len(value) > max_string_length:
            raise ReportValidationError("extension string too long")
        return value
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > max_string_length:
                raise ReportValidationError("extension key has invalid type or is too long")
            result[key] = _checked_unknown(item, max_string_length, depth + 1)
        return result
    if isinstance(value, list):
        return [_checked_unknown(item, max_string_length, depth + 1) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise ReportValidationError("extension value has unsupported type")


def _required_string(obj: dict[str, Any], key: str, max_string_length: int) -> str:
    value = obj.get(key)
    if not isinstance(value, str):
        raise ReportValidationError(f"field {key!r} must be a string")
    if not value:
        raise ReportValidationError(f"field {key!r} must not be empty")
    if len(value) > max_string_length:
        raise ReportValidationError(f"field {key!r} exceeds maximum length")
    return value


def _required_string_maybe_empty(obj: dict[str, Any], key: str, max_string_length: int) -> str:
    # Browsers send an empty blocked-uri for inline violations.
    value = obj.get(key)
    if not isinstance(value, str):
        raise ReportValidationError(f"field {key!r} must be a string")
    if len(value) > max_string_length:
        raise ReportValidationError(f"field {key!r} exceeds maximum length")
    return value


def _optional_string(obj: dict[str, Any], key: str, max_string_length: int) -> str | None:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ReportValidationError(f"field {key!r} must be a string")
    if len(value) > max_string_length:
        raise ReportValidationError(f"field {key!r} exceeds maximum length")
    return value


def _optional_nonneg_int(obj: dict[str, Any], key: str) -> int | None:
    value = obj.get(key)
    if value is None:
        return None
    # bool is a subclass of int; reject it explicitly.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReportValidationError(f"field {key!r} must be a non-negative integer")
    return value


def sanitize_uri(raw: str, max_string_length: int) -> str:
    """Normalise and redact a URI contained in a report.

    The URI is *only* parsed -- no network request is ever made.  Redaction:

    * userinfo (``user:password@``) is dropped;
    * fragments are dropped (they never reach the server anyway);
    * scheme and host are lower-cased;
    * ASCII control characters are rejected (log/response injection guard).

    Relative URIs (e.g. the empty ``blocked-uri`` some browsers send) are
    preserved as-is after the control-character check.
    """
    if len(raw) > max_string_length:
        raise ReportValidationError("uri exceeds maximum length")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise ReportValidationError("uri contains control characters")

    parts = urlsplit(raw)
    if not parts.scheme:
        # Relative/opaque reference: nothing safe to rewrite, keep it verbatim.
        return raw

    host = ""
    if parts.hostname is not None:
        host = parts.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        if parts.port is not None:
            host = f"{host}:{parts.port}"

    # Rebuilding from (scheme, host, path, query, fragment) drops userinfo and
    # fragments automatically.
    return urlunsplit((parts.scheme.lower(), host, parts.path, parts.query, ""))


def _directive_name(violated_directive: str) -> str:
    """Extract the effective directive name from a ``directive-name value``
    string such as ``script-src 'self'``."""
    return violated_directive.split(None, 1)[0]


def _disposition(value: Any) -> str:
    if value not in VALID_DISPOSITIONS:
        raise ReportValidationError("field 'disposition' must be 'enforce' or 'report'")
    return value


def _extras(
    obj: dict[str, Any],
    known: frozenset[str],
    max_string_length: int,
) -> dict[str, Any]:
    return {
        key: _checked_unknown(item, max_string_length)
        for key, item in obj.items()
        if key not in known
    }


_LEGACY_KNOWN = frozenset(
    {
        "document-uri",
        "referrer",
        "violated-directive",
        "effective-directive",
        "original-policy",
        "disposition",
        "blocked-uri",
        "line-number",
        "column-number",
        "source-file",
        "status-code",
        "script-sample",
    }
)


def _normalise_legacy_report(
    report: Any,
    received_at: datetime,
    max_string_length: int,
) -> CSPViolation:
    """Normalise a legacy ``application/csp-report`` body."""
    if not isinstance(report, dict):
        raise ReportValidationError("'csp-report' must be a JSON object")

    document_uri = sanitize_uri(_required_string(report, "document-uri", max_string_length), max_string_length)
    blocked_uri = sanitize_uri(_required_string_maybe_empty(report, "blocked-uri", max_string_length), max_string_length)
    disposition = _disposition(report.get("disposition"))
    violated = _required_string(report, "violated-directive", max_string_length)

    effective = _optional_string(report, "effective-directive", max_string_length)
    if not effective:
        effective = _directive_name(violated)

    referrer = _optional_string(report, "referrer", max_string_length)
    if referrer is not None:
        referrer = sanitize_uri(referrer, max_string_length)
    source_file = _optional_string(report, "source-file", max_string_length)
    if source_file is not None:
        source_file = sanitize_uri(source_file, max_string_length)

    return CSPViolation(
        document_uri=document_uri,
        blocked_uri=blocked_uri,
        effective_directive=effective,
        disposition=disposition,
        source="legacy",
        received_at=received_at,
        # The legacy format carries no age, so the actual event time is
        # unknown and must not be confused with the server receive time.
        occurred_at=None,
        violated_directive=violated,
        original_policy=_optional_string(report, "original-policy", max_string_length),
        referrer=referrer,
        line_number=_optional_nonneg_int(report, "line-number"),
        column_number=_optional_nonneg_int(report, "column-number"),
        source_file=source_file,
        status_code=_optional_nonneg_int(report, "status-code"),
        sample=_optional_string(report, "script-sample", max_string_length),
        body_extras=_extras(report, _LEGACY_KNOWN, max_string_length),
    )


_ENVELOPE_KNOWN = frozenset({"type", "age", "url", "userAgent", "body"})
_BODY_KNOWN = frozenset(
    {
        "blockedURL",
        "blockedURLSample",
        "disposition",
        "documentURL",
        "effectiveDirective",
        "lineNumber",
        "columnNumber",
        "originalPolicy",
        "referrer",
        "sample",
        "sourceFile",
        "statusCode",
        "violatedDirective",
    }
)


def _normalise_reporting_item(
    item: Any,
    received_at: datetime,
    max_string_length: int,
) -> CSPViolation:
    """Normalise one element of a Reporting API ``reports`` array."""
    if not isinstance(item, dict):
        raise ReportValidationError("report element must be a JSON object")

    report_type = item.get("type")
    if report_type != "csp-violation":
        raise ReportValidationError(f"unsupported report type {report_type!r}")
    body = item.get("body")
    if not isinstance(body, dict):
        raise ReportValidationError("field 'body' must be a JSON object")

    document_uri = sanitize_uri(_required_string(body, "documentURL", max_string_length), max_string_length)
    blocked_uri = sanitize_uri(_required_string_maybe_empty(body, "blockedURL", max_string_length), max_string_length)
    disposition = _disposition(body.get("disposition"))
    violated = _required_string(body, "violatedDirective", max_string_length)

    effective = _optional_string(body, "effectiveDirective", max_string_length)
    if not effective:
        effective = _directive_name(violated)

    referrer = _optional_string(body, "referrer", max_string_length)
    if referrer is not None:
        referrer = sanitize_uri(referrer, max_string_length)
    source_file = _optional_string(body, "sourceFile", max_string_length)
    if source_file is not None:
        source_file = sanitize_uri(source_file, max_string_length)

    age = _optional_nonneg_int(item, "age")
    occurred_at = None
    if age is not None:
        occurred_at = received_at - timedelta(milliseconds=age)

    page_url = _optional_string(item, "url", max_string_length)
    if page_url is not None:
        page_url = sanitize_uri(page_url, max_string_length)

    return CSPViolation(
        document_uri=document_uri,
        blocked_uri=blocked_uri,
        effective_directive=effective,
        disposition=disposition,
        source="reporting",
        received_at=received_at,
        occurred_at=occurred_at,
        violated_directive=violated,
        original_policy=_optional_string(body, "originalPolicy", max_string_length),
        referrer=referrer,
        line_number=_optional_nonneg_int(body, "lineNumber"),
        column_number=_optional_nonneg_int(body, "columnNumber"),
        source_file=source_file,
        status_code=_optional_nonneg_int(body, "statusCode"),
        sample=_optional_string(body, "sample", max_string_length),
        page_url=page_url,
        user_agent=_optional_string(item, "userAgent", max_string_length),
        body_extras=_extras(body, _BODY_KNOWN, max_string_length),
        envelope_extras=_extras(item, _ENVELOPE_KNOWN, max_string_length),
    )


def default_callback(request: HttpRequest, violation: CSPViolation) -> None:
    """Log a short, redacted one-line summary.

    Deliberately does **not** log the full raw body or arbitrary extension
    fields: reports are attacker-influenceable and may contain sensitive
    fragments or very large strings.
    """
    occurred = violation.occurred_at.isoformat() if violation.occurred_at else "unknown"
    logger.info(
        "CSP violation (%s, %s) effective-directive=%s blocked-uri=%s document-uri=%s occurred-at=%s",
        violation.source,
        violation.disposition,
        violation.effective_directive,
        violation.blocked_uri,
        violation.document_uri,
        occurred,
    )


def report_view(
    callback: ReportCallback | None = None,
    *,
    max_body_bytes: int | None = None,
    max_reports: int | None = None,
    max_string_length: int | None = None,
) -> Callable[[HttpRequest], HttpResponse]:
    """Build a CSP violation-report view.

    ``callback`` is called once per accepted event as
    ``callback(request, violation)``.  When omitted, the dotted path in
    ``settings.CSP_REPORT_CALLBACK`` is imported lazily per request, falling
    back to :func:`default_callback`.
    """
    configured_callback = callback

    def setting(name: str, default: int) -> int:
        return getattr(settings, name, default)

    def resolve_callback() -> ReportCallback:
        if configured_callback is not None:
            return configured_callback
        path = getattr(settings, "CSP_REPORT_CALLBACK", None)
        if path is None:
            return default_callback
        from django.utils.module_loading import import_string

        resolved = import_string(path)
        if not callable(resolved):
            raise TypeError(f"CSP_REPORT_CALLBACK {path!r} is not callable")
        return resolved

    def view(request: HttpRequest) -> HttpResponse:
        body_limit = max_body_bytes if max_body_bytes is not None else setting("CSP_REPORT_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)
        reports_limit = max_reports if max_reports is not None else setting("CSP_REPORT_MAX_REPORTS", DEFAULT_MAX_REPORTS)
        string_limit = (
            max_string_length if max_string_length is not None else setting("CSP_REPORT_MAX_STRING_LENGTH", DEFAULT_MAX_STRING_LENGTH)
        )
        if body_limit <= 0 or reports_limit <= 0 or string_limit <= 0:
            raise ValueError("report limits must be positive integers")

        advertised = request.META.get("CONTENT_LENGTH")
        if advertised is not None:
            try:
                if int(advertised) > body_limit:
                    return _error(413, "request body exceeds maximum size")
            except ValueError:
                return _error(400, "invalid Content-Length header")

        body = request.body
        if len(body) > body_limit:
            return _error(413, "request body exceeds maximum size")

        content_type = request.content_type or ""

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _error(400, "request body is not valid UTF-8 JSON")

        received_at = datetime.now(tz=timezone.utc)
        accepted_callback = resolve_callback()

        if content_type == LEGACY_MEDIA_TYPE:
            if not isinstance(payload, dict) or "csp-report" not in payload:
                return _error(400, "legacy report must be an object containing 'csp-report'")
            try:
                violation = _normalise_legacy_report(payload["csp-report"], received_at, string_limit)
            except ReportValidationError as exc:
                return _error(400, str(exc))
            accepted_callback(request, violation)
            return JsonResponse({"status": "accepted", "accepted": 1, "rejected": 0}, status=202)

        if content_type == REPORTING_MEDIA_TYPE:
            if not isinstance(payload, list):
                return _error(400, "Reporting API body must be a JSON array")
            if len(payload) > reports_limit:
                return _error(413, "report batch exceeds maximum number of reports")

            violations: list[CSPViolation] = []
            rejected = 0
            for item in payload:
                try:
                    violations.append(_normalise_reporting_item(item, received_at, string_limit))
                except ReportValidationError as exc:
                    rejected += 1
                    logger.debug("rejected CSP report element: %s", exc)

            for violation in violations:
                accepted_callback(request, violation)

            return JsonResponse(
                {"status": "accepted", "accepted": len(violations), "rejected": rejected},
                status=202,
            )

        return _error(415, f"unsupported content type {content_type!r}")

    return csrf_exempt(require_POST(view))


def _error(status_code: int, message: str) -> JsonResponse:
    return JsonResponse({"status": "error", "detail": message}, status=status_code)


# Ready-to-use view for simple URLconf inclusion.
csp_report_view = report_view()
