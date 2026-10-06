from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Callable, cast

from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseNotAllowed
from django.utils.module_loading import import_string
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt

from csp.reports import (
    CSP_REPORT_CONTENT_TYPE,
    REPORTING_API_CONTENT_TYPE,
    CSPViolation,
    ReportBatch,
    ReportPayloadError,
    ReportTooLargeError,
    ReportValidationError,
    parse_reports,
)

DEFAULT_MAX_BODY_SIZE = 64 * 1024
DEFAULT_MAX_REPORTS = 100
DEFAULT_MAX_STRING_LENGTH = 2048

ReportCallback = Callable[[HttpRequest, list[CSPViolation]], None]


def default_report_callback(request: HttpRequest, reports: list[CSPViolation]) -> None:
    return None


@dataclass(frozen=True)
class ReportOptions:
    max_body_size: int = DEFAULT_MAX_BODY_SIZE
    max_reports: int = DEFAULT_MAX_REPORTS
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH
    callback: ReportCallback = default_report_callback


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _resolve_callback(value: Any) -> ReportCallback:
    if isinstance(value, str):
        value = import_string(value)
    if not callable(value):
        raise TypeError("callback must be callable")
    return cast(ReportCallback, value)


def report_receiver(
    *,
    max_body_size: int | None = None,
    max_reports: int | None = None,
    max_string_length: int | None = None,
    callback: ReportCallback | None = None,
) -> Callable[[HttpRequest], HttpResponse]:
    overrides = {
        "max_body_size": max_body_size,
        "max_reports": max_reports,
        "max_string_length": max_string_length,
        "callback": callback,
    }

    @csrf_exempt
    @never_cache
    def receive_reports(request: HttpRequest) -> HttpResponse:
        if request.method != "POST":
            return HttpResponseNotAllowed(("POST",))

        content_type = request.content_type or ""
        if content_type not in (CSP_REPORT_CONTENT_TYPE, REPORTING_API_CONTENT_TYPE):
            return HttpResponse(status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE)

        configured = getattr(settings, "CSP_REPORTS", {}) or {}
        if not isinstance(configured, dict):
            return HttpResponse(status=HTTPStatus.INTERNAL_SERVER_ERROR)
        options_kwargs = {}
        for name, override in overrides.items():
            value = override
            if value is None:
                value = configured.get(name)
            if name == "callback":
                if value is None:
                    value = default_report_callback
                else:
                    try:
                        value = _resolve_callback(value)
                    except (ImportError, TypeError):
                        return HttpResponse(status=HTTPStatus.INTERNAL_SERVER_ERROR)
            else:
                if value is None:
                    value = getattr(ReportOptions, name)
                try:
                    value = _positive_int(value, name)
                except (TypeError, ValueError):
                    return HttpResponse(status=HTTPStatus.INTERNAL_SERVER_ERROR)
            options_kwargs[name] = value

        options = ReportOptions(**options_kwargs)
        try:
            content_length = int(request.META.get("CONTENT_LENGTH") or 0)
        except (TypeError, ValueError):
            return HttpResponse(status=HTTPStatus.BAD_REQUEST)
        if content_length < 0:
            return HttpResponse(status=HTTPStatus.BAD_REQUEST)
        if content_length > options.max_body_size:
            return HttpResponse(status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)

        body = request.read(options.max_body_size + 1)
        if len(body) > options.max_body_size:
            return HttpResponse(status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)

        try:
            batch: ReportBatch = parse_reports(
                body,
                content_type=content_type,
                max_string_length=options.max_string_length,
                max_reports=options.max_reports,
            )
        except ReportTooLargeError:
            return HttpResponse(status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        except ReportPayloadError:
            return HttpResponse(status=HTTPStatus.BAD_REQUEST)
        except ReportValidationError:
            return HttpResponse(status=HTTPStatus.BAD_REQUEST)

        options.callback(request, batch.reports)
        response = HttpResponse(status=HTTPStatus.ACCEPTED)
        response["X-CSP-Invalid-Reports"] = str(batch.invalid_reports)
        return response

    return receive_reports
