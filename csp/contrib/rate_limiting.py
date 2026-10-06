from __future__ import annotations

import random
from dataclasses import replace
from typing import TYPE_CHECKING

from django.conf import settings

from csp.middleware import CSPMiddleware, PolicyParts

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase


class RateLimitedCSPMiddleware(CSPMiddleware):
    """A CSP middleware that rate-limits the number of violation reports sent
    to report-uri by excluding it from some requests."""

    def get_policy_parts(self, request: HttpRequest, response: HttpResponseBase, report_only: bool = False) -> PolicyParts:
        return super().get_policy_parts(request, response, report_only)

    def get_policy_parts_list(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
        report_only: bool = False,
    ) -> list[PolicyParts]:
        policy_parts = super().get_policy_parts_list(request, response, report_only)

        csp_setting_name = "CONTENT_SECURITY_POLICY_REPORT_ONLY" if report_only else "CONTENT_SECURITY_POLICY"
        policy = getattr(settings, csp_setting_name, None)
        if policy is None:
            return policy_parts

        remove_report = random.random() * 100 >= policy.get("REPORT_PERCENTAGE", 100)
        if not remove_report:
            return policy_parts

        return [
            replace(
                part,
                replace={
                    **(part.replace or {}),
                    "report-uri": None,
                    "report-to": None,
                },
            )
            for part in policy_parts
        ]
