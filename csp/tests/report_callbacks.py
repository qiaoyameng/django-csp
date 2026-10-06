"""Test-only CSP report callbacks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from csp.contrib.reports import CSPViolation

if TYPE_CHECKING:
    from django.http import HttpRequest

received: list[CSPViolation] = []


def collect_callback(request: HttpRequest, violation: CSPViolation) -> None:
    received.append(violation)
