from __future__ import annotations

import base64
import http.client as http_client
import os
import warnings
from dataclasses import asdict
from functools import partial
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject, empty

from csp.constants import HEADER, HEADER_REPORT_ONLY
from csp.exceptions import CSPNonceError
from csp.policies import PolicyParts, PolicyPartsCollection
from csp.utils import DIRECTIVES_T, build_policy, get_policy_configs

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase


class CheckableLazyObject(SimpleLazyObject):
    """A SimpleLazyObject where bool(obj) returns True if no longer lazy"""

    def __bool__(self) -> bool:
        """
        If the wrapped function has been evaluated, return True.
        If the wrapped function has not been evalated, return False.
        """
        return getattr(self, "_wrapped") is not empty


class CSPMiddleware(MiddlewareMixin):
    """
    Implements the Content-Security-Policy response header, which
    conforming user-agents can use to restrict the permitted sources
    of various content.

    See http://www.w3.org/TR/CSP/

    Can be customised by subclassing and extending the get_policy_parts method.
    """

    def _make_nonce(self, request: HttpRequest) -> str:
        # Ensure that any subsequent calls to request.csp_nonce return the same value
        stored_nonce = getattr(request, "_csp_nonce", None)
        if isinstance(stored_nonce, str):
            return stored_nonce
        nonce = base64.b64encode(os.urandom(16)).decode("ascii")
        setattr(request, "_csp_nonce", nonce)
        return nonce

    @staticmethod
    def _csp_nonce_post_response() -> None:
        raise CSPNonceError(
            "The 'csp_nonce' attribute is not available after the CSP header has been written. Consider adjusting your MIDDLEWARE order."
        )

    def process_request(self, request: HttpRequest) -> None:
        nonce = partial(self._make_nonce, request)
        setattr(request, "csp_nonce", CheckableLazyObject(nonce))

    def process_response(self, request: HttpRequest, response: HttpResponseBase) -> HttpResponseBase:
        # Check for debug view
        exempted_debug_codes = (
            http_client.INTERNAL_SERVER_ERROR,
            http_client.NOT_FOUND,
        )
        if response.status_code in exempted_debug_codes and settings.DEBUG:
            return response

        policy_collection = self.get_policy_collection(request=request, response=response)
        csp_policies = [build_policy(**asdict(policy_parts)) for policy_parts in policy_collection.enforced]
        csp = ", ".join(policy for policy in csp_policies if policy)
        if csp:
            # Only set header if not already set and not an excluded prefix and not exempted.
            is_not_exempt = getattr(response, "_csp_exempt", False) is False
            no_header = HEADER not in response
            policy = getattr(settings, "CONTENT_SECURITY_POLICY", None) or {}
            prefixes = policy.get("EXCLUDE_URL_PREFIXES", None) or ()
            is_not_excluded = not request.path_info.startswith(tuple(prefixes))
            if no_header and is_not_exempt and is_not_excluded:
                response[HEADER] = csp

        csp_policies_ro = [
            build_policy(**asdict(policy_parts), report_only=True)
            for policy_parts in policy_collection.report_only
        ]
        csp_ro = ", ".join(policy for policy in csp_policies_ro if policy)
        if csp_ro:
            # Only set header if not already set and not an excluded prefix and not exempted.
            is_not_exempt = getattr(response, "_csp_exempt_ro", False) is False
            no_header = HEADER_REPORT_ONLY not in response
            policy = getattr(settings, "CONTENT_SECURITY_POLICY_REPORT_ONLY", None) or {}
            prefixes = policy.get("EXCLUDE_URL_PREFIXES", None) or ()
            is_not_excluded = not request.path_info.startswith(tuple(prefixes))
            if no_header and is_not_exempt and is_not_excluded:
                response[HEADER_REPORT_ONLY] = csp_ro

        # Once we've written the header, accessing the `request.csp_nonce` will no longer trigger
        # the nonce to be added to the header. Instead we throw an error here to catch this since
        # this has security implications.
        if getattr(request, "_csp_nonce", None) is None:
            setattr(request, "csp_nonce", CheckableLazyObject(self._csp_nonce_post_response))

        return response

    def build_policy(self, request: HttpRequest, response: HttpResponseBase) -> str:
        warnings.warn("deprecated in favor of get_policy_parts", DeprecationWarning)
        policy_parts = self.get_policy_parts(request=request, response=response, report_only=False)
        return build_policy(**asdict(policy_parts))

    def build_policy_ro(self, request: HttpRequest, response: HttpResponseBase) -> str:
        warnings.warn("deprecated in favor of get_policy_parts", DeprecationWarning)
        policy_parts_ro = self.get_policy_parts(request=request, response=response, report_only=True)
        return build_policy(**asdict(policy_parts_ro), report_only=True)

    def get_policy_parts(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
        report_only: bool = False,
    ) -> PolicyParts:
        setting_configs = get_policy_configs(report_only=report_only)
        return self._build_policy_parts(request, response, report_only, 0, setting_configs)

    def get_policy_collection(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
    ) -> PolicyPartsCollection:
        return PolicyPartsCollection(
            enforced=self.get_policy_parts_list(request=request, response=response, report_only=False),
            report_only=self.get_policy_parts_list(request=request, response=response, report_only=True),
        )

    @staticmethod
    def _get_policy_attribute(
        response: HttpResponseBase,
        attribute: str,
        report_only: bool,
        policy_index: int,
    ) -> Any:
        suffix = "_ro" if report_only else ""
        if policy_index == 0:
            return getattr(response, f"_csp_{attribute}{suffix}", None)
        values = getattr(response, f"_csp_{attribute}_additional{suffix}", {})
        if isinstance(values, dict):
            return values.get(policy_index)
        return None

    def get_policy_parts_list(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
        report_only: bool = False,
    ) -> list[PolicyParts]:
        setting_configs = get_policy_configs(report_only=report_only)
        suffix = "_ro" if report_only else ""

        config_overrides = getattr(response, f"_csp_config_additional{suffix}", {})
        updates = getattr(response, f"_csp_update_additional{suffix}", {})
        replaces = getattr(response, f"_csp_replace_additional{suffix}", {})
        if not isinstance(config_overrides, dict) or not isinstance(updates, dict) or not isinstance(replaces, dict):
            raise TypeError("Additional CSP policy attributes must be dictionaries keyed by policy index.")

        policy_count = len(setting_configs)
        for indexed_attribute in (config_overrides, updates, replaces):
            for policy_index in indexed_attribute:
                if not isinstance(policy_index, int) or isinstance(policy_index, bool):
                    raise TypeError("CSP policy indexes must be integers.")
                if policy_index < 0:
                    raise ValueError("CSP policy indexes must be non-negative.")

        configured_count = len(setting_configs)
        config_override_count = max(config_overrides, default=0)
        policy_count = max(policy_count, config_override_count + 1)
        for policy_index in range(1, policy_count):
            if policy_index >= configured_count and policy_index not in config_overrides:
                raise ValueError("Additional CSP policy indexes must start at 1 and be contiguous.")

        for indexed_attribute in (updates, replaces):
            for policy_index in indexed_attribute:
                if policy_index >= policy_count:
                    raise ValueError(f"CSP policy index {policy_index} is not configured.")

        policy_parts = []
        for policy_index in range(policy_count):
            if policy_index == 0:
                policy_parts.append(self.get_policy_parts(request=request, response=response, report_only=report_only))
                continue

            if policy_index in config_overrides:
                config = config_overrides[policy_index]
            else:
                config = setting_configs[policy_index]
            policy_parts.append(self._build_policy_parts(request, response, report_only, policy_index, setting_configs, config))

        return policy_parts

    def _build_policy_parts(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
        report_only: bool,
        policy_index: int,
        setting_configs: list[dict[str, Any] | None],
        config_override: DIRECTIVES_T | None = None,
    ) -> PolicyParts:
        suffix = "_ro" if report_only else ""
        if policy_index == 0:
            primary_config = getattr(response, f"_csp_config{suffix}", None)
            if primary_config is not None:
                config = primary_config
            elif setting_configs:
                config = setting_configs[0]
            else:
                config = None
        else:
            config = config_override

        nonce = getattr(request, "_csp_nonce", None)
        return PolicyParts(
            config=config,
            update=self._get_policy_attribute(response, "update", report_only, policy_index),
            replace=self._get_policy_attribute(response, "replace", report_only, policy_index),
            nonce=nonce,
        )
