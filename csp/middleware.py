from __future__ import annotations

import base64
import http.client as http_client
import os
import warnings
from dataclasses import asdict, dataclass
from functools import partial
from collections.abc import AsyncIterator, Iterator
from typing import TYPE_CHECKING, Any, cast

from django.conf import settings
from django.http import StreamingHttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject, empty

from csp.constants import HEADER, HEADER_REPORT_ONLY
from csp.exceptions import CSPNonceError
from csp.utils import DIRECTIVES_T, build_policy

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase


@dataclass
class PolicyParts:
    # A dataclass is used rather than a namedtuple so that the attributes are mutable
    config: DIRECTIVES_T | None = None
    update: DIRECTIVES_T | None = None
    replace: DIRECTIVES_T | None = None
    nonce: str | None = None


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

    def _policy_header_will_include_nonce(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
        policy_parts: PolicyParts,
        header: str,
        policy_setting: dict[str, Any],
        report_only: bool = False,
    ) -> bool:
        nonce_marker = f"csp-nonce-probe-{os.urandom(16).hex()}"
        policy_arguments = asdict(policy_parts)
        policy_arguments["nonce"] = nonce_marker
        policy = build_policy(**policy_arguments, report_only=report_only)
        exempt_attribute = "_csp_exempt_ro" if report_only else "_csp_exempt"

        return (
            bool(policy)
            and f"'nonce-{nonce_marker}'" in policy
            and self._response_should_include_header(request, response, header, policy_setting, exempt_attribute)
        )

    @staticmethod
    def _response_should_include_header(
        request: HttpRequest,
        response: HttpResponseBase,
        header: str,
        policy_setting: dict[str, Any],
        exempt_attribute: str,
    ) -> bool:
        prefixes = policy_setting.get("EXCLUDE_URL_PREFIXES", None) or ()

        return (
            header not in response
            and getattr(response, exempt_attribute, False) is False
            and not request.path_info.startswith(tuple(prefixes))
        )

    def _fix_streaming_nonce(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
        policy_parts: PolicyParts,
        policy_parts_ro: PolicyParts,
    ) -> str | None:
        if not isinstance(response, StreamingHttpResponse):
            return None

        uses_nonce = self._policy_header_will_include_nonce(
            request,
            response,
            policy_parts,
            HEADER,
            getattr(settings, "CONTENT_SECURITY_POLICY", None) or {},
        ) or self._policy_header_will_include_nonce(
            request,
            response,
            policy_parts_ro,
            HEADER_REPORT_ONLY,
            getattr(settings, "CONTENT_SECURITY_POLICY_REPORT_ONLY", None) or {},
            report_only=True,
        )
        if not uses_nonce:
            return None

        nonce = self._make_nonce(request)
        setattr(request, "csp_nonce", nonce)
        policy_parts.nonce = nonce
        policy_parts_ro.nonce = nonce
        return nonce

    def _wrap_streaming_content(
        self,
        request: HttpRequest,
        response: StreamingHttpResponse,
        fixed_nonce: str,
    ) -> None:
        def clear_nonce() -> None:
            if getattr(request, "_csp_nonce", None) == fixed_nonce:
                setattr(request, "_csp_nonce", None)
                setattr(request, "csp_nonce", CheckableLazyObject(self._csp_nonce_post_response))

        if response.is_async:
            async_streaming_content = cast(AsyncIterator[bytes], response.streaming_content)

            async def wrapper() -> AsyncIterator[bytes]:
                try:
                    async for chunk in async_streaming_content:
                        yield chunk
                finally:
                    clear_nonce()

        else:
            sync_streaming_content = cast(Iterator[bytes], response.streaming_content)

            def wrapper() -> Iterator[bytes]:
                try:
                    yield from sync_streaming_content
                finally:
                    clear_nonce()

        response.streaming_content = wrapper()

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

        policy_parts = self.get_policy_parts(request=request, response=response)
        policy_parts_ro = self.get_policy_parts(request=request, response=response, report_only=True)
        fixed_streaming_nonce = self._fix_streaming_nonce(
            request=request,
            response=response,
            policy_parts=policy_parts,
            policy_parts_ro=policy_parts_ro,
        )
        csp = build_policy(**asdict(policy_parts))
        if csp:
            # Only set header if not already set and not an excluded prefix and not exempted.
            policy = getattr(settings, "CONTENT_SECURITY_POLICY", None) or {}
            if self._response_should_include_header(request, response, HEADER, policy, "_csp_exempt"):
                response[HEADER] = csp

        csp_ro = build_policy(**asdict(policy_parts_ro), report_only=True)
        if csp_ro:
            # Only set header if not already set and not an excluded prefix and not exempted.
            policy = getattr(settings, "CONTENT_SECURITY_POLICY_REPORT_ONLY", None) or {}
            if self._response_should_include_header(request, response, HEADER_REPORT_ONLY, policy, "_csp_exempt_ro"):
                response[HEADER_REPORT_ONLY] = csp_ro

        # Once we've written the header, accessing the `request.csp_nonce` will no longer trigger
        # the nonce to be added to the header. Instead we throw an error here to catch this since
        # this has security implications.
        if fixed_streaming_nonce is not None and isinstance(response, StreamingHttpResponse):
            self._wrap_streaming_content(request, response, fixed_streaming_nonce)
        elif getattr(request, "_csp_nonce", None) is None:
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
        if report_only:
            config = getattr(response, "_csp_config_ro", None)
            update = getattr(response, "_csp_update_ro", None)
            replace = getattr(response, "_csp_replace_ro", None)
        else:
            config = getattr(response, "_csp_config", None)
            update = getattr(response, "_csp_update", None)
            replace = getattr(response, "_csp_replace", None)

        nonce = getattr(request, "_csp_nonce", None)

        return PolicyParts(config, update, replace, nonce)
