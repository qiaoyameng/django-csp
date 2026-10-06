from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Generator
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from django.http import HttpRequest

from django.http import (
    HttpResponse,
    HttpResponseNotFound,
    HttpResponseServerError,
    StreamingHttpResponse,
)
from django.template import Context, Template, engines
from django.test import RequestFactory
from django.test.utils import override_settings

import pytest

from csp.constants import HEADER, HEADER_REPORT_ONLY, SELF
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


def test_streaming_nonce_is_fixed_in_header_and_body_sync() -> None:
    request = rf.get("/")
    mw.process_request(request)

    def streaming_content() -> Generator[str, None, None]:
        yield str(request.csp_nonce)
        yield str(request.csp_nonce)

    response = StreamingHttpResponse(streaming_content())
    mw.process_response(request, response)
    header_nonce = response[HEADER].split("'nonce-", 1)[1].rstrip("'")

    assert bool(request.csp_nonce) is True
    chunks = [chunk.decode() for chunk in response.streaming_content]

    assert chunks == [header_nonce, header_nonce]
    assert bool(request.csp_nonce) is False
    with pytest.raises(CSPNonceError):
        str(request.csp_nonce)


def test_streaming_nonce_is_fixed_in_header_and_body_async() -> None:
    request = rf.get("/")
    mw.process_request(request)

    async def streaming_content() -> AsyncGenerator[str, None]:
        yield str(request.csp_nonce)
        yield str(request.csp_nonce)

    response = StreamingHttpResponse(streaming_content())
    mw.process_response(request, response)
    header_nonce = response[HEADER].split("'nonce-", 1)[1].rstrip("'")

    async def consume() -> list[str]:
        return [chunk.decode() async for chunk in response.streaming_content]

    assert bool(request.csp_nonce) is True
    assert asyncio.run(consume()) == [header_nonce, header_nonce]
    assert bool(request.csp_nonce) is False
    with pytest.raises(CSPNonceError):
        str(request.csp_nonce)


def test_two_streaming_responses_can_iterate_in_parallel_sync() -> None:
    requests = [rf.get("/"), rf.get("/")]
    responses = []

    for request in requests:
        mw.process_request(request)

        def streaming_content(request: HttpRequest = request) -> Generator[str, None, None]:
            yield str(request.csp_nonce)
            yield str(request.csp_nonce)

        response = StreamingHttpResponse(streaming_content())
        mw.process_response(request, response)
        responses.append(response)

    first_iterators = [iter(response.streaming_content) for response in responses]
    first_chunks = [next(iterator) for iterator in first_iterators]
    second_chunks = [next(iterator) for iterator in reversed(first_iterators)]

    header_nonces = [response[HEADER].split("'nonce-", 1)[1].rstrip("'") for response in responses]
    assert [chunk.decode() for chunk in first_chunks] == header_nonces
    assert [chunk.decode() for chunk in reversed(second_chunks)] == header_nonces
    assert header_nonces[0] != header_nonces[1]


def test_two_streaming_responses_can_iterate_in_parallel_async() -> None:
    requests = [rf.get("/"), rf.get("/")]
    responses = []

    for request in requests:
        mw.process_request(request)

        async def streaming_content(request: HttpRequest = request) -> AsyncGenerator[str, None]:
            yield str(request.csp_nonce)
            yield str(request.csp_nonce)

        response = StreamingHttpResponse(streaming_content())
        mw.process_response(request, response)
        responses.append(response)

    async def consume() -> list[list[str]]:
        iterators = [response.streaming_content.__aiter__() for response in responses]
        first_chunks = [await iterator.__anext__() for iterator in iterators]
        second_chunks = [await iterator.__anext__() for iterator in reversed(iterators)]
        return [
            [chunk.decode() for chunk in first_chunks],
            [chunk.decode() for chunk in reversed(second_chunks)],
        ]

    header_nonces = [response[HEADER].split("'nonce-", 1)[1].rstrip("'") for response in responses]
    chunks = asyncio.run(consume())
    assert chunks == [header_nonces, header_nonces]
    assert header_nonces[0] != header_nonces[1]


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}})
def test_streaming_without_nonce_policy_raises_on_late_read_sync() -> None:
    request = rf.get("/")
    mw.process_request(request)

    def streaming_content() -> Generator[str, None, None]:
        yield str(request.csp_nonce)

    response = StreamingHttpResponse(streaming_content())
    mw.process_response(request, response)

    with pytest.raises(CSPNonceError):
        next(iter(response.streaming_content))


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}})
def test_streaming_without_nonce_policy_raises_on_late_read_async() -> None:
    request = rf.get("/")
    mw.process_request(request)

    async def streaming_content() -> AsyncGenerator[str, None]:
        yield str(request.csp_nonce)

    response = StreamingHttpResponse(streaming_content())
    mw.process_response(request, response)

    async def consume() -> None:
        async for chunk in response.streaming_content:
            return chunk

    with pytest.raises(CSPNonceError):
        asyncio.run(consume())


def test_streaming_nonce_is_cleared_when_sync_stream_closes() -> None:
    request = rf.get("/")
    mw.process_request(request)

    def streaming_content() -> Generator[str, None, None]:
        yield str(request.csp_nonce)
        yield str(request.csp_nonce)

    response = StreamingHttpResponse(streaming_content())
    mw.process_response(request, response)
    fixed_nonce = response[HEADER].split("'nonce-", 1)[1].rstrip("'")
    iterator = iter(response.streaming_content)
    assert next(iterator).decode() == fixed_nonce

    response.close()

    assert bool(request.csp_nonce) is False
    with pytest.raises(CSPNonceError):
        str(request.csp_nonce)


def test_streaming_nonce_is_cleared_when_async_stream_cancels() -> None:
    request = rf.get("/")
    mw.process_request(request)

    async def streaming_content() -> AsyncGenerator[str, None]:
        yield str(request.csp_nonce)
        await asyncio.Event().wait()

    response = StreamingHttpResponse(streaming_content())
    mw.process_response(request, response)
    fixed_nonce = response[HEADER].split("'nonce-", 1)[1].rstrip("'")

    async def consume(streaming_content: Any) -> None:
        async for chunk in streaming_content:
            assert chunk.decode() == fixed_nonce
            await asyncio.sleep(1000)

    async def cancel_stream() -> None:
        task = asyncio.ensure_future(consume(response.streaming_content))
        await asyncio.sleep(0)
        assert task.done() is False
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_stream())

    assert bool(request.csp_nonce) is False
    with pytest.raises(CSPNonceError):
        str(request.csp_nonce)


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
