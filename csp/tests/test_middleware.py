import asyncio

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

from csp.constants import HEADER, HEADER_REPORT_ONLY, NONCE, SELF
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


def test_streaming_nonce_is_fixed_before_response_body() -> None:
    def body(request):
        yield f'<script nonce="{request.csp_nonce}"></script>'

    request1 = rf.get("/")
    request2 = rf.get("/")
    mw.process_request(request1)
    mw.process_request(request2)
    response1 = StreamingHttpResponse(body(request1))
    response2 = StreamingHttpResponse(body(request2))
    mw.process_response(request1, response1)
    mw.process_response(request2, response2)

    nonce1 = request1._csp_nonce
    nonce2 = request2._csp_nonce
    assert nonce1 != nonce2
    assert response1[HEADER] == f"default-src 'self' 'nonce-{nonce1}'"
    assert response2[HEADER] == f"default-src 'self' 'nonce-{nonce2}'"

    iterator1 = iter(response1.streaming_content)
    iterator2 = iter(response2.streaming_content)
    assert next(iterator1) == f'<script nonce="{nonce1}"></script>'.encode()
    assert next(iterator2) == f'<script nonce="{nonce2}"></script>'.encode()
    with pytest.raises(StopIteration):
        next(iterator1)
    with pytest.raises(StopIteration):
        next(iterator2)


def test_async_streaming_nonce_is_fixed_before_response_body() -> None:
    async def body(request):
        yield f'<script nonce="{request.csp_nonce}"></script>'

    async def test_body():
        request1 = rf.get("/")
        request2 = rf.get("/")
        mw.process_request(request1)
        mw.process_request(request2)
        response1 = StreamingHttpResponse(body(request1))
        response2 = StreamingHttpResponse(body(request2))
        mw.process_response(request1, response1)
        mw.process_response(request2, response2)

        nonce1 = request1._csp_nonce
        nonce2 = request2._csp_nonce
        assert nonce1 != nonce2
        assert response1[HEADER] == f"default-src 'self' 'nonce-{nonce1}'"
        assert response2[HEADER] == f"default-src 'self' 'nonce-{nonce2}'"

        iterator1 = response1.streaming_content
        iterator2 = response2.streaming_content
        assert await iterator1.__anext__() == f'<script nonce="{nonce1}"></script>'.encode()
        assert await iterator2.__anext__() == f'<script nonce="{nonce2}"></script>'.encode()
        with pytest.raises(StopAsyncIteration):
            await iterator1.__anext__()
        with pytest.raises(StopAsyncIteration):
            await iterator2.__anext__()

    asyncio.run(test_body())


def test_streaming_nonce_recognized_as_scalar_policy_value() -> None:
    request = rf.get("/")
    mw.process_request(request)
    response = StreamingHttpResponse((str(request.csp_nonce),))
    setattr(response, "_csp_config", {"default-src": NONCE})
    mw.process_response(request, response)

    nonce = request._csp_nonce
    assert response[HEADER] == f"default-src 'nonce-{nonce}'"
    assert b"".join(response.streaming_content) == nonce.encode()


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF, NONCE]}},
)
def test_streaming_nonce_is_fixed_for_report_only_policy() -> None:
    request = rf.get("/")
    mw.process_request(request)
    response = StreamingHttpResponse((str(request.csp_nonce),))
    mw.process_response(request, response)

    nonce = request._csp_nonce
    assert response[HEADER] == "default-src 'self'"
    assert response[HEADER_REPORT_ONLY] == f"default-src 'self' 'nonce-{nonce}'"
    assert b"".join(response.streaming_content) == nonce.encode()


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}})
def test_streaming_nonce_disabled_raises_on_late_read() -> None:
    request = rf.get("/")

    def body():
        yield str(request.csp_nonce)

    mw.process_request(request)
    response = StreamingHttpResponse(body())
    mw.process_response(request, response)
    assert response[HEADER] == "default-src 'self'"
    with pytest.raises(CSPNonceError):
        list(response.streaming_content)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}})
def test_async_streaming_nonce_disabled_raises_on_late_read() -> None:
    request = rf.get("/")

    async def body():
        yield str(request.csp_nonce)

    async def test_body():
        async for _chunk in response.streaming_content:
            pass

    mw.process_request(request)
    response = StreamingHttpResponse(body())
    mw.process_response(request, response)
    assert response[HEADER] == "default-src 'self'"
    with pytest.raises(CSPNonceError):
        asyncio.run(test_body())


def test_closed_streaming_nonce_does_not_leak_to_next_request() -> None:
    def body():
        yield "before"
        yield str(request1.csp_nonce)

    request1 = rf.get("/")
    mw.process_request(request1)
    response1 = StreamingHttpResponse(body())
    mw.process_response(request1, response1)
    nonce1 = request1._csp_nonce
    iterator = iter(response1.streaming_content)
    assert next(iterator) == b"before"
    response1.close()

    request2 = rf.get("/")
    mw.process_request(request2)
    response2 = StreamingHttpResponse(
        f'<script nonce="{request2.csp_nonce}"></script>' for _value in ()
    )
    assert getattr(request2, "_csp_nonce", None) is None
    mw.process_response(request2, response2)
    nonce2 = request2._csp_nonce
    assert nonce1 != nonce2


def test_cancelled_async_streaming_nonce_does_not_leak_to_next_request() -> None:
    async def body():
        yield "before"
        await asyncio.Event().wait()

    async def consume(response):
        async for _chunk in response.streaming_content:
            await asyncio.Event().wait()

    async def test_body():
        request1 = rf.get("/")
        mw.process_request(request1)
        response1 = StreamingHttpResponse(body())
        mw.process_response(request1, response1)
        nonce1 = request1._csp_nonce
        task = asyncio.create_task(consume(response1))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        request2 = rf.get("/")
        mw.process_request(request2)
        response2 = StreamingHttpResponse(())
        assert getattr(request2, "_csp_nonce", None) is None
        mw.process_response(request2, response2)
        nonce2 = request2._csp_nonce
        assert nonce1 != nonce2

    asyncio.run(test_body())
