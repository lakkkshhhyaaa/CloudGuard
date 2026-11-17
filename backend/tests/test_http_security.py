import asyncio

from app.main import (
    MAX_REQUEST_BODY_BYTES,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)


def run_asgi(app, body=b"", headers=None, path="/"):
    sent = []
    messages = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers or [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }

    asyncio.run(app(scope, receive, send))
    return sent


def simple_app(status=200):
    async def app(scope, receive, send):
        await receive()
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"text/plain")],
        })
        await send({
            "type": "http.response.body",
            "body": b"ok",
            "more_body": False,
        })
    return app


def response_start(messages):
    return next(m for m in messages if m["type"] == "http.response.start")


def test_security_headers_are_added():
    middleware = SecurityHeadersMiddleware(simple_app())
    messages = run_asgi(middleware)

    headers = dict(response_start(messages)["headers"])
    assert headers[b"x-content-type-options"] == b"nosniff"
    assert headers[b"x-frame-options"] == b"DENY"
    assert headers[b"referrer-policy"] == b"strict-origin-when-cross-origin"
    assert b"strict-transport-security" not in headers


def test_hsts_is_added_only_when_explicitly_enabled():
    middleware = SecurityHeadersMiddleware(simple_app(), enable_hsts=True)
    messages = run_asgi(middleware)

    headers = dict(response_start(messages)["headers"])
    assert headers[b"strict-transport-security"] == (
        b"max-age=31536000; includeSubDomains"
    )


def test_existing_security_header_is_not_duplicated():
    async def app(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"x-frame-options", b"SAMEORIGIN")],
        })
        await send({"type": "http.response.body", "body": b""})

    messages = run_asgi(SecurityHeadersMiddleware(app))
    headers = [k for k, _ in response_start(messages)["headers"]]
    assert headers.count(b"x-frame-options") == 1


def test_request_body_under_limit_is_allowed():
    middleware = RequestSizeLimitMiddleware(simple_app(), max_bytes=10)
    messages = run_asgi(middleware, body=b"1234567890")
    assert response_start(messages)["status"] == 200


def test_declared_content_length_over_limit_is_rejected():
    middleware = RequestSizeLimitMiddleware(simple_app(), max_bytes=10)
    messages = run_asgi(
        middleware,
        body=b"",
        headers=[(b"content-length", b"11")],
    )
    assert response_start(messages)["status"] == 413


def test_actual_body_over_limit_is_rejected():
    middleware = RequestSizeLimitMiddleware(simple_app(), max_bytes=10)
    messages = run_asgi(middleware, body=b"12345678901")
    assert response_start(messages)["status"] == 413


def test_invalid_content_length_is_rejected():
    middleware = RequestSizeLimitMiddleware(simple_app(), max_bytes=10)
    messages = run_asgi(
        middleware,
        body=b"",
        headers=[(b"content-length", b"not-a-number")],
    )
    assert response_start(messages)["status"] == 413


def test_non_http_scope_is_passed_through():
    called = []

    async def app(scope, receive, send):
        called.append(scope["type"])

    middleware = RequestSizeLimitMiddleware(app, max_bytes=10)

    async def receive():
        return {"type": "websocket.receive"}

    async def send(message):
        pass

    asyncio.run(middleware({"type": "websocket"}, receive, send))
    assert called == ["websocket"]
