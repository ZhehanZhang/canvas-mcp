"""HTTP bearer gate used when the server holds its own PennKey-managed token."""

from canvas_mcp.server import CanvasCredentialMiddleware


async def _call(mw, headers):
    sent = []

    async def send(msg):
        sent.append(msg)

    async def receive():
        return {"type": "http.request"}

    await mw({"type": "http", "headers": headers}, receive, send)
    return sent


async def _ok_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})


async def test_gate_rejects_missing_or_wrong_key():
    mw = CanvasCredentialMiddleware(_ok_app, access_key="s3cret")
    assert (await _call(mw, []))[0]["status"] == 401
    wrong = [(b"authorization", b"Bearer nope")]
    assert (await _call(mw, wrong))[0]["status"] == 401


async def test_gate_allows_correct_key():
    mw = CanvasCredentialMiddleware(_ok_app, access_key="s3cret")
    ok = [(b"authorization", b"Bearer s3cret")]
    assert (await _call(mw, ok))[0]["status"] == 200


async def test_no_key_configured_keeps_old_behavior():
    mw = CanvasCredentialMiddleware(_ok_app)
    assert (await _call(mw, []))[0]["status"] == 200


async def test_gate_accepts_x_api_key_header():
    mw = CanvasCredentialMiddleware(_ok_app, access_key="s3cret")
    assert (await _call(mw, [(b"x-api-key", b"s3cret")]))[0]["status"] == 200
    assert (await _call(mw, [(b"x-api-key", b"wrong")]))[0]["status"] == 401


def test_chrome_user_agent_has_no_headless_marker():
    from canvas_mcp.auth.pennkey import chrome_user_agent

    ua = chrome_user_agent("141.0.7390.37")
    assert "Headless" not in ua and "Chrome/141.0.0.0" in ua
