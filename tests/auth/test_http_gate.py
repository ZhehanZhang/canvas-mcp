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


async def _call_scope(mw, scope_extra):
    sent = []
    seen = {}

    async def app(scope, receive, send):
        seen["qs"] = scope.get("query_string")
        await send({"type": "http.response.start", "status": 200, "headers": []})

    mw.app = app

    async def send(msg):
        sent.append(msg)

    async def receive():
        return {"type": "http.request"}

    await mw({"type": "http", "headers": [], **scope_extra}, receive, send)
    return sent[0]["status"], seen.get("qs")


async def test_gate_accepts_query_param_and_strips_it():
    mw = CanvasCredentialMiddleware(_ok_app, access_key="s3cret")
    status, qs = await _call_scope(mw, {"query_string": b"api_key=s3cret&x=1"})
    assert status == 200 and qs == b"x=1"
    status, _ = await _call_scope(mw, {"query_string": b"key=s3cret"})
    assert status == 200
    status, _ = await _call_scope(mw, {"query_string": b"api_key=wrong"})
    assert status == 401


async def test_gate_accepts_bare_authorization_header():
    mw = CanvasCredentialMiddleware(_ok_app, access_key="s3cret")
    assert (await _call(mw, [(b"authorization", b"s3cret")]))[0]["status"] == 200
    assert (await _call(mw, [(b"authorization", b"Basic s3cret")]))[0]["status"] == 401
