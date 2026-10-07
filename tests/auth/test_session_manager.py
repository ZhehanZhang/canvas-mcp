"""Tests for automated Canvas web-session auth (CANVAS_AUTH_MODE=pennkey)."""

import os
import stat
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from canvas_mcp.auth import manager as manager_module
from canvas_mcp.auth.httpx_auth import SessionAuth
from canvas_mcp.auth.manager import SessionInvalidError, SessionManager
from canvas_mcp.auth.pennkey import BadCredentialsError, DuoError, LoginError
from canvas_mcp.auth.session import CanvasSession, SessionStore, strip_json_prefix
from canvas_mcp.auth.settings import AuthConfigError, AuthSettings


def make_settings(tmp_path: Path, **overrides) -> AuthSettings:
    base = AuthSettings(
        username="pennuser",
        password="secret",
        api_url="https://canvas.example.edu/api/v1",
        login_path="/login/saml",
        state_dir=tmp_path,
        refresh_check_interval_sec=900,
        duo_factor="push",
        duo_passcode="",
        duo_timeout_sec=5,
        duo_max_push_attempts=2,
        duo_trust_browser=True,
        login_timeout_sec=10,
        login_cooldown_sec=900,
        notify_webhook_url="",
        headless=True,
    )
    return replace(base, **overrides)


def sess(value: str, csrf: str = "abc%2Bdef") -> CanvasSession:
    return CanvasSession.from_cookies([
        {"name": "_normandy_session", "value": value, "domain": "canvas.example.edu"},
        {"name": "_csrf_token", "value": csrf, "domain": "canvas.example.edu"},
    ])


class FakeLogin:
    def __init__(self, sessions=None, error: Exception | None = None):
        self.calls = 0
        self.sessions = list(sessions or [])
        self.error = error

    def __call__(self, settings, notify):
        self.calls += 1
        if self.error:
            raise self.error
        return self.sessions.pop(0)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("unexpected network call")

    monkeypatch.setattr(manager_module, "validate_session", fail)


def _store(tmp_path: Path) -> SessionStore:
    return SessionStore(tmp_path / "canvas_session.json")


# -- settings -----------------------------------------------------------------


def test_settings_reads_secret_files(tmp_path, monkeypatch):
    pw_file = tmp_path / "pw"
    pw_file.write_text("from-file\n")
    monkeypatch.setenv("PENNKEY_USERNAME", "alice")
    monkeypatch.delenv("PENNKEY_PASSWORD", raising=False)
    monkeypatch.setenv("PENNKEY_PASSWORD_FILE", str(pw_file))
    monkeypatch.delenv("CANVAS_API_URL", raising=False)
    monkeypatch.setenv("CANVAS_AUTH_STATE_DIR", str(tmp_path))
    settings = AuthSettings.from_env()
    assert settings.password == "from-file"
    assert settings.base_url == "https://canvas.upenn.edu"
    assert settings.session_file == tmp_path / "canvas_session.json"
    settings.require_credentials()


def test_settings_rejects_bad_values(monkeypatch):
    monkeypatch.setenv("DUO_FACTOR", "sms-bypass")
    with pytest.raises(AuthConfigError):
        AuthSettings.from_env()
    monkeypatch.setenv("DUO_FACTOR", "push")
    monkeypatch.setenv("CANVAS_SESSION_CHECK_SEC", "5")
    with pytest.raises(AuthConfigError):
        AuthSettings.from_env()


def test_require_credentials_missing(tmp_path):
    with pytest.raises(AuthConfigError, match="PENNKEY_PASSWORD"):
        make_settings(tmp_path, password="").require_credentials()


# -- session + store ----------------------------------------------------------


def test_session_headers():
    s = sess("sessval", csrf="abc%2Bdef%3D%3D")
    assert "_normandy_session=sessval" in s.cookie_header()
    assert s.csrf_token() == "abc+def=="  # URL-decoded for the header
    assert s.is_usable()


def test_session_without_session_cookie_is_unusable():
    s = CanvasSession.from_cookies([{"name": "_csrf_token", "value": "x"}])
    assert not s.is_usable()


def test_session_store_roundtrip_is_private(tmp_path):
    store = SessionStore(tmp_path / "state" / "canvas_session.json")
    store.save(sess("abc"))
    assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600
    loaded = store.load()
    assert loaded is not None and "_normandy_session=abc" in loaded.cookie_header()
    store.clear()
    assert store.load() is None


def test_strip_json_prefix():
    assert strip_json_prefix('while(1);{"a":1}') == '{"a":1}'
    assert strip_json_prefix('{"a":1}') == '{"a":1}'


# -- manager ------------------------------------------------------------------


def test_first_run_logs_in_and_persists(tmp_path):
    login = FakeLogin([sess("fresh")])
    mgr = SessionManager(make_settings(tmp_path), login_runner=login)
    assert "fresh" in mgr.ensure_valid_session().cookie_header()
    assert login.calls == 1
    assert "fresh" in _store(tmp_path).load().cookie_header()
    mgr.ensure_valid_session()
    assert login.calls == 1


def test_saved_session_reused_without_login(tmp_path):
    _store(tmp_path).save(sess("saved"))
    login = FakeLogin()
    mgr = SessionManager(make_settings(tmp_path), login_runner=login)
    assert "saved" in mgr.ensure_valid_session().cookie_header()
    assert login.calls == 0


def test_validate_drops_expired_session_and_relogs(tmp_path, monkeypatch):
    _store(tmp_path).save(sess("expired"))

    def reject(url, session):
        raise SessionInvalidError("401")

    monkeypatch.setattr(manager_module, "validate_session", reject)
    login = FakeLogin([sess("fresh")])
    mgr = SessionManager(make_settings(tmp_path), login_runner=login)
    assert "fresh" in mgr.ensure_valid_session(validate=True).cookie_header()
    assert login.calls == 1


def test_validate_network_error_keeps_session(tmp_path, monkeypatch):
    _store(tmp_path).save(sess("saved"))

    def boom(url, session):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(manager_module, "validate_session", boom)
    login = FakeLogin()
    mgr = SessionManager(make_settings(tmp_path), login_runner=login)
    assert "saved" in mgr.ensure_valid_session(validate=True).cookie_header()
    assert login.calls == 0


def test_failed_login_enters_cooldown(tmp_path):
    login = FakeLogin(error=DuoError("not approved"))
    mgr = SessionManager(make_settings(tmp_path), login_runner=login)
    with pytest.raises(DuoError):
        mgr.ensure_valid_session()
    with pytest.raises(LoginError, match="paused"):
        mgr.ensure_valid_session()
    assert login.calls == 1  # no second Duo push during cooldown


def test_bad_password_disables_auto_login(tmp_path):
    login = FakeLogin(error=BadCredentialsError("wrong password"))
    mgr = SessionManager(make_settings(tmp_path, login_cooldown_sec=0), login_runner=login)
    with pytest.raises(BadCredentialsError):
        mgr.ensure_valid_session()
    with pytest.raises(LoginError, match="disabled"):
        mgr.ensure_valid_session()
    assert login.calls == 1


def test_unexpected_login_exception_wrapped(tmp_path):
    mgr = SessionManager(make_settings(tmp_path), login_runner=FakeLogin(error=RuntimeError("crash")))
    with pytest.raises(LoginError, match="crash"):
        mgr.ensure_valid_session()


def test_unauthorized_permission_error_does_not_relogin(tmp_path, monkeypatch):
    _store(tmp_path).save(sess("good"))
    login = FakeLogin()
    mgr = SessionManager(make_settings(tmp_path), login_runner=login)
    current = mgr.ensure_valid_session()
    monkeypatch.setattr(manager_module, "validate_session", lambda url, s: None)
    assert mgr.handle_unauthorized(current.cookie_header()) is None
    assert login.calls == 0


def test_unauthorized_expired_session_relogs(tmp_path, monkeypatch):
    _store(tmp_path).save(sess("old"))
    mgr = SessionManager(make_settings(tmp_path), login_runner=FakeLogin([sess("fresh")]))
    current = mgr.ensure_valid_session()

    def reject(url, session):
        raise SessionInvalidError("401")

    monkeypatch.setattr(manager_module, "validate_session", reject)
    new = mgr.handle_unauthorized(current.cookie_header())
    assert new is not None and "fresh" in new.cookie_header()


def test_unauthorized_with_stale_marker_returns_current(tmp_path):
    _store(tmp_path).save(sess("newer"))
    mgr = SessionManager(make_settings(tmp_path), login_runner=FakeLogin())
    mgr.ensure_valid_session()
    result = mgr.handle_unauthorized("_normandy_session=older")
    assert result is not None and "newer" in result.cookie_header()


def test_on_notify_receives_login_messages(tmp_path):
    seen = []

    def login(settings, notify):
        notify("Enter code 123 in Duo Mobile")
        return sess("fresh")

    mgr = SessionManager(make_settings(tmp_path), login_runner=login, on_notify=seen.append)
    mgr.ensure_valid_session()
    assert seen == ["Enter code 123 in Duo Mobile"]


def test_get_session_manager_respects_mode(monkeypatch, tmp_path):
    from canvas_mcp.auth import get_session_manager, reset_session_manager

    reset_session_manager()
    monkeypatch.setenv("CANVAS_AUTH_MODE", "token")
    assert get_session_manager() is None
    monkeypatch.setenv("CANVAS_AUTH_MODE", "pennkey")
    monkeypatch.setenv("CANVAS_AUTH_STATE_DIR", str(tmp_path))
    try:
        assert isinstance(get_session_manager(), SessionManager)
    finally:
        reset_session_manager()


# -- httpx auth ---------------------------------------------------------------


async def test_session_auth_sends_cookies_and_csrf_on_writes(tmp_path):
    _store(tmp_path).save(sess("good", csrf="tok%2B1"))
    mgr = SessionManager(make_settings(tmp_path), login_runner=FakeLogin())
    mgr.ensure_valid_session()
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.headers.get("Cookie"), request.headers.get("X-CSRF-Token")))
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), auth=SessionAuth(mgr)) as c:
        await c.get("https://canvas.example.edu/api/v1/courses")
        await c.post("https://canvas.example.edu/api/v1/courses/1/discussion_topics", json={})
    get_req, post_req = seen
    assert "_normandy_session=good" in get_req[1] and get_req[2] is None
    assert post_req[2] == "tok+1"


async def test_session_auth_relogs_once_on_401(tmp_path, monkeypatch):
    _store(tmp_path).save(sess("expired"))
    mgr = SessionManager(make_settings(tmp_path), login_runner=FakeLogin([sess("fresh")]))
    mgr.ensure_valid_session()

    def reject(url, session):
        raise SessionInvalidError("401")

    monkeypatch.setattr(manager_module, "validate_session", reject)
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        cookie = request.headers["Cookie"]
        seen.append(cookie)
        if "expired" in cookie:
            return httpx.Response(401, json={"status": "unauthenticated"})
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), auth=SessionAuth(mgr)) as c:
        response = await c.get("https://canvas.example.edu/api/v1/courses")
    assert response.status_code == 200
    assert len(seen) == 2 and "fresh" in seen[1]


async def test_session_auth_treats_login_redirect_as_expired(tmp_path, monkeypatch):
    _store(tmp_path).save(sess("expired"))
    mgr = SessionManager(make_settings(tmp_path), login_runner=FakeLogin([sess("fresh")]))
    mgr.ensure_valid_session()
    monkeypatch.setattr(
        manager_module, "validate_session",
        lambda url, s: (_ for _ in ()).throw(SessionInvalidError("302")),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if "expired" in request.headers["Cookie"]:
            return httpx.Response(302, headers={"location": "https://canvas.example.edu/login"})
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), auth=SessionAuth(mgr)) as c:
        response = await c.get("https://canvas.example.edu/api/v1/courses")
    assert response.status_code == 200


async def test_session_auth_passes_through_permission_401(tmp_path, monkeypatch):
    _store(tmp_path).save(sess("good"))
    mgr = SessionManager(make_settings(tmp_path), login_runner=FakeLogin())
    mgr.ensure_valid_session()
    monkeypatch.setattr(manager_module, "validate_session", lambda url, s: None)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(401, json={"status": "unauthorized"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), auth=SessionAuth(mgr)) as c:
        response = await c.get("https://canvas.example.edu/api/v1/accounts")
    assert response.status_code == 401 and len(calls) == 1


def test_client_parses_while1_prefix():
    from canvas_mcp.core.client import _parse_json

    r = httpx.Response(200, text='while(1);[{"id":1}]')
    assert _parse_json(r) == [{"id": 1}]
    assert _parse_json(httpx.Response(200, json={"a": 1})) == {"a": 1}


def test_update_cookies_persists_refreshed_session(tmp_path):
    _store(tmp_path).save(sess("v1"))
    mgr = SessionManager(make_settings(tmp_path), login_runner=FakeLogin())
    mgr.ensure_valid_session()
    mgr.update_cookies({"_normandy_session": "v2"})
    assert "_normandy_session=v2" in mgr.current.cookie_header()
    assert "_normandy_session=v2" in _store(tmp_path).load().cookie_header()


async def test_session_auth_captures_set_cookie(tmp_path):
    _store(tmp_path).save(sess("v1"))
    mgr = SessionManager(make_settings(tmp_path), login_runner=FakeLogin())
    mgr.ensure_valid_session()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"ok": True},
            headers={"set-cookie": "_normandy_session=v2; path=/; secure; HttpOnly"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), auth=SessionAuth(mgr)) as c:
        await c.get("https://canvas.example.edu/api/v1/courses")
    assert "_normandy_session=v2" in mgr.current.cookie_header()


def test_notify_bark_posts_title_and_body(tmp_path, monkeypatch):
    sent = {}

    def fake_post(url, json=None, timeout=None):
        sent["url"], sent["json"] = url, json

    monkeypatch.setattr(manager_module.httpx, "post", fake_post)
    settings = make_settings(tmp_path, notify_webhook_url="https://api.day.app/DEVKEY/?group=x")
    SessionManager(settings, login_runner=FakeLogin()).notify("Canvas MCP: Enter code 123")
    assert sent["url"] == "https://api.day.app/DEVKEY"
    assert sent["json"]["body"] == "Enter code 123"
    assert sent["json"]["group"] == "canvas-mcp"


def test_notify_generic_webhook(tmp_path, monkeypatch):
    sent = {}
    monkeypatch.setattr(
        manager_module.httpx, "post",
        lambda url, json=None, timeout=None: sent.update(url=url, json=json),
    )
    settings = make_settings(tmp_path, notify_webhook_url="https://ntfy.sh/topic")
    SessionManager(settings, login_runner=FakeLogin()).notify("hello")
    assert sent["json"] == {"text": "hello", "content": "hello"}
