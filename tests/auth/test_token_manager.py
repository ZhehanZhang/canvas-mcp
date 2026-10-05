"""Tests for automated Canvas token lifecycle (CANVAS_AUTH_MODE=pennkey)."""

import os
import stat
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from canvas_mcp.auth import manager as manager_module
from canvas_mcp.auth.canvas_tokens import TokenInvalidError, strip_json_prefix
from canvas_mcp.auth.httpx_auth import ManagedTokenAuth
from canvas_mcp.auth.manager import TokenManager
from canvas_mcp.auth.pennkey import BadCredentialsError, DuoError, LoginError
from canvas_mcp.auth.settings import AuthConfigError, AuthSettings
from canvas_mcp.auth.token_store import StoredToken, TokenStore


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def make_settings(tmp_path: Path, **overrides) -> AuthSettings:
    base = AuthSettings(
        username="pennuser",
        password="secret",
        api_url="https://canvas.example.edu/api/v1",
        login_path="/login/saml",
        state_dir=tmp_path,
        token_lifetime_days=90,
        refresh_margin_hours=72,
        refresh_check_interval_sec=3600,
        duo_factor="push",
        duo_passcode="",
        duo_timeout_sec=5,
        duo_max_push_attempts=2,
        duo_trust_browser=True,
        login_timeout_sec=10,
        login_cooldown_sec=900,
        notify_webhook_url="",
        headless=True,
        token_purpose="canvas-mcp test",
    )
    return replace(base, **overrides)


class FakeLogin:
    def __init__(self, tokens=None, error: Exception | None = None):
        self.calls = 0
        self.tokens = list(tokens or [])
        self.error = error

    def __call__(self, settings, notify):
        self.calls += 1
        if self.error:
            raise self.error
        return self.tokens.pop(0)


def tok(value: str, days: float = 90, token_id: int = 1) -> StoredToken:
    return StoredToken(
        token=value,
        token_id=token_id,
        expires_at=_iso(timedelta(days=days)),
        created_at=_iso(timedelta()),
    )


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("unexpected network call")

    monkeypatch.setattr(manager_module, "check_token", fail)
    monkeypatch.setattr(manager_module, "regenerate_token", fail)


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
    assert settings.duo_factor == "push"
    settings.require_credentials()


def test_settings_rejects_bad_values(monkeypatch):
    monkeypatch.setenv("DUO_FACTOR", "sms-bypass")
    with pytest.raises(AuthConfigError):
        AuthSettings.from_env()
    monkeypatch.setenv("DUO_FACTOR", "push")
    monkeypatch.setenv("CANVAS_TOKEN_LIFETIME_DAYS", "365")
    with pytest.raises(AuthConfigError):
        AuthSettings.from_env()


def test_require_credentials_missing(tmp_path):
    with pytest.raises(AuthConfigError, match="PENNKEY_PASSWORD"):
        make_settings(tmp_path, password="").require_credentials()


# -- store --------------------------------------------------------------------


def test_token_store_roundtrip_is_private(tmp_path):
    store = TokenStore(tmp_path / "state" / "canvas_token.json")
    store.save(tok("abc"))
    mode = stat.S_IMODE(os.stat(store.path).st_mode)
    assert mode == 0o600
    loaded = store.load()
    assert loaded is not None and loaded.token == "abc"
    store.clear()
    assert store.load() is None


def test_stored_token_from_api_requires_full_value():
    with pytest.raises(ValueError):
        StoredToken.from_api({"id": 1, "visible_token": "1~ab..."})
    t = StoredToken.from_api({"id": "7", "visible_token": "1~full", "expires_at": None})
    assert t.token_id == 7 and t.seconds_until_expiry() is None


def test_strip_json_prefix():
    assert strip_json_prefix('while(1);{"a":1}') == '{"a":1}'
    assert strip_json_prefix('{"a":1}') == '{"a":1}'


# -- manager ------------------------------------------------------------------


def test_first_run_logs_in_and_persists(tmp_path):
    login = FakeLogin([tok("fresh")])
    mgr = TokenManager(make_settings(tmp_path), login_runner=login)
    assert mgr.ensure_valid_token() == "fresh"
    assert login.calls == 1
    assert TokenStore(tmp_path / "canvas_token.json").load().token == "fresh"
    # second call reuses without logging in again
    assert mgr.ensure_valid_token() == "fresh"
    assert login.calls == 1


def test_saved_token_reused_without_login(tmp_path):
    TokenStore(tmp_path / "canvas_token.json").save(tok("saved"))
    login = FakeLogin()
    mgr = TokenManager(make_settings(tmp_path), login_runner=login)
    assert mgr.ensure_valid_token() == "saved"
    assert login.calls == 0


def test_near_expiry_regenerates_without_duo(tmp_path, monkeypatch):
    TokenStore(tmp_path / "canvas_token.json").save(tok("old", days=1))
    monkeypatch.setattr(
        manager_module, "regenerate_token", lambda url, cur, days: tok("rotated")
    )
    login = FakeLogin()
    mgr = TokenManager(make_settings(tmp_path), login_runner=login)
    assert mgr.ensure_valid_token() == "rotated"
    assert login.calls == 0
    assert TokenStore(tmp_path / "canvas_token.json").load().token == "rotated"


def test_regenerate_rejected_falls_back_to_login(tmp_path, monkeypatch):
    TokenStore(tmp_path / "canvas_token.json").save(tok("old", days=1))

    def refuse(*a):
        raise TokenInvalidError("401")

    monkeypatch.setattr(manager_module, "regenerate_token", refuse)
    login = FakeLogin([tok("fresh")])
    mgr = TokenManager(make_settings(tmp_path), login_runner=login)
    assert mgr.ensure_valid_token() == "fresh"
    assert login.calls == 1


def test_transient_regenerate_failure_keeps_current(tmp_path, monkeypatch):
    TokenStore(tmp_path / "canvas_token.json").save(tok("old", days=1))

    def boom(*a):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(manager_module, "regenerate_token", boom)
    login = FakeLogin()
    mgr = TokenManager(make_settings(tmp_path), login_runner=login)
    assert mgr.ensure_valid_token() == "old"
    assert login.calls == 0


def test_expired_saved_token_triggers_login(tmp_path):
    TokenStore(tmp_path / "canvas_token.json").save(tok("dead", days=-1))
    login = FakeLogin([tok("fresh")])
    mgr = TokenManager(make_settings(tmp_path), login_runner=login)
    assert mgr.ensure_valid_token() == "fresh"


def test_validate_drops_revoked_token(tmp_path, monkeypatch):
    TokenStore(tmp_path / "canvas_token.json").save(tok("revoked"))

    def reject(url, token):
        raise TokenInvalidError("401")

    monkeypatch.setattr(manager_module, "check_token", reject)
    login = FakeLogin([tok("fresh")])
    mgr = TokenManager(make_settings(tmp_path), login_runner=login)
    assert mgr.ensure_valid_token(validate=True) == "fresh"


def test_failed_login_enters_cooldown(tmp_path):
    login = FakeLogin(error=DuoError("not approved"))
    mgr = TokenManager(make_settings(tmp_path), login_runner=login)
    with pytest.raises(DuoError):
        mgr.ensure_valid_token()
    with pytest.raises(LoginError, match="paused"):
        mgr.ensure_valid_token()
    assert login.calls == 1  # no second Duo push during cooldown


def test_bad_password_disables_auto_login(tmp_path):
    login = FakeLogin(error=BadCredentialsError("wrong password"))
    mgr = TokenManager(make_settings(tmp_path, login_cooldown_sec=0), login_runner=login)
    with pytest.raises(BadCredentialsError):
        mgr.ensure_valid_token()
    with pytest.raises(LoginError, match="disabled"):
        mgr.ensure_valid_token()
    assert login.calls == 1


def test_unexpected_login_exception_wrapped(tmp_path):
    login = FakeLogin(error=RuntimeError("browser crashed"))
    mgr = TokenManager(make_settings(tmp_path), login_runner=login)
    with pytest.raises(LoginError, match="browser crashed"):
        mgr.ensure_valid_token()


def test_unauthorized_permission_error_does_not_relogin(tmp_path, monkeypatch):
    TokenStore(tmp_path / "canvas_token.json").save(tok("good"))
    monkeypatch.setattr(manager_module, "check_token", lambda url, t: {"id": 1})
    login = FakeLogin()
    mgr = TokenManager(make_settings(tmp_path), login_runner=login)
    mgr.ensure_valid_token()
    assert mgr.handle_unauthorized("good") is None
    assert login.calls == 0


def test_unauthorized_revoked_token_relogs(tmp_path, monkeypatch):
    TokenStore(tmp_path / "canvas_token.json").save(tok("revoked"))
    mgr = TokenManager(make_settings(tmp_path), login_runner=FakeLogin([tok("fresh")]))
    mgr.ensure_valid_token()

    def reject(url, token):
        raise TokenInvalidError("401")

    monkeypatch.setattr(manager_module, "check_token", reject)
    assert mgr.handle_unauthorized("revoked") == "fresh"


def test_unauthorized_with_stale_token_returns_current(tmp_path):
    TokenStore(tmp_path / "canvas_token.json").save(tok("newer"))
    mgr = TokenManager(make_settings(tmp_path), login_runner=FakeLogin())
    mgr.ensure_valid_token()
    assert mgr.handle_unauthorized("older") == "newer"


def test_token_published_to_config(tmp_path):
    from canvas_mcp.core.config import get_config

    mgr = TokenManager(make_settings(tmp_path), login_runner=FakeLogin([tok("pub")]))
    mgr.ensure_valid_token()
    assert get_config().canvas_api_token == "pub"


def test_get_token_manager_respects_mode(monkeypatch, tmp_path):
    from canvas_mcp.auth import get_token_manager, reset_token_manager

    reset_token_manager()
    monkeypatch.setenv("CANVAS_AUTH_MODE", "token")
    assert get_token_manager() is None
    monkeypatch.setenv("CANVAS_AUTH_MODE", "pennkey")
    monkeypatch.setenv("CANVAS_AUTH_STATE_DIR", str(tmp_path))
    try:
        assert isinstance(get_token_manager(), TokenManager)
    finally:
        reset_token_manager()


# -- httpx auth ---------------------------------------------------------------


async def test_managed_auth_retries_once_on_401(tmp_path, monkeypatch):
    TokenStore(tmp_path / "canvas_token.json").save(tok("revoked"))
    mgr = TokenManager(make_settings(tmp_path), login_runner=FakeLogin([tok("fresh")]))

    def reject(url, token):
        raise TokenInvalidError("401")

    monkeypatch.setattr(manager_module, "check_token", reject)
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers["Authorization"]
        seen.append(auth)
        if auth == "Bearer revoked":
            return httpx.Response(401, json={"errors": [{"message": "Invalid access token."}]})
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), auth=ManagedTokenAuth(mgr)
    ) as client:
        response = await client.get("https://canvas.example.edu/api/v1/courses")
    assert response.status_code == 200
    assert seen == ["Bearer revoked", "Bearer fresh"]


async def test_managed_auth_passes_through_permission_401(tmp_path, monkeypatch):
    TokenStore(tmp_path / "canvas_token.json").save(tok("good"))
    mgr = TokenManager(make_settings(tmp_path), login_runner=FakeLogin())
    monkeypatch.setattr(manager_module, "check_token", lambda url, t: {"id": 1})
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(401, json={"status": "unauthorized"})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), auth=ManagedTokenAuth(mgr)
    ) as client:
        response = await client.get("https://canvas.example.edu/api/v1/accounts")
    assert response.status_code == 401
    assert len(calls) == 1


def test_on_notify_receives_login_messages(tmp_path):
    seen = []

    def login(settings, notify):
        notify("Enter code 123 in Duo Mobile")
        return tok("fresh")

    mgr = TokenManager(make_settings(tmp_path), login_runner=login, on_notify=seen.append)
    mgr.ensure_valid_token()
    assert seen == ["Enter code 123 in Duo Mobile"]
