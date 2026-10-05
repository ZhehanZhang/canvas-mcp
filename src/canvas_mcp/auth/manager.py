"""Keeps a valid Canvas token available when ``CANVAS_AUTH_MODE=pennkey``.

Token lifecycle:

* On startup, reuse the token saved in the state dir if Canvas still accepts it.
* Before it expires (``CANVAS_TOKEN_REFRESH_MARGIN_HOURS``), rotate it with
  Canvas' regenerate API. This uses the token itself, so no Duo prompt.
* Only when there is no usable token (first run, revoked, or expired while the
  server was down) run the full PennKey + Duo login, which asks the owner to
  approve a Duo Push.
* Failed logins back off for ``PENNKEY_LOGIN_COOLDOWN_SEC`` so a broken setup
  never spams the owner's phone, and a wrong password stops automatic logins
  entirely until restart (protects the PennKey from lockout).

All methods are synchronous and thread-safe; async callers use
``asyncio.to_thread``. A daemon thread re-checks expiry periodically so an
idle server still rotates its token in time.
"""

import threading
import time
from collections.abc import Callable

import httpx

from ..core.logging import log_error, log_info, log_warning
from .canvas_tokens import TokenInvalidError, check_token, regenerate_token
from .pennkey import BadCredentialsError, LoginError, PennKeyLogin
from .settings import AuthSettings, get_auth_mode
from .token_store import StoredToken, TokenStore

LoginRunner = Callable[[AuthSettings, Callable[[str], None]], StoredToken]


def _default_login(settings: AuthSettings, notify: Callable[[str], None]) -> StoredToken:
    return PennKeyLogin(settings, notify=notify).run()


class TokenManager:
    def __init__(
        self,
        settings: AuthSettings,
        login_runner: LoginRunner = _default_login,
        store: TokenStore | None = None,
    ) -> None:
        self.settings = settings
        self._login_runner = login_runner
        self._store = store or TokenStore(settings.token_file)
        self._lock = threading.RLock()
        self._current: StoredToken | None = None
        self._loaded = False
        self._login_blocked_until = 0.0
        self._login_disabled_reason = ""
        self._refresh_thread: threading.Thread | None = None
        self._stop = threading.Event()

    # -- queries --------------------------------------------------------------

    @property
    def current(self) -> StoredToken | None:
        return self._current

    def current_token(self) -> str | None:
        return self._current.token if self._current else None

    def needs_refresh(self) -> bool:
        current = self._current
        if current is None:
            return True
        remaining = current.seconds_until_expiry()
        if remaining is None:
            return False
        return remaining < self.settings.refresh_margin_hours * 3600

    # -- lifecycle ------------------------------------------------------------

    def ensure_valid_token(self, validate: bool = False) -> str:
        """Return a usable token, refreshing or logging in if needed."""
        with self._lock:
            if not self._loaded:
                self._current = self._store.load()
                self._loaded = True
                if self._current is not None:
                    log_info("Loaded saved Canvas token", token_id=self._current.token_id)
                    self._publish(self._current)

            current = self._current
            if current is not None:
                remaining = current.seconds_until_expiry()
                if remaining is not None and remaining <= 0:
                    log_warning("Saved Canvas token has expired")
                    self._discard()
                elif validate:
                    try:
                        check_token(self.settings.api_url, current.token)
                    except TokenInvalidError:
                        log_warning("Saved Canvas token was rejected by Canvas")
                        self._discard()
                    except httpx.HTTPError as e:
                        log_warning(
                            "Could not validate saved Canvas token; keeping it",
                            error_type=type(e).__name__,
                        )

            if self._current is not None and self.needs_refresh():
                self._try_regenerate()

            if self._current is None:
                self._login()

            assert self._current is not None
            return self._current.token

    def handle_unauthorized(self, failed_token: str) -> str | None:
        """React to a 401. Returns a new token to retry with, or None.

        Canvas also answers 401 for permission errors, so the token is only
        replaced when ``/users/self`` rejects it too.
        """
        with self._lock:
            current = self._current
            if current is not None and current.token != failed_token:
                return current.token  # another caller already rotated it
            if current is not None:
                try:
                    check_token(self.settings.api_url, current.token)
                    return None  # token is fine; the 401 was a permission error
                except TokenInvalidError:
                    log_warning("Canvas token was rejected; obtaining a new one")
                    self._discard()
                except httpx.HTTPError:
                    return None
            try:
                return self.ensure_valid_token()
            except LoginError as e:
                log_error(f"Could not obtain a new Canvas token: {e}")
                return None

    def login(self) -> str:
        """Force a full PennKey + Duo login (used by ``--login``)."""
        with self._lock:
            self._loaded = True
            self._login_blocked_until = 0.0
            self._login()
            assert self._current is not None
            return self._current.token

    # -- background refresh ---------------------------------------------------

    def start_background_refresh(self) -> None:
        if self._refresh_thread is not None and self._refresh_thread.is_alive():
            return
        self._stop.clear()
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop, name="canvas-token-refresh", daemon=True
        )
        self._refresh_thread.start()

    def stop_background_refresh(self) -> None:
        self._stop.set()

    def _refresh_loop(self) -> None:
        while not self._stop.wait(self.settings.refresh_check_interval_sec):
            try:
                if self.needs_refresh():
                    self.ensure_valid_token()
            except Exception as e:  # noqa: BLE001 - keep the thread alive
                log_error(f"Background Canvas token refresh failed: {e}")

    # -- internals ------------------------------------------------------------

    def _try_regenerate(self) -> None:
        current = self._current
        assert current is not None
        try:
            new_token = regenerate_token(
                self.settings.api_url, current, self.settings.token_lifetime_days
            )
        except TokenInvalidError as e:
            log_warning(f"Could not regenerate Canvas token: {e}")
            self._discard()
            return
        except httpx.HTTPError as e:
            # Transient failure: keep using the current token until it expires.
            log_warning("Canvas token regeneration failed; will retry", error_type=type(e).__name__)
            return
        log_info("Regenerated Canvas token", expires_at=new_token.expires_at)
        self._set(new_token)

    def _login(self) -> None:
        if self._login_disabled_reason:
            raise LoginError(self._login_disabled_reason)
        now = time.monotonic()
        if now < self._login_blocked_until:
            wait = int(self._login_blocked_until - now)
            raise LoginError(
                f"Automatic PennKey login is paused for {wait}s after a failed attempt"
            )
        log_info("Starting automated PennKey + Duo login for a new Canvas token")
        try:
            new_token = self._login_runner(self.settings, self.notify)
        except BadCredentialsError as e:
            self._login_disabled_reason = (
                f"{e}. Automatic login is disabled until the server restarts with corrected credentials."
            )
            self.notify(f"Canvas MCP: {self._login_disabled_reason}")
            raise
        except Exception as e:
            self._login_blocked_until = time.monotonic() + self.settings.login_cooldown_sec
            self.notify(f"Canvas MCP: automated Canvas login failed ({e}).")
            if isinstance(e, LoginError):
                raise
            raise LoginError(f"{type(e).__name__}: {e}") from e
        self._set(new_token)

    def _set(self, token: StoredToken) -> None:
        self._current = token
        try:
            self._store.save(token)
        except OSError as e:
            log_warning(f"Could not persist Canvas token to {self._store.path}: {e}")
        self._publish(token)

    def _discard(self) -> None:
        self._current = None
        self._store.clear()

    @staticmethod
    def _publish(token: StoredToken) -> None:
        """Expose the token to code that reads it from config (e.g. code execution)."""
        from ..core.config import get_config

        get_config().canvas_api_token = token.token

    def notify(self, message: str) -> None:
        url = self.settings.notify_webhook_url
        if not url:
            return
        try:
            # "text" is read by Slack/Teams-style hooks, "content" by Discord;
            # ntfy.sh shows the raw body.
            httpx.post(url, json={"text": message, "content": message}, timeout=10)
        except httpx.HTTPError as e:
            log_warning("Auth notification webhook failed", error_type=type(e).__name__)


_manager: TokenManager | None = None
_manager_lock = threading.Lock()


def is_auto_auth_enabled() -> bool:
    return get_auth_mode() == "pennkey"


def get_token_manager() -> TokenManager | None:
    """Return the process-wide manager, or None when using a static token."""
    global _manager
    if not is_auto_auth_enabled():
        return None
    with _manager_lock:
        if _manager is None:
            _manager = TokenManager(AuthSettings.from_env())
        return _manager


def reset_token_manager() -> None:
    """Testing hook."""
    global _manager
    with _manager_lock:
        if _manager is not None:
            _manager.stop_background_refresh()
        _manager = None
