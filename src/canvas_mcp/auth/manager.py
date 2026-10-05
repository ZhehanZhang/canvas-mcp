"""Keeps a valid Canvas web session available when ``CANVAS_AUTH_MODE=pennkey``.

Session lifecycle:

* On startup, reuse the session saved in the state dir if Canvas still accepts
  its cookies.
* There is no token to rotate, so when Canvas rejects the session (it expired,
  or the server was down past its lifetime) the server runs the full PennKey +
  Duo login again. The saved WebLogin and Duo "remember this device" cookies
  usually make that prompt-free.
* A background thread revalidates periodically so an idle server notices an
  expired session and re-logs-in before the next real request needs it.
* Failed logins back off for ``PENNKEY_LOGIN_COOLDOWN_SEC`` so a broken setup
  never spams the owner's phone, and a wrong password stops automatic logins
  entirely until restart (protects the PennKey from lockout).

All methods are synchronous and thread-safe; async callers use
``asyncio.to_thread``.
"""

import threading
import time
from collections.abc import Callable

import httpx

from ..core.logging import log_error, log_info, log_warning
from .pennkey import BadCredentialsError, LoginError, PennKeyLogin
from .session import CanvasSession, SessionStore
from .settings import AuthSettings, get_auth_mode

LoginRunner = Callable[[AuthSettings, Callable[[str], None]], CanvasSession]


class SessionInvalidError(Exception):
    """Canvas rejected the web session (expired or signed out)."""


def _default_login(settings: AuthSettings, notify: Callable[[str], None]) -> CanvasSession:
    return PennKeyLogin(settings, notify=notify).run()


def validate_session(
    api_url: str, session: CanvasSession, timeout: float = 30
) -> dict[str, str]:
    """Call ``/users/self`` with the session cookies; raise if Canvas rejects them.

    Returns any cookies Canvas refreshed via ``Set-Cookie`` (Canvas extends
    the session on activity), so the caller can keep them.
    """
    response = httpx.get(
        f"{api_url}/users/self",
        headers={"Cookie": session.cookie_header(), "Accept": "application/json"},
        timeout=timeout,
        follow_redirects=False,
    )
    # A valid API session returns 200. An expired one returns 401, or a 302 to
    # the login page.
    if response.status_code in (401, 403) or 300 <= response.status_code < 400:
        raise SessionInvalidError(f"Canvas rejected the session (HTTP {response.status_code})")
    response.raise_for_status()
    return dict(response.cookies)


class SessionManager:
    def __init__(
        self,
        settings: AuthSettings,
        login_runner: LoginRunner = _default_login,
        store: SessionStore | None = None,
        on_notify: Callable[[str], None] | None = None,
    ) -> None:
        self.settings = settings
        self._on_notify = on_notify
        self._login_runner = login_runner
        self._store = store or SessionStore(settings.session_file)
        self._lock = threading.RLock()
        self._current: CanvasSession | None = None
        self._loaded = False
        self._login_blocked_until = 0.0
        self._login_disabled_reason = ""
        self._refresh_thread: threading.Thread | None = None
        self._stop = threading.Event()

    # -- queries --------------------------------------------------------------

    @property
    def current(self) -> CanvasSession | None:
        return self._current

    def current_session(self) -> CanvasSession | None:
        return self._current

    # -- lifecycle ------------------------------------------------------------

    def ensure_valid_session(self, validate: bool = False) -> CanvasSession:
        """Return a usable session, validating or logging in if needed."""
        with self._lock:
            if not self._loaded:
                self._current = self._store.load()
                self._loaded = True
                if self._current is not None:
                    log_info("Loaded saved Canvas session")

            if self._current is not None and validate:
                try:
                    refreshed = validate_session(self.settings.api_url, self._current)
                    self.update_cookies(refreshed or {})
                except SessionInvalidError:
                    log_warning("Saved Canvas session is no longer valid")
                    self._discard()
                except httpx.HTTPError as e:
                    log_warning(
                        "Could not validate saved Canvas session; keeping it",
                        error_type=type(e).__name__,
                    )

            if self._current is None:
                self._login()

            assert self._current is not None
            return self._current

    def handle_unauthorized(self, failed_marker: str) -> CanvasSession | None:
        """React to a 401. Returns a new session to retry with, or None.

        Canvas also answers 401 for permission errors, so the session is only
        replaced when ``/users/self`` rejects it too. ``failed_marker`` is the
        cookie header the failing request used, so a session another caller
        already refreshed is detected and reused instead of logging in again.
        """
        with self._lock:
            current = self._current
            if current is not None and current.cookie_header() != failed_marker:
                return current  # already refreshed by another caller
            if current is not None:
                try:
                    validate_session(self.settings.api_url, current)
                    return None  # session is fine; the 401 was a permission error
                except SessionInvalidError:
                    log_warning("Canvas session was rejected; signing in again")
                    self._discard()
                except httpx.HTTPError:
                    return None
            try:
                return self.ensure_valid_session()
            except LoginError as e:
                log_error(f"Could not obtain a new Canvas session: {e}")
                return None

    def update_cookies(self, updates: dict[str, str]) -> None:
        """Merge cookies Canvas refreshed via ``Set-Cookie`` into the session.

        Keeping the refreshed session cookie is what lets activity (including
        the background check) extend the session instead of it expiring and
        needing another Duo login.
        """
        if not updates:
            return
        with self._lock:
            if self._current is None:
                return
            updated = self._current.with_updates(updates)
            if updated.cookie_header() != self._current.cookie_header():
                self._set(updated)

    def login(self) -> CanvasSession:
        """Force a full PennKey + Duo login (used by ``--login``)."""
        with self._lock:
            self._loaded = True
            self._login_blocked_until = 0.0
            self._login()
            assert self._current is not None
            return self._current

    # -- background refresh ---------------------------------------------------

    def start_background_refresh(self) -> None:
        if self._refresh_thread is not None and self._refresh_thread.is_alive():
            return
        self._stop.clear()
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop, name="canvas-session-refresh", daemon=True
        )
        self._refresh_thread.start()

    def stop_background_refresh(self) -> None:
        self._stop.set()

    def _refresh_loop(self) -> None:
        while not self._stop.wait(self.settings.refresh_check_interval_sec):
            try:
                if self._current is not None:
                    self.ensure_valid_session(validate=True)
            except Exception as e:  # noqa: BLE001 - keep the thread alive
                log_error(f"Background Canvas session check failed: {e}")

    # -- internals ------------------------------------------------------------

    def _login(self) -> None:
        if self._login_disabled_reason:
            raise LoginError(self._login_disabled_reason)
        now = time.monotonic()
        if now < self._login_blocked_until:
            wait = int(self._login_blocked_until - now)
            raise LoginError(
                f"Automatic PennKey login is paused for {wait}s after a failed attempt"
            )
        log_info("Starting automated PennKey + Duo login for a new Canvas session")
        try:
            session = self._login_runner(self.settings, self.notify)
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
        self._set(session)

    def _set(self, session: CanvasSession) -> None:
        self._current = session
        try:
            self._store.save(session)
        except OSError as e:
            log_warning(f"Could not persist Canvas session to {self._store.path}: {e}")

    def _discard(self) -> None:
        self._current = None
        self._store.clear()

    def notify(self, message: str) -> None:
        if self._on_notify is not None:
            self._on_notify(message)
        url = self.settings.notify_webhook_url
        if not url:
            return
        try:
            # "text" is read by Slack/Teams-style hooks, "content" by Discord;
            # ntfy.sh shows the raw body.
            httpx.post(url, json={"text": message, "content": message}, timeout=10)
        except httpx.HTTPError as e:
            log_warning("Auth notification webhook failed", error_type=type(e).__name__)


_manager: SessionManager | None = None
_manager_lock = threading.Lock()


def is_auto_auth_enabled() -> bool:
    return get_auth_mode() == "pennkey"


def get_session_manager() -> SessionManager | None:
    """Return the process-wide manager, or None when using a static token."""
    global _manager
    if not is_auto_auth_enabled():
        return None
    with _manager_lock:
        if _manager is None:
            _manager = SessionManager(AuthSettings.from_env())
        return _manager


def reset_session_manager() -> None:
    """Testing hook."""
    global _manager
    with _manager_lock:
        if _manager is not None:
            _manager.stop_background_refresh()
        _manager = None

