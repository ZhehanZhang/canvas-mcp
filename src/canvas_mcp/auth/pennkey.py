"""Headless PennKey (Penn WebLogin) + Duo login that mints a Canvas token.

Flow, driven by a headless Chromium via Playwright:

1. Open ``<canvas>/login/saml``, which redirects to Penn WebLogin
   (a Shibboleth IdP at ``weblogin.pennkey.upenn.edu``).
2. Submit the PennKey username and password.
3. Complete Duo's Universal Prompt. By default this sends a Duo Push and
   waits for the account owner to approve it on their phone; nothing here
   bypasses or auto-approves the second factor. ``DUO_FACTOR=passcode`` uses
   a one-time passcode the owner supplies instead.
4. Once Canvas has a logged-in session, create a personal access token with
   ``POST /api/v1/users/self/tokens`` (session cookie + CSRF header).

Browser cookies (WebLogin SSO and Duo's "remember this device") are stored
in the auth state dir so later logins usually need fewer Duo prompts.

Playwright is an optional dependency: ``pip install 'canvas-mcp[pennkey]'``
then ``playwright install chromium``.
"""

import json
import re
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from ..core.logging import log_info, log_warning
from .session import CanvasSession
from .settings import AuthSettings
from .token_store import write_private_file

if TYPE_CHECKING:  # pragma: no cover
    from playwright.sync_api import BrowserContext, Page


class LoginError(Exception):
    """The automated login could not be completed."""


class BadCredentialsError(LoginError):
    """WebLogin rejected the PennKey username or password.

    Never retried automatically, to avoid locking the PennKey account.
    """


class DuoError(LoginError):
    """Duo was not approved (denied, timed out, or no factor available)."""


Notifier = Callable[[str], None]

WEBLOGIN_HOST_HINTS = ("weblogin.pennkey.upenn.edu", "/idp/profile/")
DUO_HOST_HINT = "duosecurity.com"

# A headless server has no security key, but Duo picks one as the default
# method when the browser advertises WebAuthn support. Hiding WebAuthn on Duo's
# pages makes Duo fall back to the account's other methods (Duo Push).
DISABLE_WEBAUTHN_ON_DUO = """
if (location.hostname.endsWith('duosecurity.com')) {
  try { delete window.PublicKeyCredential; } catch (e) {}
  try { Object.defineProperty(window, 'PublicKeyCredential', {value: undefined, configurable: true}); } catch (e) {}
  try {
    Object.defineProperty(navigator, 'credentials', {value: undefined, configurable: true});
  } catch (e) {}
}
"""

# Duo Universal Prompt text/selectors. Duo changes its markup occasionally, so
# each step lists several fallbacks and the flow fails with a saved screenshot
# rather than hanging.
DUO_TRUST_YES = ["#trust-browser-button", "button:has-text('Yes, this is my device')"]
DUO_TRUST_NO = ["#dont-trust-browser-button", "button:has-text('No, other people use this device')"]
DUO_OTHER_OPTIONS = [
    "a:has-text('Other options')",
    "button:has-text('Other options')",
    "a:has-text('Other methods')",
    "button:has-text('Other methods')",
]
DUO_CANCEL = ["button:has-text('Cancel')", "a:has-text('Cancel')"]
DUO_PUSH_SENT_TEXT = re.compile(
    r"(check for a duo push|pushed a login request|push sent|sent to .*(phone|iphone|android|ipad)"
    r"|enter (this|the) code|verification code)",
    re.I,
)
DUO_CODE_SELECTORS = [
    ".verification-code",
    "[class*='verification-code']",
    "[data-testid*='verification-code']",
    "[class*='verification'] [class*='code']",
]
DUO_CHOOSE_PUSH = [
    "[data-testid='test-id-push']",
    "button:has-text('Duo Push')",
    "a:has-text('Duo Push')",
    "li:has-text('Duo Push')",
]
DUO_CHOOSE_PASSCODE = [
    "[data-testid='test-id-passcode']",
    "a:has-text('Duo Mobile passcode')",
    "button:has-text('Duo Mobile passcode')",
    "li:has-text('passcode')",
]
DUO_PASSCODE_INPUT = ["#passcode-input", "input[name='passcode-input']", "input[autocomplete='one-time-code']"]
DUO_VERIFY = ["button:has-text('Verify')", "button[type='submit']"]
DUO_SEND_PUSH = ["button:has-text('Send a Push')", "button:has-text('Send Me a Push')"]
DUO_RETRY = ["button:has-text('Try again')", "a:has-text('Try again')", "button:has-text('Send another push')"]
DUO_DENIED_TEXT = re.compile(r"(request was denied|login request denied|you denied)", re.I)
DUO_TIMEOUT_TEXT = re.compile(r"(timed out|time out|took too long)", re.I)
WEBLOGIN_ERROR_TEXT = re.compile(
    r"(incorrect|invalid (pennkey|password|username)|password you entered|unknown user)", re.I
)


def _first_visible(page: "Page", selectors: list[str]) -> Any:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() and locator.is_visible():
                return locator
        except Exception:  # noqa: BLE001 - selector errors on a changing page
            continue
    return None


def chrome_user_agent(browser_version: str) -> str:
    """A regular desktop Chrome user agent for the bundled Chromium version."""
    major = browser_version.split(".", 1)[0] or "141"
    return (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{major}.0.0.0 Safari/537.36"
    )


def _host(url: str) -> str:
    return urlsplit(url).netloc.lower()


class PennKeyLogin:
    """Run one PennKey + Duo login and return a freshly created Canvas token."""

    def __init__(self, settings: AuthSettings, notify: Notifier | None = None) -> None:
        self.settings = settings
        self.notify = notify or (lambda _msg: None)

    # -- public ---------------------------------------------------------------

    def run(self) -> CanvasSession:
        self.settings.require_credentials()
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:  # pragma: no cover - depends on install extras
            raise LoginError(
                "Playwright is not installed. Install with "
                "\"pip install 'canvas-mcp[pennkey]'\" and run \"playwright install chromium\"."
            ) from e

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=self.settings.headless)
            try:
                # Headless Chromium reports itself as "HeadlessChrome", which Duo
                # may treat as an unsupported browser. Present as regular Chrome.
                context_kwargs: dict[str, Any] = {
                    "user_agent": self.settings.user_agent or chrome_user_agent(browser.version),
                }
                if self.settings.browser_state_file.exists():
                    context_kwargs["storage_state"] = str(self.settings.browser_state_file)
                context = browser.new_context(**context_kwargs)
                context.add_init_script(DISABLE_WEBAUTHN_ON_DUO)
                page = context.new_page()
                page.set_default_timeout(self.settings.login_timeout_sec * 1000)
                try:
                    self._login(page)
                    self._save_browser_state(context)
                    session = self._capture_session(context)
                except Exception:
                    self._save_debug(page)
                    raise
                return session
            finally:
                browser.close()

    # -- steps ----------------------------------------------------------------

    def _login(self, page: "Page") -> None:
        s = self.settings
        log_info("PennKey login: opening Canvas SSO")
        page.goto(f"{s.base_url}{s.login_path}", wait_until="domcontentloaded")

        deadline = time.monotonic() + s.login_timeout_sec
        submitted_password = False
        while time.monotonic() < deadline:
            page.wait_for_load_state("domcontentloaded")
            url = page.url
            host = _host(url)

            if self._is_logged_in(page):
                log_info("PennKey login: Canvas session established")
                return

            if DUO_HOST_HINT in host:
                # Duo has its own timeouts; time spent waiting on the phone
                # doesn't count against the page-navigation budget.
                self._handle_duo(page)
                deadline = time.monotonic() + s.login_timeout_sec
                continue

            if any(h in url for h in WEBLOGIN_HOST_HINTS):
                if page.locator("#username").count() and page.locator("#password").count():
                    if submitted_password:
                        body = page.locator("body").inner_text()
                        if WEBLOGIN_ERROR_TEXT.search(body):
                            raise BadCredentialsError(
                                "Penn WebLogin rejected the PennKey username or password"
                            )
                    self._submit_password(page)
                    submitted_password = True
                    continue
                # Shibboleth interstitials (attribute release, "continue") use the same event id.
                proceed = _first_visible(page, ["button[name='_eventId_proceed']", "input[name='_eventId_proceed']"])
                if proceed is not None:
                    proceed.click()
                    continue

            page.wait_for_timeout(1000)

        raise LoginError(f"Timed out during PennKey login (last page: {_host(page.url)})")

    def _is_logged_in(self, page: "Page") -> bool:
        url = page.url
        if _host(url) != self.settings.canvas_host:
            return False
        path = urlsplit(url).path
        if path.startswith("/login") or path.startswith("/saml"):
            return False
        return any(c["name"] == "_csrf_token" for c in page.context.cookies(self.settings.base_url))

    def _submit_password(self, page: "Page") -> None:
        log_info("PennKey login: submitting PennKey credentials")
        page.fill("#username", self.settings.username)
        page.fill("#password", self.settings.password)
        with page.expect_navigation(wait_until="domcontentloaded"):
            page.click("button[name='_eventId_proceed']")

    def _handle_duo(self, page: "Page") -> None:
        s = self.settings
        self._debug_snapshot(page, "duo-start")
        if s.duo_factor == "passcode":
            self._duo_passcode(page)
        else:
            self._duo_push(page)
        self._duo_wait_for_exit(page)
        # Persist Duo's "remember this device" cookie right away, so it survives
        # even if a later step (token creation) fails.
        self._save_browser_state(page.context)

    def _push_in_progress(self, page: "Page") -> bool:
        try:
            body = page.locator("body").inner_text(timeout=2000)
        except Exception:  # noqa: BLE001 - page navigating
            return False
        return bool(DUO_PUSH_SENT_TEXT.search(body))

    def _select_push(self, page: "Page") -> bool:
        """Make Duo send a push. Returns True once a push is pending.

        Penn accounts may default to a security key or another method, so when
        no push is pending go through "Other options" and pick Duo Push.
        """
        for _ in range(10):
            if DUO_HOST_HINT not in _host(page.url):
                return False
            if self._push_in_progress(page):
                return True
            send = _first_visible(page, DUO_SEND_PUSH) or _first_visible(page, DUO_CHOOSE_PUSH)
            if send is not None:
                send.click()
                page.wait_for_timeout(1500)
                continue
            # Security-key (or other) screen: dismiss it and open the method list.
            cancel = _first_visible(page, DUO_CANCEL)
            if cancel is not None:
                cancel.click()
                page.wait_for_timeout(800)
            other = _first_visible(page, DUO_OTHER_OPTIONS)
            if other is not None:
                other.click()
                page.wait_for_timeout(1500)
                self._debug_snapshot(page, "duo-other-options")
                continue
            page.wait_for_timeout(1000)
        return self._push_in_progress(page)

    def _read_verification_code(self, page: "Page") -> str | None:
        """Read Duo Verified Push's on-screen code (3 to 6 digits), if shown."""
        for selector in DUO_CODE_SELECTORS:
            try:
                locator = page.locator(selector).first
                if locator.count() and locator.is_visible():
                    match = re.search(r"\b(\d{3,6})\b", locator.inner_text(timeout=1000))
                    if match:
                        return match.group(1)
            except Exception:  # noqa: BLE001
                continue
        try:
            body = page.locator("body").inner_text(timeout=2000)
        except Exception:  # noqa: BLE001
            return None
        for line in body.splitlines():
            line = line.strip()
            if re.fullmatch(r"\d{3,6}", line):
                return line
        return None

    def _duo_push(self, page: "Page") -> None:
        s = self.settings
        attempts = max(1, s.duo_max_push_attempts)
        for attempt in range(1, attempts + 1):
            page.wait_for_timeout(1500)
            if DUO_HOST_HINT not in _host(page.url) or _first_visible(page, DUO_TRUST_YES) is not None:
                return
            if not self._select_push(page):
                if DUO_HOST_HINT not in _host(page.url):
                    return
                self._debug_snapshot(page, "duo-no-push")
                raise DuoError(
                    "Could not get Duo to send a push (no Duo Push option found). "
                    "Check that Duo Push is enrolled for this PennKey."
                )
            self._debug_snapshot(page, "duo-push-sent")

            code = None
            for _ in range(5):
                code = self._read_verification_code(page)
                if code:
                    break
                page.wait_for_timeout(500)
            if code:
                msg = (
                    f"Canvas MCP: Duo Push sent for {s.username}. "
                    f"Enter code {code} in Duo Mobile to approve "
                    f"(attempt {attempt}/{attempts})."
                )
            else:
                msg = (
                    f"Canvas MCP: Duo Push sent for {s.username}. Approve it in Duo Mobile "
                    f"(attempt {attempt}/{attempts})."
                )
            log_warning(msg)
            self.notify(msg)

            outcome = self._wait_for_push_result(page)
            if outcome == "approved":
                return
            if outcome == "denied":
                raise DuoError("The Duo Push was denied")
            if attempt >= attempts:
                break
            retry = _first_visible(page, DUO_RETRY)
            if retry is not None:
                retry.click()

        raise DuoError(f"Duo Push was not approved after {attempts} attempt(s)")

    def _wait_for_push_result(self, page: "Page") -> str:
        deadline = time.monotonic() + self.settings.duo_timeout_sec
        while time.monotonic() < deadline:
            if DUO_HOST_HINT not in _host(page.url):
                return "approved"
            if _first_visible(page, DUO_TRUST_YES + DUO_TRUST_NO) is not None:
                return "approved"
            try:
                body = page.locator("body").inner_text(timeout=2000)
            except Exception:  # noqa: BLE001 - page navigating away
                body = ""
            if DUO_DENIED_TEXT.search(body):
                return "denied"
            if DUO_TIMEOUT_TEXT.search(body) or _first_visible(page, DUO_RETRY) is not None:
                return "timeout"
            page.wait_for_timeout(1000)
        return "timeout"

    def _duo_passcode(self, page: "Page") -> None:
        passcode = self.settings.duo_passcode
        if not passcode:
            raise DuoError(
                "DUO_FACTOR=passcode but no DUO_PASSCODE was provided; run "
                "'canvas-mcp-server --login' interactively to enter one"
            )
        page.wait_for_timeout(1500)
        field = _first_visible(page, DUO_PASSCODE_INPUT)
        if field is None:
            cancel = _first_visible(page, DUO_CANCEL)
            if cancel is not None:
                cancel.click()
                page.wait_for_timeout(800)
            other = _first_visible(page, DUO_OTHER_OPTIONS)
            if other is not None:
                other.click()
                page.wait_for_timeout(1500)
            choose = _first_visible(page, DUO_CHOOSE_PASSCODE)
            if choose is not None:
                choose.click()
                page.wait_for_timeout(1500)
            field = _first_visible(page, DUO_PASSCODE_INPUT)
        if field is None:
            self._debug_snapshot(page, "duo-no-passcode-field")
            raise DuoError("Could not find Duo's passcode field")
        field.fill(passcode)
        verify = _first_visible(page, DUO_VERIFY)
        if verify is None:
            raise DuoError("Could not find Duo's Verify button")
        verify.click()

    def _duo_wait_for_exit(self, page: "Page") -> None:
        deadline = time.monotonic() + self.settings.duo_timeout_sec
        clicked_trust = False
        while time.monotonic() < deadline and DUO_HOST_HINT in _host(page.url):
            choice = _first_visible(
                page, DUO_TRUST_YES if self.settings.duo_trust_browser else DUO_TRUST_NO
            )
            if choice is not None and not clicked_trust:
                self._debug_snapshot(page, "duo-trust")
                choice.click()
                clicked_trust = True
                log_info(
                    "Duo: answered 'Is this your device?' with "
                    + ("yes (remember this browser)" if self.settings.duo_trust_browser else "no")
                )
            page.wait_for_timeout(1000)
        if DUO_HOST_HINT in _host(page.url):
            self._debug_snapshot(page, "duo-stuck")
            raise DuoError("Duo did not finish after approval")

    def _capture_session(self, context: "BrowserContext") -> CanvasSession:
        """Pull the logged-in Canvas cookies out of the browser context."""
        cookies = [dict(c) for c in context.cookies(self.settings.base_url)]
        session = CanvasSession.from_cookies(cookies)
        if not session.is_usable():
            raise LoginError(
                "Login finished but no Canvas session cookie was found; "
                "the session could not be captured"
            )
        log_info("PennKey login: captured Canvas web session")
        return session

    # -- state ----------------------------------------------------------------

    def _save_browser_state(self, context: "BrowserContext") -> None:
        try:
            write_private_file(
                self.settings.browser_state_file, json.dumps(context.storage_state())
            )
        except Exception as e:  # noqa: BLE001 - best effort
            log_warning("Could not save browser state", error_type=type(e).__name__)

    def _debug_snapshot(self, page: "Page", label: str) -> None:
        """With PENNKEY_DEBUG=true, save a screenshot and Duo's HTML at each Duo step.

        Only Duo pages are saved as HTML; they never contain the PennKey password.
        """
        if not self.settings.debug:
            return
        try:
            debug_dir = self.settings.debug_dir
            debug_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            stem = debug_dir / f"{int(time.time())}-{label}"
            page.screenshot(path=f"{stem}.png", full_page=True)
            if DUO_HOST_HINT in _host(page.url):
                write_private_file(stem.with_suffix(".html"), page.content())
        except Exception:  # noqa: BLE001 - best effort
            pass

    def _save_debug(self, page: "Page") -> None:
        """Save a screenshot of the failing page (no HTML, which can echo credentials)."""
        try:
            debug_dir = self.settings.debug_dir
            debug_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = debug_dir / f"login-failure-{int(time.time())}.png"
            page.screenshot(path=str(path), full_page=True)
            log_warning(f"PennKey login failed; screenshot saved to {path}")
        except Exception:  # noqa: BLE001 - best effort
            pass
