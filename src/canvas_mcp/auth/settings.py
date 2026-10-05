"""Settings for automated (headless) Canvas web-session login (PennKey + Duo).

Everything is read from environment variables. Secrets can be supplied either
directly (``PENNKEY_PASSWORD``) or via a file path (``PENNKEY_PASSWORD_FILE``),
which is how Docker/Kubernetes secrets are usually mounted.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_PENN_CANVAS_API_URL = "https://canvas.upenn.edu/api/v1"
VALID_AUTH_MODES = frozenset({"token", "pennkey"})
VALID_DUO_FACTORS = frozenset({"push", "passcode"})


class AuthConfigError(ValueError):
    """Raised when automated-auth settings are missing or invalid."""


def read_secret(name: str) -> str:
    """Read ``NAME`` from the environment, falling back to the file at ``NAME_FILE``."""
    value = os.getenv(name, "")
    if value:
        return value
    file_path = os.getenv(f"{name}_FILE", "")
    if file_path:
        try:
            return Path(file_path).read_text(encoding="utf-8").strip()
        except OSError as e:
            raise AuthConfigError(f"Could not read {name}_FILE ({file_path}): {e}") from e
    return ""


def _int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as e:
        raise AuthConfigError(f"{name} must be an integer (got '{raw}')") from e


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def get_auth_mode() -> str:
    """Return the configured auth mode (``token`` or ``pennkey``)."""
    return os.getenv("CANVAS_AUTH_MODE", "token").strip().lower() or "token"


@dataclass(frozen=True)
class AuthSettings:
    """Resolved settings for PennKey + Duo automated login."""

    username: str
    password: str
    api_url: str
    login_path: str
    state_dir: Path
    refresh_check_interval_sec: int
    duo_factor: str
    duo_passcode: str
    duo_timeout_sec: int
    duo_max_push_attempts: int
    duo_trust_browser: bool
    login_timeout_sec: int
    login_cooldown_sec: int
    notify_webhook_url: str
    headless: bool
    debug: bool = False
    user_agent: str = ""

    @property
    def base_url(self) -> str:
        """Canvas web origin, e.g. ``https://canvas.upenn.edu``."""
        parts = urlsplit(self.api_url)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def canvas_host(self) -> str:
        return urlsplit(self.api_url).netloc.lower()

    @property
    def session_file(self) -> Path:
        return self.state_dir / "canvas_session.json"

    @property
    def browser_state_file(self) -> Path:
        return self.state_dir / "browser_state.json"

    @property
    def debug_dir(self) -> Path:
        return self.state_dir / "debug"

    @classmethod
    def from_env(cls) -> "AuthSettings":
        username = read_secret("PENNKEY_USERNAME")
        password = read_secret("PENNKEY_PASSWORD")
        api_url = os.getenv("CANVAS_API_URL", "").strip() or DEFAULT_PENN_CANVAS_API_URL

        duo_factor = os.getenv("DUO_FACTOR", "push").strip().lower() or "push"
        if duo_factor not in VALID_DUO_FACTORS:
            raise AuthConfigError(
                f"DUO_FACTOR must be one of {', '.join(sorted(VALID_DUO_FACTORS))} (got '{duo_factor}')"
            )

        check_interval = _int("CANVAS_SESSION_CHECK_SEC", 900)
        if check_interval < 60:
            raise AuthConfigError("CANVAS_SESSION_CHECK_SEC must be at least 60")

        default_state = Path(os.getenv("HOME", ".")) / ".canvas-mcp"
        state_dir = Path(os.getenv("CANVAS_AUTH_STATE_DIR", "").strip() or default_state)

        login_path = os.getenv("CANVAS_LOGIN_PATH", "/login/saml").strip() or "/login/saml"
        if not login_path.startswith("/"):
            login_path = f"/{login_path}"

        return cls(
            username=username,
            password=password,
            api_url=api_url.rstrip("/"),
            login_path=login_path,
            state_dir=state_dir,
            refresh_check_interval_sec=check_interval,
            duo_factor=duo_factor,
            duo_passcode=read_secret("DUO_PASSCODE"),
            duo_timeout_sec=_int("DUO_TIMEOUT_SEC", 90),
            duo_max_push_attempts=_int("DUO_MAX_PUSH_ATTEMPTS", 2),
            duo_trust_browser=_bool("DUO_TRUST_BROWSER", True),
            login_timeout_sec=_int("PENNKEY_LOGIN_TIMEOUT_SEC", 60),
            login_cooldown_sec=_int("PENNKEY_LOGIN_COOLDOWN_SEC", 900),
            notify_webhook_url=read_secret("AUTH_NOTIFY_WEBHOOK_URL"),
            headless=_bool("PENNKEY_HEADLESS", True),
            debug=_bool("PENNKEY_DEBUG", False),
            user_agent=os.getenv("PENNKEY_USER_AGENT", "").strip(),
        )

    def require_credentials(self) -> None:
        """Raise if a full PennKey login is impossible with the current settings."""
        missing = [
            name
            for name, value in (
                ("PENNKEY_USERNAME", self.username),
                ("PENNKEY_PASSWORD", self.password),
            )
            if not value
        ]
        if missing:
            raise AuthConfigError(
                f"{' and '.join(missing)} must be set (directly or via *_FILE) for CANVAS_AUTH_MODE=pennkey"
            )
