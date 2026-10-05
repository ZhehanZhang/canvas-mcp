"""The Canvas web-login session used to authenticate API calls.

Penn does not allow accounts to create personal access tokens, so instead of
a bearer token the server authenticates with the cookies from a real Canvas
web login (the same session a browser would use). For GET requests the session
cookie is enough; Canvas requires an ``X-CSRF-Token`` header (matching the
``_csrf_token`` cookie) on POST/PUT/DELETE.

Sessions have no client-visible expiry and cannot be refreshed with a token,
so when Canvas rejects the session the only remedy is another PennKey + Duo
login. The saved WebLogin and Duo "remember this device" cookies usually make
that login prompt-free.

The session is stored at ``<state_dir>/canvas_session.json`` with 0600
permissions. Mount ``state_dir`` on a volume so a container restart reuses it.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

# Canvas' session cookie name varies by deployment; these are the ones Canvas
# sets for a logged-in web session. Any of them means "logged in".
SESSION_COOKIE_NAMES = ("_normandy_session", "canvas_session", "_legacy_normandy_session")
CSRF_COOKIE_NAME = "_csrf_token"


def strip_json_prefix(text: str) -> str:
    """Remove Canvas' ``while(1);`` anti-hijacking prefix from session-auth JSON."""
    prefix = "while(1);"
    return text[len(prefix):] if text.startswith(prefix) else text


@dataclass
class CanvasSession:
    """Cookies from a logged-in Canvas web session."""

    cookies: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = ""

    @classmethod
    def from_cookies(cls, cookies: list[dict[str, Any]]) -> "CanvasSession":
        return cls(
            cookies=[
                {"name": c["name"], "value": c["value"], "domain": c.get("domain", ""),
                 "path": c.get("path", "/")}
                for c in cookies
            ],
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def _value(self, name: str) -> str:
        for c in self.cookies:
            if c["name"] == name:
                return str(c["value"])
        return ""

    def has_session_cookie(self) -> bool:
        return any(self._value(name) for name in SESSION_COOKIE_NAMES)

    def cookie_header(self) -> str:
        """``name=value; ...`` for the HTTP Cookie request header."""
        return "; ".join(f"{c['name']}={c['value']}" for c in self.cookies if c["value"])

    def csrf_token(self) -> str:
        """The URL-decoded CSRF token Canvas expects in ``X-CSRF-Token``."""
        return unquote(self._value(CSRF_COOKIE_NAME))

    def with_updates(self, updates: dict[str, str]) -> "CanvasSession":
        """Return a copy with cookie values replaced/added from ``Set-Cookie``."""
        if not updates:
            return self
        cookies = [dict(c) for c in self.cookies]
        names = {c["name"] for c in cookies}
        for c in cookies:
            if c["name"] in updates:
                c["value"] = updates[c["name"]]
        for name, value in updates.items():
            if name not in names:
                cookies.append({"name": name, "value": value, "domain": "", "path": "/"})
        return CanvasSession(cookies=cookies, created_at=self.created_at)

    def is_usable(self) -> bool:
        return self.has_session_cookie() and bool(self.cookie_header())


class SessionStore:
    """Load and save a :class:`CanvasSession` as JSON (0600)."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> CanvasSession | None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            session = CanvasSession(
                cookies=list(data.get("cookies", [])),
                created_at=data.get("created_at", ""),
            )
            return session if session.is_usable() else None
        except (OSError, ValueError, TypeError):
            return None

    def save(self, session: CanvasSession) -> None:
        from .token_store import write_private_file

        write_private_file(self.path, json.dumps({
            "cookies": session.cookies,
            "created_at": session.created_at,
        }, indent=2))

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
