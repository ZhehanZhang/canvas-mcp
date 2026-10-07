"""httpx auth hook that authenticates with the managed Canvas web session."""

import asyncio
from collections.abc import AsyncGenerator
from urllib.parse import urlsplit

import httpx

from .manager import SessionManager
from .session import CanvasSession

# Canvas requires a CSRF header on state-changing requests made with a session.
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _apply(request: httpx.Request, session: CanvasSession) -> None:
    request.headers["Cookie"] = session.cookie_header()
    request.headers.setdefault("Accept", "application/json")
    if request.method.upper() in _UNSAFE_METHODS:
        request.headers["X-CSRF-Token"] = session.csrf_token()
    else:
        request.headers.pop("X-CSRF-Token", None)


def _is_login_redirect(response: httpx.Response) -> bool:
    if not 300 <= response.status_code < 400:
        return False
    location = response.headers.get("location", "")
    return "/login" in urlsplit(location).path or "weblogin" in location


class SessionAuth(httpx.Auth):
    """Attach the session cookies; on an expired session, re-login once and retry."""

    def __init__(self, manager: SessionManager) -> None:
        self.manager = manager

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        session = self.manager.current_session()
        if session is None:
            session = await asyncio.to_thread(self.manager.ensure_valid_session)
        _apply(request, session)
        response = yield request

        if response.status_code != 401 and not _is_login_redirect(response):
            # Keep cookies Canvas refreshed so activity extends the session.
            refreshed = dict(response.cookies)
            if refreshed:
                await asyncio.to_thread(self.manager.update_cookies, refreshed)
            return
        new_session = await asyncio.to_thread(
            self.manager.handle_unauthorized, session.cookie_header()
        )
        if new_session is None or new_session.cookie_header() == session.cookie_header():
            return
        _apply(request, new_session)
        yield request
