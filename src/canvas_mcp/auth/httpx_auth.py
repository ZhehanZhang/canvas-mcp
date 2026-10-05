"""httpx auth hook that pulls the bearer token from the :class:`TokenManager`."""

import asyncio
from collections.abc import AsyncGenerator

import httpx

from .manager import TokenManager


class ManagedTokenAuth(httpx.Auth):
    """Attach the current managed token; on 401, refresh once and retry."""

    def __init__(self, manager: TokenManager) -> None:
        self.manager = manager

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        token = self.manager.current_token()
        if token is None or self.manager.needs_refresh():
            token = await asyncio.to_thread(self.manager.ensure_valid_token)
        request.headers["Authorization"] = f"Bearer {token}"
        response = yield request

        if response.status_code != 401:
            return
        new_token = await asyncio.to_thread(self.manager.handle_unauthorized, token)
        if new_token is None or new_token == token:
            return
        request.headers["Authorization"] = f"Bearer {new_token}"
        yield request
