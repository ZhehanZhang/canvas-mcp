"""Canvas access-token API calls that authenticate with an existing token.

Canvas lets a manually created token regenerate itself
(``PUT /api/v1/users/self/tokens/:id`` with ``token[regenerate]=1``), so as
long as the current token is still valid it can be rotated without a new
PennKey + Duo login.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from .token_store import StoredToken


class TokenInvalidError(Exception):
    """The Canvas token was rejected (expired, revoked, or deleted)."""


def strip_json_prefix(text: str) -> str:
    """Remove Canvas' ``while(1);`` anti-hijacking prefix from session-auth JSON."""
    prefix = "while(1);"
    return text[len(prefix):] if text.startswith(prefix) else text


def expiry_iso(lifetime_days: int, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return (now + timedelta(days=lifetime_days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_token(api_url: str, token: str, timeout: float = 30) -> dict[str, Any]:
    """Return ``/users/self`` for ``token``; raise :class:`TokenInvalidError` on 401."""
    response = httpx.get(
        f"{api_url}/users/self",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    if response.status_code == 401:
        raise TokenInvalidError("Canvas rejected the token (401)")
    response.raise_for_status()
    result: dict[str, Any] = response.json()
    return result


def regenerate_token(
    api_url: str,
    current: StoredToken,
    lifetime_days: int,
    timeout: float = 30,
) -> StoredToken:
    """Rotate ``current`` into a fresh token with a new expiry date."""
    if current.token_id is None:
        raise TokenInvalidError("Token id unknown; cannot regenerate in place")
    response = httpx.put(
        f"{api_url}/users/self/tokens/{current.token_id}",
        headers={"Authorization": f"Bearer {current.token}"},
        data={
            "token[regenerate]": "1",
            "token[expires_at]": expiry_iso(lifetime_days),
        },
        timeout=timeout,
    )
    if response.status_code in (401, 403, 404):
        raise TokenInvalidError(
            f"Canvas refused to regenerate the token (HTTP {response.status_code})"
        )
    response.raise_for_status()
    return StoredToken.from_api(response.json())
