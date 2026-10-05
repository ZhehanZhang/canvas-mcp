"""On-disk persistence for the automatically managed Canvas token.

The token is written to ``<state_dir>/canvas_token.json`` with 0600
permissions. In a container, mount ``state_dir`` on a volume so a restart
reuses the token instead of triggering a new PennKey + Duo login.
"""

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class StoredToken:
    """A Canvas personal access token and the metadata needed to refresh it."""

    token: str
    token_id: int | None
    expires_at: str | None  # ISO 8601, UTC
    created_at: str

    def expires_at_dt(self) -> datetime | None:
        if not self.expires_at:
            return None
        value = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value

    def seconds_until_expiry(self, now: datetime | None = None) -> float | None:
        expires = self.expires_at_dt()
        if expires is None:
            return None
        now = now or datetime.now(timezone.utc)
        return (expires - now).total_seconds()

    @classmethod
    def from_api(cls, payload: dict[str, Any]) -> "StoredToken":
        """Build from a Canvas ``Token`` API object (create/regenerate response)."""
        token = payload.get("visible_token") or payload.get("token") or ""
        if not token or token.endswith("..."):
            raise ValueError("Canvas did not return the full token value")
        raw_id = payload.get("id")
        return cls(
            token=token,
            token_id=int(raw_id) if raw_id is not None else None,
            expires_at=payload.get("expires_at"),
            created_at=datetime.now(timezone.utc).isoformat(),
        )


def _write_private(path: Path, content: str) -> None:
    """Atomically write ``content`` to ``path`` readable only by the owner."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class TokenStore:
    """Load and save a :class:`StoredToken` as JSON."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> StoredToken | None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return StoredToken(
                token=data["token"],
                token_id=data.get("token_id"),
                expires_at=data.get("expires_at"),
                created_at=data.get("created_at", ""),
            )
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def save(self, token: StoredToken) -> None:
        _write_private(self.path, json.dumps(asdict(token), indent=2))

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def write_private_file(path: Path, content: str) -> None:
    """Public wrapper used for other auth state (browser cookies)."""
    _write_private(path, content)
