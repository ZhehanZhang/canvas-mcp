"""Private-file helper for auth state written to disk."""

import os
import tempfile
from pathlib import Path


def write_private_file(path: Path, content: str) -> None:
    """Atomically write ``content`` to ``path`` readable only by the owner (0600)."""
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
