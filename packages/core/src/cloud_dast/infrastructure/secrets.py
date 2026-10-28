"""Runtime secret lookup without putting credentials into domain state."""

from __future__ import annotations

import os
from pathlib import Path


def secret_value(name: str, *, default_file: str | None = None) -> str:
    """Read ``name`` from its mounted file first, then from the environment."""

    file_name = os.environ.get(f"{name}_FILE", default_file)
    if file_name:
        path = Path(file_name)
        if path.is_file():
            value = path.read_text(encoding="utf-8").strip()
            if value:
                return value
    return os.environ.get(name, "").strip()


def secret_configured(name: str, *, default_file: str | None = None) -> bool:
    """Check presence without exposing the credential value."""

    file_name = os.environ.get(f"{name}_FILE", default_file)
    return bool(
        (file_name and Path(file_name).is_file() and Path(file_name).stat().st_size)
        or os.environ.get(name)
    )
