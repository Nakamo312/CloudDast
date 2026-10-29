"""Runtime token providers without embedded credentials."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import threading
import time
from collections.abc import Mapping
from pathlib import Path

FILE_TOKEN_CACHE_TTL_SECONDS = 60.0


def normalize_identity_key(identity: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", identity).upper()


def configured_token_command(
    identity: str | None = None,
    *,
    prefix: str = "CLOUD_DAST_TOKEN_",
    fallback: str = "CLOUD_DAST_IAM_TOKEN",
) -> str:
    """Return the configured token command without executing it.

    An explicit identity has no global command fallback.
    """

    if identity:
        key = normalize_identity_key(identity)
        return os.environ.get(f"{prefix}{key}_COMMAND", "").strip()
    return os.environ.get(f"{fallback}_COMMAND", "").strip()


def _truthy(value: str | None) -> bool:
    return bool(value and value.strip().lower() in {"1", "true", "yes", "on"})


class EnvironmentTokenProvider:
    """Read IAM tokens from files, environment variables, or a local command.

    For an explicit identity the provider uses only
    ``CLOUD_DAST_TOKEN_<IDENTITY>`` and its ``_FILE``/``_COMMAND`` variants.
    There is no global token fallback: one identity must never receive another
    identity's credential. A run without an identity may use
    ``CLOUD_DAST_IAM_TOKEN`` and ``CLOUD_DAST_IAM_TOKEN_COMMAND``.

    File-backed values are cached for 60 seconds so an externally refreshed
    mounted token is picked up promptly. Other token sources use the command
    cache TTL (50 minutes by default).

    Set ``CLOUD_DAST_IAM_TOKEN_PREFER_COMMAND=1`` to make a configured command
    take precedence over a mounted secret file. This is useful for host runs;
    container images should normally consume a token file refreshed outside the
    container rather than mounting cloud CLI credentials.

    Commands are split with ``shlex`` and executed without a shell. Token
    values and command stderr are never logged or stored in domain objects.
    """

    def __init__(
        self,
        *,
        prefix: str = "CLOUD_DAST_TOKEN_",
        fallback: str = "CLOUD_DAST_IAM_TOKEN",
        command_timeout: float = 30.0,
        cache_ttl_seconds: float = 3000.0,
        file_cache_ttl_seconds: float = FILE_TOKEN_CACHE_TTL_SECONDS,
    ) -> None:
        if command_timeout <= 0:
            raise ValueError("command_timeout must be positive")
        if cache_ttl_seconds < 0:
            raise ValueError("cache_ttl_seconds must not be negative")
        if file_cache_ttl_seconds < 0:
            raise ValueError("file_cache_ttl_seconds must not be negative")
        self._prefix = prefix
        self._fallback = fallback
        self._command_timeout = command_timeout
        self._cache_ttl_seconds = cache_ttl_seconds
        self._file_cache_ttl_seconds = file_cache_ttl_seconds
        self._cache: dict[str, tuple[str, float]] = {}
        self._identity_by_key: dict[str, str] = {}
        self._lock = threading.Lock()

    def metadata(self, identity: str) -> tuple[tuple[str, str], ...]:
        token = self._token(identity)
        if not token:
            key = normalize_identity_key(identity)
            raise RuntimeError(
                f"IAM token is not configured for identity {identity!r}; "
                f"set {self._prefix}{key} or {self._prefix}{key}_COMMAND"
            )
        return (("authorization", f"Bearer {token}"),)

    def _token(self, identity: str) -> str:
        key = self._bind_identity(identity)
        identity_name = f"{self._prefix}{key}"
        secret_name = identity_name if identity else self._fallback
        command = configured_token_command(
            identity, prefix=self._prefix, fallback=self._fallback
        )
        prefer_command = _truthy(os.environ.get("CLOUD_DAST_IAM_TOKEN_PREFER_COMMAND"))

        cached = self._cached(identity)
        if cached is not None:
            return cached

        if command and prefer_command:
            token = self._run_command(command, identity)
            self._cache_token(identity, token)
            return token

        token, from_file = self._read_secret(secret_name)
        if token:
            self._cache_token(identity, token, from_file=from_file)
            return token

        if command:
            token = self._run_command(command, identity)
            self._cache_token(identity, token)
            return token

        return ""

    def _bind_identity(self, identity: str) -> str:
        key = normalize_identity_key(identity)
        with self._lock:
            bound_identity = self._identity_by_key.get(key)
            if bound_identity is None:
                self._identity_by_key[key] = identity
            elif bound_identity != identity:
                raise RuntimeError(
                    f"IAM identity key {key!r} is ambiguous: "
                    f"{bound_identity!r} and {identity!r}"
                )
        return key

    @staticmethod
    def _read_secret(name: str) -> tuple[str, bool]:
        file_name = os.environ.get(f"{name}_FILE")
        if file_name:
            path = Path(file_name)
            if path.is_file():
                value = path.read_text(encoding="utf-8").strip()
                if value:
                    return value, True
        return os.environ.get(name, "").strip(), False

    def _cached(self, identity: str) -> str | None:
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(identity)
            if cached is None:
                return None
            token, expires_at = cached
            if expires_at <= now:
                del self._cache[identity]
                return None
            return token

    def _cache_token(
        self, identity: str, token: str, *, from_file: bool = False
    ) -> None:
        ttl = self._cache_ttl_seconds
        if from_file:
            ttl = min(ttl, self._file_cache_ttl_seconds)
        expires_at = time.monotonic() + ttl
        with self._lock:
            self._cache[identity] = (token, expires_at)

    def _run_command(self, command: str, identity: str) -> str:
        try:
            argv = shlex.split(command)
        except ValueError as error:
            raise RuntimeError(
                f"IAM token command for identity {identity!r} is invalid"
            ) from error
        if not argv:
            raise RuntimeError(f"IAM token command for identity {identity!r} is empty")
        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self._command_timeout,
                check=False,
                env=self._safe_environment(),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError(
                f"IAM token command for identity {identity!r} failed"
            ) from error
        if result.returncode != 0:
            raise RuntimeError(
                f"IAM token command for identity {identity!r} failed "
                f"with exit code {result.returncode}"
            )
        token = result.stdout.strip()
        if not token or any(character.isspace() for character in token):
            raise RuntimeError(
                f"IAM token command for identity {identity!r} returned invalid output"
            )
        return token

    @staticmethod
    def _safe_environment() -> Mapping[str, str]:
        # Preserve PATH, HOME and locale so a CLI can find its configuration,
        # while avoiding unrelated application variables that could change the
        # command's behavior. The command itself is user-configured.
        allow = {
            "PATH",
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "TMPDIR",
            "CLOUD_DAST_IAM_AUTHORIZED_KEY_FILE",
            "CLOUD_DAST_IAM_ENDPOINT",
        }
        return {name: value for name, value in os.environ.items() if name in allow}
