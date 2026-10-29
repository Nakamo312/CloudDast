from __future__ import annotations

import hashlib
import json
import logging
import os
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Lock

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows has no advisory flock
    fcntl = None

logger = logging.getLogger("cloud_dast.infrastructure.jsonl")

_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_NAMED_PAIR_FIELDS = frozenset(
    {
        "request",
        "payload",
        "response_tree",
        "resource_state_before",
        "resource_state_after",
    }
)


class JsonlFile:
    """Private, redacting, thread- and process-safe append-only JSONL file.

    The sidecar lock is deliberately outside the record file, so a partially
    written lock record can never become part of the stream.
    Event-bearing JSON objects minimize arbitrary request, full-response, and
    resource-state values before they reach durable storage.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._lock = Lock()

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Serialize access across threads and processes."""

        self._ensure_private_directory(self.path.parent)
        self._ensure_private_file(self._lock_path)
        with self._lock_path.open("a+") as stream:
            if fcntl is not None:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def ensure(self) -> None:
        self._ensure_private_directory(self.path.parent)
        self._ensure_private_file(self.path)

    def append(
        self,
        payload: bytes,
        *,
        separator: bytes = b"",
        redact: bool = True,
        retained_fields: Iterable[str] = (),
    ) -> None:
        if redact:
            payload = redact_json_payload(payload, retained_fields=retained_fields)
        self.ensure()
        with self.path.open("ab") as stream:
            stream.write(separator + payload + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

    def complete_tail(self, offset: int) -> tuple[bytes, int]:
        """Read only complete records appended after ``offset``."""

        size = self.path.stat().st_size
        if size <= offset:
            return b"", offset
        with self.path.open("rb") as stream:
            stream.seek(offset)
            tail = stream.read()
        complete_bytes = tail.rfind(b"\n") + 1
        if complete_bytes == 0:
            return b"", offset
        return tail[:complete_bytes], offset + complete_bytes

    def iter_lines(self) -> Iterator[tuple[int, bytes]]:
        with self.path.open("rb") as stream:
            for number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                yield number, line

    def truncate_incomplete_tail(
        self,
        *,
        validate: Callable[[bytes], object] | None = None,
        preserve_complete: bool = False,
        label: str = "record",
    ) -> bool:
        """Remove a torn final record and report whether a separator is needed.

        With ``preserve_complete`` a valid final JSON record without its newline
        is retained; the next append must then add the missing newline first.
        """

        size = self.path.stat().st_size
        if not size:
            return False

        with self.path.open("rb") as stream:
            stream.seek(-1, os.SEEK_END)
            if stream.read(1) == b"\n":
                return False

            tail_start = self._last_newline_end(stream, size)
            stream.seek(tail_start)
            tail = stream.read()

        if not tail.strip():
            self._truncate_to(tail_start)
            return False
        if validate is None:
            self._truncate_to(tail_start)
            return False

        try:
            json.loads(tail)
        except json.JSONDecodeError as exc:
            if exc.pos < len(tail.rstrip()) - 1:
                raise ValueError(
                    f"invalid {label} JSON at line {self._line_number(tail_start)}"
                ) from exc
            self._truncate_to(tail_start)
            return False
        if validate is not None:
            try:
                validate(tail)
            except ValueError as exc:
                raise ValueError(
                    f"invalid {label} JSON at line {self._line_number(tail_start)}"
                ) from exc
        if preserve_complete:
            return True
        self._truncate_to(tail_start)
        return False

    @staticmethod
    def _last_newline_end(stream: object, size: int) -> int:
        """Return the offset immediately after the last newline."""

        chunk_size = 8192
        cursor = size
        while cursor:
            start = max(0, cursor - chunk_size)
            stream.seek(start)  # type: ignore[attr-defined]
            chunk = stream.read(cursor - start)  # type: ignore[attr-defined]
            index = chunk.rfind(b"\n")
            if index >= 0:
                return start + index + 1
            cursor = start
        return 0

    def _truncate_to(self, offset: int) -> None:
        with self.path.open("r+b") as stream:
            stream.truncate(offset)
            stream.flush()
            os.fsync(stream.fileno())

    def _line_number(self, offset: int) -> int:
        """Compute a diagnostic line number during exceptional recovery."""

        lines = 1
        with self.path.open("rb") as stream:
            remaining = offset
            while remaining:
                chunk = stream.read(min(8192, remaining))
                if not chunk:
                    break
                lines += chunk.count(b"\n")
                remaining -= len(chunk)
        return lines

    @staticmethod
    def _ensure_private_directory(path: Path) -> None:
        """Create missing artifact directories with owner-only permissions."""

        missing: list[Path] = []
        current = path
        while not current.exists():
            missing.append(current)
            if current.parent == current:
                break
            current = current.parent
        for directory in reversed(missing):
            try:
                directory.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
            except FileExistsError:
                pass
            os.chmod(directory, _PRIVATE_DIRECTORY_MODE)

    @staticmethod
    def _ensure_private_file(path: Path) -> None:
        """Create or harden one artifact file with owner-only permissions."""

        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                _PRIVATE_FILE_MODE,
            )
        except FileExistsError:
            os.chmod(path, _PRIVATE_FILE_MODE)
        else:
            os.close(descriptor)


def redact_json_payload(
    payload: bytes,
    *,
    retained_fields: Iterable[str] = (),
) -> bytes:
    """Minimize a JSON event record before it is made durable.

    ``retained_fields`` names the fields whose values may be kept because the
    graph carries accepted replay-safe role facts for them.  Every other named
    value is redacted and reported as a deficit; a field name alone never
    makes its value safe to persist.
    """

    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return payload
    if not isinstance(value, dict):
        return payload
    retained = frozenset(retained_fields)
    gaps: set[str] = set()
    redacted = _redact_event(value, retained, gaps)
    if gaps:
        logger.warning(
            "jsonl event values redacted: fields without accepted "
            "replay-safe roles: %s",
            ",".join(sorted(gaps)),
        )
    return json.dumps(
        redacted,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


_redact_json_payload = redact_json_payload


def _redact_event(value: object, retained: frozenset[str], gaps: set[str]) -> object:
    if isinstance(value, dict):
        return {
            key: _redact_named_pairs(item, retained, gaps)
            if key in _NAMED_PAIR_FIELDS
            else _redact_event(item, retained, gaps)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_event(item, retained, gaps) for item in value]
    return value


def _redact_named_pairs(
    value: object,
    retained: frozenset[str],
    gaps: set[str],
) -> object:
    if not (
        isinstance(value, list)
        and all(
            isinstance(pair, list) and len(pair) == 2 and isinstance(pair[0], str)
            for pair in value
        )
    ):
        return _redact_event(value, retained, gaps)
    projected = []
    for name, item in value:
        if _is_retained_value(name, item, retained):
            projected.append([name, item])
        else:
            gaps.add(name)
            projected.append([name, _redacted_value(item)])
    return projected


def _is_retained_value(
    name: str,
    value: object,
    retained: frozenset[str],
) -> bool:
    return name in retained and (value is None or isinstance(value, str))


def _redacted_value(value: object) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"redacted:sha256:{digest}:length:{len(canonical.encode('utf-8'))}"
