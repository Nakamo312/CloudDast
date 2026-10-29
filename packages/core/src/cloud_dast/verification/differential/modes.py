"""Stable mode vocabulary and execution limits for differential discovery."""

from typing import Literal

DiffMode = Literal["factors", "payload", "readback", "timing", "concurrency"]
"""Differential discovery modes (RFC §9.1)."""

DIFF_MODES: frozenset[DiffMode] = frozenset(
    {"factors", "payload", "readback", "timing", "concurrency"},
)
"""Closed alphabet of differential discovery modes."""

PAYLOAD_ROLE = "payload"
MUTABLE_INPUT_ROLE = "mutable_input"
MUTABLE_INPUT_ROLES = frozenset({PAYLOAD_ROLE, MUTABLE_INPUT_ROLE})
"""Closed role alphabet that makes one input field safe to mutate."""

TIMING_REPEATS = 3
"""Number of control/treatment pairs executed by the timing mode."""

TIMING_MIN_SAMPLES = 3
"""Minimum duration samples per leg required for a latency class."""

CONCURRENCY_PROBES = 4
"""Number of identical probes executed by the concurrency mode."""

CONCURRENCY_MAX_WORKERS = 4
"""Upper bound on workers used by one concurrency probe batch."""

__all__ = [
    "CONCURRENCY_MAX_WORKERS",
    "CONCURRENCY_PROBES",
    "DIFF_MODES",
    "DiffMode",
    "MUTABLE_INPUT_ROLE",
    "MUTABLE_INPUT_ROLES",
    "PAYLOAD_ROLE",
    "TIMING_MIN_SAMPLES",
    "TIMING_REPEATS",
]
