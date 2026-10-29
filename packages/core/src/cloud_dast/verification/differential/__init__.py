"""Differential observation comparison for discovery grounding."""

from cloud_dast.verification.differential.comparator import (
    compare_observations,
)
from cloud_dast.verification.differential.contracts import (
    ConcurrencyResult,
    DifferentialSpec,
    IsolatedStandPolicy,
    PayloadPairSpec,
    ReadBackResult,
    ReadBackSpec,
    payload_canary,
    payload_fields,
    read_resource_binding,
    read_resource_reference,
    select_read_method,
)
from cloud_dast.verification.differential.modes import (
    CONCURRENCY_MAX_WORKERS,
    CONCURRENCY_PROBES,
    DIFF_MODES,
    MUTABLE_INPUT_ROLE,
    MUTABLE_INPUT_ROLES,
    PAYLOAD_ROLE,
    TIMING_MIN_SAMPLES,
    TIMING_REPEATS,
    DiffMode,
)
from cloud_dast.verification.differential.projection import project_diff
from cloud_dast.verification.differential.report import (
    DIFFERENCE_DIMENSIONS,
    DiffReport,
)

__all__ = [
    "DIFFERENCE_DIMENSIONS",
    "DiffReport",
    "CONCURRENCY_MAX_WORKERS",
    "CONCURRENCY_PROBES",
    "DIFF_MODES",
    "DiffMode",
    "DifferentialSpec",
    "ConcurrencyResult",
    "IsolatedStandPolicy",
    "MUTABLE_INPUT_ROLE",
    "MUTABLE_INPUT_ROLES",
    "PAYLOAD_ROLE",
    "PayloadPairSpec",
    "ReadBackResult",
    "ReadBackSpec",
    "TIMING_MIN_SAMPLES",
    "TIMING_REPEATS",
    "compare_observations",
    "payload_canary",
    "payload_fields",
    "project_diff",
    "read_resource_binding",
    "read_resource_reference",
    "select_read_method",
]
