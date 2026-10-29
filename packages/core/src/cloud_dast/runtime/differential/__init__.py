"""Differential discovery, probing, evidence, and result contracts."""

from importlib import import_module
from typing import Final

_EXPORTS: Final[dict[str, tuple[str, str]]] = {
    "ConcurrencyPartialResult": (
        "cloud_dast.runtime.differential.results",
        "ConcurrencyPartialResult",
    ),
    "ExperimentDeps": (
        "cloud_dast.runtime.differential.campaign",
        "ExperimentDeps",
    ),
    "Runner": (
        "cloud_dast.runtime.differential.campaign",
        "Runner",
    ),
    "DifferentialEvidence": (
        "cloud_dast.runtime.differential.evidence",
        "DifferentialEvidence",
    ),
    "Store": (
        "cloud_dast.runtime.differential.evidence",
        "Store",
    ),
    "OutcomeRecorder": (
        "cloud_dast.runtime.differential.outcomes",
        "OutcomeRecorder",
    ),
    "ProbeCallbacks": (
        "cloud_dast.runtime.differential.probes",
        "ProbeCallbacks",
    ),
    "ProbeRunner": (
        "cloud_dast.runtime.differential.probes",
        "ProbeRunner",
    ),
    "ProbeExecutor": (
        "cloud_dast.runtime.differential.executor",
        "ProbeExecutor",
    ),
    "SpecResolver": (
        "cloud_dast.runtime.differential.specs",
        "SpecResolver",
    ),
    "MeasurementKey": ("cloud_dast.runtime.differential.evidence", "MeasurementKey"),
    "PairPartialResult": (
        "cloud_dast.runtime.differential.results",
        "PairPartialResult",
    ),
    "PartialExecutionError": (
        "cloud_dast.runtime.differential.results",
        "PartialExecutionError",
    ),
    "PartialExecutionResult": (
        "cloud_dast.runtime.differential.results",
        "PartialExecutionResult",
    ),
    "ReadBackPartialResult": (
        "cloud_dast.runtime.differential.results",
        "ReadBackPartialResult",
    ),
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> object:
    """Load one differential symbol without initializing campaign execution."""

    try:
        module_name, symbol_name = _EXPORTS[name]
    except KeyError as error:
        raise AttributeError(name) from error
    value = getattr(import_module(module_name), symbol_name)
    globals()[name] = value
    return value
