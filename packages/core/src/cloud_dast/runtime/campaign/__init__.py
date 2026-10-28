"""Campaign lifecycle, state, replay, and graph assembly.

The package exposes the campaign API lazily so importing one campaign
projection cannot initialize the whole lifecycle and create an import cycle.
"""

from importlib import import_module
from typing import Final

_EXPORTS: Final[dict[str, tuple[str, str]]] = {
    "BoundPathRunner": ("cloud_dast.runtime.execution", "BoundPathRunner"),
    "DifferentialState": (
        "cloud_dast.runtime.campaign.state",
        "DifferentialState",
    ),
    "ExecutionState": (
        "cloud_dast.runtime.campaign.state",
        "ExecutionState",
    ),
    "FinalizerDeps": (
        "cloud_dast.runtime.campaign.finalization",
        "FinalizerDeps",
    ),
    "Finalizer": (
        "cloud_dast.runtime.campaign.finalization",
        "Finalizer",
    ),
    "Assembler": (
        "cloud_dast.runtime.campaign.graph",
        "Assembler",
    ),
    "GroundingState": (
        "cloud_dast.runtime.campaign.state",
        "GroundingState",
    ),
    "BootstrapDeps": (
        "cloud_dast.runtime.campaign.initialization",
        "BootstrapDeps",
    ),
    "Bootstrap": (
        "cloud_dast.runtime.campaign.initialization",
        "Bootstrap",
    ),
    "RunnerDeps": (
        "cloud_dast.runtime.campaign.round",
        "RunnerDeps",
    ),
    "Runner": (
        "cloud_dast.runtime.campaign.round",
        "Runner",
    ),
    "RuntimeState": (
        "cloud_dast.runtime.campaign.state",
        "RuntimeState",
    ),
    "EventGraph": ("cloud_dast.runtime.campaign.replay", "EventGraph"),
    "EvaluationResult": (
        "cloud_dast.contracts.execution",
        "EvaluationResult",
    ),
    "EvidenceDeficitRecord": (
        "cloud_dast.runtime.evidence_gate",
        "EvidenceDeficitRecord",
    ),
    "ExecutionResult": ("cloud_dast.contracts.execution", "ExecutionResult"),
    "FindingEvaluator": (
        "cloud_dast.verification.finding_evaluator",
        "FindingEvaluator",
    ),
    "LiveWorkflow": ("cloud_dast.runtime.campaign.runtime", "LiveWorkflow"),
    "LiveWorkflowOptions": (
        "cloud_dast.runtime.campaign.runtime",
        "LiveWorkflowOptions",
    ),
    "RoundReplay": ("cloud_dast.runtime.campaign.replay", "RoundReplay"),
    "VarianceRecord": ("cloud_dast.runtime.differential.results", "VarianceRecord"),
    "WaveExecution": ("cloud_dast.runtime.consultation.context", "WaveExecution"),
    "diff_modes_from_environment": (
        "cloud_dast.runtime.campaign.runtime",
        "diff_modes_from_environment",
    ),
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> object:
    """Load one campaign API symbol without importing unrelated lifecycle code."""

    try:
        module_name, symbol_name = _EXPORTS[name]
    except KeyError as error:
        raise AttributeError(name) from error
    value = getattr(import_module(module_name), symbol_name)
    globals()[name] = value
    return value
