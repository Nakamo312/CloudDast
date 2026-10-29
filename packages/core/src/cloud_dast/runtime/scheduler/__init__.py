"""Coverage scheduling contracts and a lazily loaded campaign scheduler."""

from importlib import import_module

from cloud_dast.runtime.scheduler.model import CoverageKey, PathOutcome, State

__all__ = ["CoverageDrivenScheduler", "CoverageKey", "PathOutcome", "State"]


def __getattr__(name: str) -> object:
    if name == "CoverageDrivenScheduler":
        return getattr(import_module(".core", __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
