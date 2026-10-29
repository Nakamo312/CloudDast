"""Registration entry point for the automata-learning extension."""

from __future__ import annotations

from cloud_dast.extensions import ExtensionRegistry

try:
    from cloud_dast_automata.learning import AALpyAutomataLearningAdapter
except ModuleNotFoundError as error:
    if error.name != "aalpy":
        raise
    AALpyAutomataLearningAdapter = None  # type: ignore[assignment,misc]

IMPLEMENTATIONS = (
    {"aalpy": AALpyAutomataLearningAdapter}
    if AALpyAutomataLearningAdapter is not None
    else {}
)


def register(registry: ExtensionRegistry) -> None:
    """Expose learned-automata implementations through the core port."""

    if AALpyAutomataLearningAdapter is not None:
        registry.register(automata_learning_factory=AALpyAutomataLearningAdapter)

__all__ = ["IMPLEMENTATIONS", "register"]
