"""Registration entry point for the optional LLM extension."""

from __future__ import annotations

from cloud_dast.extensions import ExtensionRegistry


def _implementations() -> dict[str, object]:
    from cloud_dast_llm.axis_grounding import Dispatcher
    from cloud_dast_llm.consultation import ConsultationDispatcher
    from cloud_dast_llm.generator import LlmGenerator
    from cloud_dast_llm.threat_model import FormalThreatModeler

    return {
        "axis_grounding_factory": Dispatcher,
        "consultation": ConsultationDispatcher,
        "threat_modeler": FormalThreatModeler,
        "llm": LlmGenerator,
    }


def register(registry: ExtensionRegistry) -> None:
    """Expose LLM implementations through stable core contracts."""

    implementations = _implementations()
    registry.register(
        axis_grounding_factory=implementations["axis_grounding_factory"],
        llm_generator_factory=implementations["llm"],
        consultation_factory=implementations["consultation"],
        threat_modeler_factory=implementations["threat_modeler"],
    )


def __getattr__(name: str):
    if name == "IMPLEMENTATIONS":
        return _implementations()
    raise AttributeError(name)


__all__ = ["IMPLEMENTATIONS", "register"]  # noqa: F822
