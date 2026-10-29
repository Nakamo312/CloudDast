"""Optional LLM proposal extensions for Cloud DAST."""

__all__ = [
    "ConsultationDispatcher",
    "LlmGeneratedCheck",
    "LlmGeneratedChecks",
    "LlmGenerator",
    "FormalThreatModeler",
]


def __getattr__(name: str):
    """Load optional implementations only when a caller requests them."""

    modules = {
        "ConsultationDispatcher": ("cloud_dast_llm.consultation", name),
        "FormalThreatModeler": ("cloud_dast_llm.threat_model", name),
        "LlmGeneratedCheck": ("cloud_dast_llm.proposals", name),
        "LlmGeneratedChecks": ("cloud_dast_llm.proposals", name),
        "LlmGenerator": ("cloud_dast_llm.generator", name),
    }
    target = modules.get(name)
    if target is None:
        raise AttributeError(name)
    from importlib import import_module

    return getattr(import_module(target[0]), target[1])
