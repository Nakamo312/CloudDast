"""Public grounding contracts and runtime orchestration."""

from importlib import import_module

_EXPORTS = {
    "AutoGroundingService": (".runtime", "AutoGroundingService"),
    "ApprovalResult": (".classification", "ApprovalResult"),
    "MeasuredEvidencePolicy": (".evidence", "MeasuredEvidencePolicy"),
    "ParkedClassification": (".classification", "ParkedClassification"),
    "ApprovalFlow": (".classification", "ApprovalFlow"),
    "RunCoordinator": (".lifecycle", "RunCoordinator"),
    "RunOptions": (".lifecycle", "RunOptions"),
    "ProposalPromoter": (".promotion", "ProposalPromoter"),
    "Activity": (".promotion", "Activity"),
    "DifferentialFlow": (".variance", "DifferentialFlow"),
    "PairInput": (".inputs", "PairInput"),
    "Loader": (".source", "Loader"),
    "DispatchFlow": (".consultation", "DispatchFlow"),
    "GrounderOptions": (".config", "GrounderOptions"),
    "ServiceOptions": (".config", "ServiceOptions"),
    "AxisResult": (".results", "AxisResult"),
    "ConsultationLedger": (".state", "ConsultationLedger"),
    "ConsultationKey": (".state", "ConsultationKey"),
    "LeadLifecycle": (".state", "LeadLifecycle"),
    "ParkedLeadState": (".state", "ParkedLeadState"),
}

__all__ = tuple(_EXPORTS)


def __getattr__(name: str):
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    module_name, attribute = target
    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value
