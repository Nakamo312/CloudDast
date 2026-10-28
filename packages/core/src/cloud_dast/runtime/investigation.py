from __future__ import annotations

from collections.abc import Callable

from cloud_dast.model import Observation
from cloud_dast.model.events import InvestigationActionExecuted, InvestigationIntent
from cloud_dast.ports import EventPublisher

InvestigationTarget = Callable[[InvestigationIntent], Observation]
InvestigationGuardrail = Callable[[InvestigationIntent], bool]


def run_investigation_intent(
    intent: InvestigationIntent,
    target: InvestigationTarget,
    guardrail: InvestigationGuardrail,
    event_bus: EventPublisher | None = None,
) -> Observation:
    """Execute one guarded investigation action and record its observation.

    Investigation is an isolated creative-loop primitive.  It deliberately
    does not enqueue search candidates or derive findings: an intent has no
    invariant/scenario provenance needed for either.  The regular search loop
    expands around confirmed findings via ``anomaly_candidates``.
    """
    if not guardrail(intent):
        raise PermissionError("investigation intent denied by guardrail")

    observation = target(intent)
    observation = observation.model_copy(update={"check_id": intent.intent_id})

    if event_bus is not None:
        event_bus.publish(
            InvestigationActionExecuted(
                intent=intent,
                observation=observation,
                correlation_id=intent.intent_id,
            )
        )

    return observation
