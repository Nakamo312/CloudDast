"""Reuse previously observed evidence while executing a bound path."""

from __future__ import annotations

from collections.abc import Callable

from cloud_dast.binding import scenario_scope
from cloud_dast.couplings import select_outputs
from cloud_dast.model import Check, VerdictStatus
from cloud_dast.model.events import CheckCompleted, DomainEvent, EventScope
from cloud_dast.qdl.graph import Atom, QdlGraph, Struct, input_field
from cloud_dast.runtime.execution.contracts import QdlExecutionPath, QdlExecutionStep
from cloud_dast.verification.projection import (
    read_observed_effects,
    read_observed_outputs,
    select_effect_witness,
)


class Reuse:
    """Discharge path steps from replayed observations and verified effects."""

    def __init__(
        self,
        *,
        refresh_events: Callable[[], tuple[DomainEvent, ...]],
        observed_graph: Callable[[QdlExecutionPath], QdlGraph],
        set_coupling_context: Callable[..., None],
        generate_pair_checks: Callable[..., tuple[Check, ...]],
        resolve_check: Callable[[Check], Check | None],
        publish_step_event: Callable[..., None],
    ) -> None:
        self._refresh_events = refresh_events
        self._observed_graph = observed_graph
        self._set_coupling_context = set_coupling_context
        self._generate_pair_checks = generate_pair_checks
        self._resolve_check = resolve_check
        self._publish_step_event = publish_step_event

    def resume_observed_step(
        self,
        path: QdlExecutionPath,
        step: QdlExecutionStep,
        *,
        scope: EventScope | None,
    ) -> bool:
        """Resume an executed occurrence without replaying or claiming it."""

        if (
            step.required_effects
            or step.invariant.norm_fact is not None
            or step.evidence_graph is None
        ):
            return False
        events = self._refresh_events()
        if scope is not None:
            events = scope.campaign_events(events)
        previous = next(
            (
                event
                for event in reversed(events)
                if isinstance(event, CheckCompleted)
                and event.path_id == path.path_id
                and event.step_id == step.step_id
                and event.observation.scenario_id == step.scenario.scenario_id
                and event.method_id == step.method.method_id
            ),
            None,
        )
        if previous is None:
            return False
        # A redacted request cannot be reconstructed. Its executed occurrence
        # still must not be silently repeated; missing values remain pending.
        if previous.check is not None and (
            previous.check.request or previous.observation.output is not None
        ):
            self._set_coupling_context(
                tuple((item.plan, item.method, item.scenario) for item in path.steps),
                evidence_graph=self._observed_graph(path),
                reset=False,
                observations=((previous.check, previous.observation),),
            )
        return True

    def proved_effects(
        self,
        step: QdlExecutionStep,
        *,
        evidence_graph: QdlGraph,
        path: QdlExecutionPath,
        step_index: int,
        scope: EventScope | None,
    ) -> bool:
        """Discharge a causal subgoal with current evidence, without a request."""

        if not step.required_effects or step.invariant.norm_fact is not None:
            return False
        generated = self._generate_pair_checks(
            step.plan,
            step.method,
            step.invariant,
            step.scenario,
            strategy=step.plan.generator,
        )
        if not generated:
            return False
        resolved = self._resolve_check(generated[0])
        if resolved is None:
            return False
        request = dict(resolved.request)
        bindings: list[tuple[Struct, Atom]] = []
        for name in (
            *step.plan.resource_params,
            *step.plan.subject_params,
            *step.plan.role_params,
        ):
            value = request.get(name)
            if not isinstance(value, str) or not value:
                return False
            bindings.append(
                (
                    input_field(
                        Atom(value=f"action:{step.method.method_id}"), Atom(value=name)
                    ),
                    Atom(value=value),
                )
            )
        proofs = read_observed_effects(
            evidence_graph,
            scope=scenario_scope(step.scenario),
            identities=resolved.identities,
            method_id=step.method.method_id,
            bindings=tuple(bindings),
        )
        downstream = {
            candidate.method.method_id for candidate in path.steps[step_index + 1 :]
        }
        witnesses = select_outputs(
            (
                coupling
                for candidate in path.steps
                for coupling in candidate.plan.couplings
            ),
            step.method.method_id,
            downstream,
        )
        if witnesses is None:
            return False
        proof = select_effect_witness(
            proofs,
            required_effects=step.required_effects,
            outputs=(
                read_observed_outputs(
                    evidence_graph,
                    witness,
                    scope=scenario_scope(step.scenario),
                    identities=generated[0].identities,
                )
                for witness in witnesses
            ),
        )
        if proof is None:
            return False
        fact, check, _ = proof
        self._publish_step_event(
            path.path_id,
            step,
            VerdictStatus.UNSCOREABLE,
            "QDL prerequisites already evidenced",
            step_index=step_index,
            is_final_step=False,
            correlation_id=str(check.value),
            observation_id=str(fact.args[0].value),
            scope=scope,
            effect_verified=True,
        )
        return True


__all__ = ["Reuse"]
