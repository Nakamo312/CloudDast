"""Resolve QDL field couplings against one execution-context snapshot."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from cloud_dast.binding import scenario_scope
from cloud_dast.couplings import FieldCoupling, normalise_action
from cloud_dast.model import (
    AccessOutcome,
    Check,
    JsonValue,
    MethodSpec,
    Observation,
    ScenarioPosition,
)
from cloud_dast.qdl.field_roles import resolve_field_roles
from cloud_dast.qdl.graph import (
    CAUSAL_EFFECT_CONSTRUCTORS,
    Atom,
    QdlGraph,
    Struct,
    input_field,
)
from cloud_dast.qdl.graph import (
    Context as QdlContext,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.reasoning import derive_requirements
from cloud_dast.runtime.coupling.constraints import (
    solve_coupled_request,
)
from cloud_dast.verification.projection import read_live_outputs, read_observed_effects

OutputRecord = tuple[Check, Observation | None, bool]


@dataclass(frozen=True, slots=True)
class Context:
    """Read-only view of the mutable forwarding state for one resolution."""

    couplings: tuple[FieldCoupling, ...]
    evidence_graph: QdlGraph | None
    methods: Mapping[str, MethodSpec]
    scenarios: Mapping[tuple[str, str], ScenarioPosition]
    outputs: Mapping[str, OutputRecord]


def _applicable_couplings(
    check: Check,
    state: Context,
    rank: Mapping[str, int],
) -> list[FieldCoupling] | None:
    """Select constraints usable now, or defer an unresolved current input."""

    method_id = normalise_action(check.method_id)
    if (method_id, check.scenario_id) not in state.scenarios:
        constrained = any(
            endpoint.name == "input_field"
            and normalise_action(atom_value(endpoint.args[0])) == method_id
            for coupling in state.couplings
            for endpoint in (coupling.left, coupling.right)
        )
        return None if constrained else []
    request = dict(check.request)
    available = {normalise_action(c.method_id) for c, _, _ in state.outputs.values()}
    order = tuple(rank)
    candidates = []
    for coupling in state.couplings:
        endpoints = (coupling.left, coupling.right)
        actions = tuple(normalise_action(atom_value(e.args[0])) for e in endpoints)
        inputs = tuple(
            e
            for e, action in zip(endpoints, actions, strict=True)
            if e.name == "input_field" and action == method_id
        )
        if any(action not in rank for action in actions):
            # A sibling constraint may be skipped; this call's missing producer may not.
            if inputs:
                return None
            continue
        if any(
            e.name == "output_field" and action == method_id
            for e, action in zip(endpoints, actions, strict=True)
        ):
            continue
        future = any(
            action not in available and rank[action] > order.index(method_id)
            for action in actions
        )
        if future:
            # Concrete producer inputs may precede an observer, unresolved inputs may not.
            if any(request.get(atom_value(e.args[1])) is None for e in inputs):
                return None
            continue
        candidates.append(coupling)
    return candidates


def _matching_attempts(
    action: str,
    check: Check,
    scope: str,
    state: Context,
) -> tuple[tuple[tuple[Check, Observation | None], ...], bool]:
    """Select compatible attempts; any live attempt forbids durable fallback."""

    called = [
        record
        for record in state.outputs.values()
        if normalise_action(record[0].method_id) == action
    ]
    live = [record for record in called if record[2]]
    compatible = [
        (candidate, observation)
        for candidate, observation, _ in live or called
        if candidate.identities == check.identities
        and (action, candidate.scenario_id) in state.scenarios
        and scenario_scope(state.scenarios[(action, candidate.scenario_id)]) == scope
    ]
    return tuple(compatible[-1:] if live else compatible), bool(live)


class Binder:
    """Resolve candidate input values from live and durable witnesses."""

    def resolve_check(self, check: Check, state: Context) -> Check | None:
        """Resolve value witnesses, then verify causal prerequisites."""

        resolved = self._resolve_values(check, state)
        return (
            resolved
            if resolved is not None and self._causal_ready(resolved, state)
            else None
        )

    def _resolve_values(self, check: Check, state: Context) -> Check | None:
        method_id = normalise_action(check.method_id)
        rank = {action: index for index, action in enumerate(state.methods)}
        candidates = _applicable_couplings(check, state, rank)
        if candidates is None:
            return None
        actions = {method_id}
        selected = []
        while True:
            added = [
                coupling
                for coupling in candidates
                if coupling not in selected
                and max(
                    (
                        normalise_action(atom_value(endpoint.args[0]))
                        for endpoint in (coupling.left, coupling.right)
                    ),
                    key=lambda action: rank.get(action, -1),
                )
                in actions
            ]
            if not added:
                break
            selected.extend(added)
            actions.update(
                normalise_action(atom_value(endpoint.args[0]))
                for coupling in added
                for endpoint in (coupling.left, coupling.right)
            )
        if not selected:
            return check
        endpoints = tuple(
            dict.fromkeys(
                endpoint
                for coupling in selected
                for endpoint in (coupling.left, coupling.right)
            )
        )
        rows = self._coupled_rows(check, endpoints, state)
        method = state.methods[method_id]
        fields = {field.name: field for field in method.request_schema.fields}
        return solve_coupled_request(check, selected, endpoints, rows, fields)

    def _coupled_rows(
        self,
        check: Check,
        endpoints: tuple[Struct, ...],
        state: Context,
    ) -> dict[str, dict[str, dict[Struct, JsonValue]]]:
        """Keep each action's fields together under its actual occurrence ID."""

        from cloud_dast.verification.projection import read_observed_outputs

        current = normalise_action(check.method_id)
        scenario = state.scenarios[(current, check.scenario_id)]
        scope = scenario_scope(scenario)
        rows: dict[str, dict[str, dict[Struct, JsonValue]]] = {}
        grouped: dict[str, list[Struct]] = {}
        for endpoint in endpoints:
            action = normalise_action(atom_value(endpoint.args[0]))
            grouped.setdefault(action, []).append(endpoint)
        for action, fields in grouped.items():
            action_fields = tuple(fields)
            rows[action] = {}
            if action == current:
                request = dict(check.request)
                rows[action][check.check_id] = {
                    endpoint: request[atom_value(endpoint.args[1])]
                    for endpoint in action_fields
                    if atom_value(endpoint.args[1]) in request
                }
                continue
            attempts, has_live = _matching_attempts(action, check, scope, state)
            for executed, observation in attempts:
                if observation is not None:
                    occurrence = f"{observation.observation_id}:{executed.check_id}"
                    rows[action][occurrence] = self._occurrence_values(
                        executed,
                        observation,
                        action_fields,
                        scope,
                        state,
                    )
            if has_live:
                continue
            if state.evidence_graph is None or not any(
                action_name == action and scenario_scope(scenario_position) == scope
                for (action_name, _), scenario_position in state.scenarios.items()
            ):
                continue
            for endpoint in action_fields:
                if endpoint.name != "output_field":
                    continue
                for observation, value, source_check, _ in read_observed_outputs(
                    state.evidence_graph,
                    endpoint,
                    scope=scope,
                    identities=check.identities,
                ):
                    occurrence = f"{observation.value}:{source_check.value}"
                    rows[action].setdefault(occurrence, {})[endpoint] = value.value
        return rows

    def _occurrence_values(
        self,
        check: Check,
        observation: Observation,
        endpoints: tuple[Struct, ...],
        scope: str,
        state: Context,
    ) -> dict[Struct, JsonValue]:
        if (
            observation.observed_outcome != AccessOutcome.ALLOWED
            or observation.auth_failed
            or observation.error_reason is not None
            or (
                observation.transport_status is not None
                and observation.transport_status.is_error()
            )
        ):
            return {}
        inputs = dict(check.request)
        outputs = read_live_outputs(
            check, observation, scope=scope, graph=state.evidence_graph
        )
        return {
            endpoint: pairs[atom_value(endpoint.args[1])]
            for endpoint in endpoints
            if atom_value(endpoint.args[1])
            in (pairs := inputs if endpoint.name == "input_field" else outputs)
        }

    def _causal_ready(self, check: Check, state: Context) -> bool:
        if state.evidence_graph is None:
            return True
        required = tuple(
            term
            for action, term in derive_requirements(
                state.evidence_graph,
                contexts={QdlContext.CONTRACT, QdlContext.ACCEPTED},
            )
            if isinstance(action, Atom)
            and (identifier := atom_value(action)) is not None
            and normalise_action(identifier) == normalise_action(check.method_id)
            and isinstance(term, Struct)
            and term.name in CAUSAL_EFFECT_CONSTRUCTORS
        )
        if not required:
            return True
        scenario = state.scenarios.get(
            (normalise_action(check.method_id), check.scenario_id)
        )
        if scenario is None:
            return False
        roles = resolve_field_roles(state.evidence_graph)
        references = []
        action = Atom(value=f"action:{normalise_action(check.method_id)}")
        for name, value in check.request:
            if "object_ref" not in roles.roles(action.value, name, direction="input"):
                continue
            if (
                not roles.retains(action.value, name, direction="input")
                or not isinstance(value, str)
                or not value
            ):
                return False
            references.append(
                (input_field(action, Atom(value=name)), Atom(value=value))
            )
        proofs = read_observed_effects(
            state.evidence_graph,
            scope=scenario_scope(scenario),
            identities=check.identities,
            references=tuple(references),
        )
        return all(
            any(fact.args[1] == term for fact, _, _ in proofs) for term in required
        )


__all__ = ["Binder", "Context"]
