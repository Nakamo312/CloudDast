"""Pure binding of planned QDL paths to executable application contracts."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping

from cloud_dast.contracts.plan import (
    InvariantProjection,
    QdlExecutionPath,
    QdlExecutionStep,
    VerificationPlan,
)
from cloud_dast.model import (
    MethodSpec,
    ScenarioPosition,
    Severity,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    canonical_json,
    transition,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.reasoning import QdlAttackPath, QdlForbiddenPath
from cloud_dast.verification.invariant_projection import norm_key


def path_key(path: QdlExecutionPath) -> tuple[tuple[str, str, str], ...]:
    """Return the canonical norm sequence of an executable path."""

    keys: list[tuple[str, str, str]] = []
    for step in path.steps:
        if (
            step.invariant.norm_fact is None
            or len(step.invariant.norm_fact.args) != 2
            or not isinstance(step.invariant.norm_fact.args[1], Struct)
        ):
            keys.append((step.method.method_id, step.invariant.invariant_id, ""))
            continue
        keys.append(norm_key(step.method.method_id, step.invariant.norm_fact.args[1]))
    return tuple(keys)


def bind_attack_path(
    path: QdlAttackPath,
    *,
    invariants: Mapping[str, InvariantProjection],
    invariants_by_action: Mapping[str, tuple[str, ...] | list[str]],
    invariants_by_effect: Mapping[str, tuple[str, ...] | list[str]],
    methods_by_action: Mapping[str, MethodSpec],
    scenarios_by_action: Mapping[str, ScenarioPosition],
    record_deficit: Callable[..., None] | None = None,
) -> QdlExecutionPath | None:
    """Bind a graph-derived chain, including ordinary steps without a norm.

    Empty outgoing effects permit value acquisition; they never certify the
    next action's own prerequisites. The runner validates those before calling.
    """

    if not path.actions:
        return None

    steps: list[QdlExecutionStep] = []
    incomplete = False
    for index, action in enumerate(path.actions):
        method = methods_by_action.get(action)
        scenario = scenarios_by_action.get(action)
        if method is None or scenario is None:
            if record_deficit is None:
                return None
            record_deficit(
                action=action,
                reason=(
                    "contract_method_missing"
                    if method is None
                    else "contract_scenario_missing"
                ),
                kind=("method_missing" if method is None else "scenario_missing"),
                context=(("coverage", "attack"), ("path_id", path.path_id)),
            )
            incomplete = True
            continue
        if incomplete:
            continue
        required_effects = (
            path.edge_effects[index] if index < len(path.edge_effects) else ()
        )
        if required_effects:
            invariant_id = select_edge_invariant(
                required_effects,
                invariants_by_effect,
            )
        else:
            candidates = invariants_by_action.get(action, ())
            invariant_id = min(candidates) if candidates else None
        invariant = (
            invariants[invariant_id]
            if invariant_id is not None
            else InvariantProjection(
                invariant_id=f"effect:{path.path_id}:{index}",
                norm_id="",
                statement=(
                    f"Establish the QDL prerequisites of {path.actions[index + 1]}"
                    if required_effects
                    else f"Observe QDL action {action} for the planned chain"
                ),
                severity=Severity.LOW,
            )
        )
        steps.append(
            build_step(
                step_id=f"step:{path.path_id}:{index}",
                goal_id=f"goal:qdl:attack:{path.path_id}",
                invariant=invariant,
                method=method,
                scenario=scenario,
                required_effects=required_effects,
            )
        )

    if incomplete:
        return None

    return QdlExecutionPath(
        path_id=path.path_id,
        goal_id=f"goal:qdl:attack:{path.path_id}",
        kind="attack",
        description="Execute a graph-derived QDL action chain.",
        steps=tuple(steps),
    )


def select_edge_invariant(
    edge_effects: tuple[Struct, ...],
    invariants_by_effect: Mapping[str, tuple[str, ...] | list[str]],
) -> str | None:
    """Select the stable norm proving one QDL edge effect."""

    for effect in edge_effects:
        invariant_ids = invariants_by_effect.get(canonical_json(effect), ())
        if invariant_ids:
            return min(invariant_ids)
    return None


def bind_forbidden_path(
    forbidden: QdlForbiddenPath,
    *,
    transitions: Mapping[tuple[str, str], tuple[str, ...]],
    methods_by_action: Mapping[str, MethodSpec],
    scenarios_by_action: Mapping[str, ScenarioPosition],
    record_deficit: Callable[..., None] | None = None,
) -> QdlExecutionPath | None:
    """Validate a forbidden route, emitting failures through record_deficit."""

    def emit(
        *,
        action: str,
        reason: str,
        kind: str,
        context: tuple[tuple[str, str], ...],
    ) -> None:
        if record_deficit is not None:
            record_deficit(
                action=action,
                reason=reason,
                kind=kind,
                context=(
                    ("coverage", "forbidden_path"),
                    ("path_id", forbidden.path_id),
                    *context,
                ),
            )

    state_path = forbidden.path
    actions = state_path.actions
    if not actions:
        return None

    steps: list[QdlExecutionStep] = []
    state = state_path.initial_state
    for index, action in enumerate(actions):
        method = methods_by_action.get(action)
        scenario = scenarios_by_action.get(action)
        if method is None or scenario is None:
            emit(
                action=action,
                reason=(
                    "contract_method_missing"
                    if method is None
                    else "contract_scenario_missing"
                ),
                kind=("method_missing" if method is None else "scenario_missing"),
                context=(("state", state),),
            )
            return None
        targets = transitions.get((action, state), ())
        if len(targets) != 1:
            reason = (
                "ambiguous_forbidden_transition"
                if targets
                else "forbidden_transition_missing"
            )
            context = (("from_state", state),)
            if targets:
                context += (("target_count", str(len(targets))),)
            emit(action=action, reason=reason, kind=reason, context=context)
            return None
        to_state = targets[0]
        final = index == len(actions) - 1
        if final and to_state != state_path.final_state:
            emit(
                action=action,
                reason="forbidden_transition_missing",
                kind="forbidden_transition_missing",
                context=(
                    ("from_state", state),
                    ("to_state", to_state),
                    ("expected_state", state_path.final_state),
                ),
            )
            return None

        steps.append(
            _forbidden_step(forbidden, index, state, to_state, method, scenario)
        )
        state = to_state

    return QdlExecutionPath(
        path_id=forbidden.path_id,
        goal_id=f"goal:qdl:forbidden:{forbidden.norm}:{state_path.final_state}",
        kind="forbidden",
        description=(
            f"Reach forbidden business state {state_path.final_state!r} "
            f"for norm {forbidden.norm!r}."
        ),
        steps=tuple(steps),
    )


def _forbidden_step(
    forbidden: QdlForbiddenPath,
    index: int,
    state: str,
    to_state: str,
    method: MethodSpec,
    scenario: ScenarioPosition,
) -> QdlExecutionStep:
    """Project a validated transition into its norm and executable step."""

    state_path = forbidden.path
    action = state_path.actions[index]
    final = index == len(state_path.actions) - 1
    invariant = InvariantProjection(
        invariant_id=f"invariant:qdl:forbidden:{forbidden.path_id}:{index}",
        norm_id=f"norm:forbidden:{forbidden.norm}",
        statement=forbidden_statement(
            action,
            state,
            to_state,
            forbidden.norm,
            final=final,
        ),
        severity=Severity.CRITICAL,
        policy=f"not transition({action}, {state}, {to_state})",
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value=f"norm:forbidden:{forbidden.norm}:{index}"),
                transition(Atom(value=state), Atom(value=to_state)),
            ),
        ),
    )
    return build_step(
        step_id=f"step:{forbidden.path_id}:{index}",
        goal_id=f"goal:qdl:forbidden:{forbidden.norm}:{state_path.final_state}",
        invariant=invariant,
        method=method,
        scenario=scenario,
        effect_ids=(f"fact:state:{to_state}:{forbidden.path_id}:{index}",),
        required_effects=(transition(Atom(value=state), Atom(value=to_state)),),
    )


def invariant_path(
    invariant: InvariantProjection,
    *,
    method: MethodSpec,
    scenario: ScenarioPosition,
) -> QdlExecutionPath:
    """Build a single executable path for one accepted invariant."""

    identity = f"{invariant.invariant_id}:{method.method_id}:{scenario.scenario_id}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    path_id = f"qdl-invariant-{digest}"
    return QdlExecutionPath(
        path_id=path_id,
        goal_id=f"goal:{invariant.invariant_id}",
        kind="invariant",
        description=f"Verify accepted QDL norm {invariant.invariant_id}.",
        steps=(
            build_step(
                step_id=f"step:{path_id}:0",
                goal_id=f"goal:{invariant.invariant_id}",
                invariant=invariant,
                method=method,
                scenario=scenario,
            ),
        ),
    )


def build_step(
    *,
    step_id: str,
    goal_id: str,
    invariant: InvariantProjection,
    method: MethodSpec,
    scenario: ScenarioPosition,
    effect_ids: tuple[str, ...] = (),
    required_effects: tuple[Struct, ...] = (),
) -> QdlExecutionStep:
    plan = VerificationPlan(
        plan_id=f"plan:{invariant.invariant_id}:{method.method_id}",
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id=scenario.scenario_id,
    )
    return QdlExecutionStep(
        step_id=step_id,
        goal_id=goal_id,
        plan=plan,
        method=method,
        scenario=scenario,
        invariant=invariant,
        required_effects=required_effects,
        effect_ids=effect_ids,
    )


def transition_targets(
    graph: QdlGraph,
) -> dict[tuple[str, str], tuple[str, ...]]:
    """Project explicit state transition targets from the executable graph."""

    targets: dict[tuple[str, str], set[str]] = {}
    for fact in graph.facts:
        if fact.predicate.name != "transition" or len(fact.args) != 3:
            continue
        action, from_state, to_state = (atom_value(item) for item in fact.args)
        if action is None or from_state is None or to_state is None:
            continue
        targets.setdefault((action, from_state), set()).add(to_state)
    return {key: tuple(sorted(values)) for key, values in targets.items() if values}


def forbidden_statement(
    action: str,
    from_state: str,
    to_state: str,
    norm: str,
    *,
    final: bool,
) -> str:
    if not final:
        return (
            f"Action {action!r} must not advance the forbidden-state sequence "
            f"for norm {norm!r} from {from_state!r} to {to_state!r}."
        )
    return (
        f"Norm {norm!r} forbids reaching business state {to_state!r}; "
        f"action {action!r} must not move the resource from "
        f"{from_state!r} to {to_state!r}."
    )


__all__ = [
    "bind_attack_path",
    "bind_forbidden_path",
    "build_step",
    "forbidden_statement",
    "invariant_path",
    "path_key",
    "select_edge_invariant",
    "transition_targets",
]
