"""Build derivation-based QDL coverage from canonical models and runtime evidence."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from cloud_dast.contracts.assessment import (
    BindingDeficit,
    CoverageMatrix,
    EffectCoverageCell,
    FieldCoverageCell,
    ForbiddenStateCoverage,
    StateMachineCoverage,
    StateMachineMismatchCoverage,
    StateMachineStateCoverage,
    StateMachineTransitionCoverage,
    TargetFieldKind,
    TermFactors,
)
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    VerdictStatus,
)
from cloud_dast.model.events import (
    CheckCompleted,
    CoverageUpdated,
    DomainEvent,
    EventScope,
    QdlStepEvaluated,
    canonical_action_id,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    QdlGraph,
    Struct,
    Term,
    Variable,
    canonical_json,
    changed,
    transition,
)
from cloud_dast.qdl.graph import field as resource_field
from cloud_dast.qdl.reasoning import (
    QdlAttackPath,
    QdlForbiddenPath,
    QdlPlan,
    QdlStatePath,
    QdlSubgoal,
    derivable,
)
from cloud_dast.qdl.semantic_norm_compiler import (
    EXPOSURE_WITNESS_NAMES,
    STATE_TRANSITION_DERIVED_ROLE,
    UNCLASSIFIED_FIELD_ROLE,
    DerivedPrimitiveSupport,
    DerivedSetupRequirement,
    derive_field_roles,
    derive_primitive_supports,
    derive_setup_requirements,
)
from cloud_dast.qdl.state_machine import (
    StateMachineEngine,
    StateMachineStatus,
    StateMachineViolation,
)
from cloud_dast.verification.action_runtime import (
    build_action_runtime_ledger,
)
from cloud_dast.verification.norms import (
    EFFECT_PRIMITIVES,
    NormCompiler,
    Primitive,
)
from cloud_dast.verification.term_coverage import (
    _PRIMITIVES,
    evaluate_term_coverage,
)

type StateTransition = tuple[str, str, str]
type ForbiddenState = tuple[str, str]

_ANY_ACTION = Variable(name="AnyAction")
_ANY_EFFECT = Variable(name="AnyEffect")
_ANY_ROLE = Variable(name="AnyRole")
_ANY_TARGET = Variable(name="AnyTarget")


@dataclass(slots=True)
class _FieldUnit:
    """One per-field coverage unit derived from base QDL facts.

    Identity is ``(field term, field kind)``: one term that is both an
    exposed response witness and a mutation target produces two units —
    an output unit and a resource unit — instead of collapsing the two
    coverage aspects into one action-level row.
    """

    field_term: Struct
    field_name: str
    field_kind: TargetFieldKind
    action_ids: set[str] = dataclass_field(default_factory=set)


@dataclass(slots=True)
class _EffectUnit:
    """One per-effect coverage unit derived from ``causes`` facts."""

    effect: Struct
    action_ids: set[str] = dataclass_field(default_factory=set)
    norm_ids: set[str] = dataclass_field(default_factory=set)


@dataclass(slots=True)
class _RuntimeEffectEvidence:
    """Runtime observations bound to one causal effect."""

    effect: Struct
    observation_ids: set[str] = dataclass_field(default_factory=set)
    action_ids: set[str] = dataclass_field(default_factory=set)
    norm_ids: set[str] = dataclass_field(default_factory=set)


class Builder:
    """Build derivation-based QDL coverage.

    ``QdlGraph`` is the coverage source of truth.  ``QdlPlan`` is a derived
    view: it cannot replace the graph, but ``build_plan`` verifies the plan
    against its graph and attaches planned-path references to the projection.
    """

    def __init__(
        self,
        state_machine_engine: StateMachineEngine | None = None,
        norm_compiler: NormCompiler | None = None,
    ) -> None:
        self._state_machine_engine = state_machine_engine or StateMachineEngine()
        self._norm_compiler = norm_compiler or NormCompiler()

    def build(
        self,
        source: object,
        *,
        context: Context = Context.CONTRACT,
        service: str | None = None,
        invariants: Mapping[str, InvariantProjection] | None = None,
        events: Iterable[DomainEvent] | None = None,
        scope: EventScope | None = None,
        paths: Iterable[object] = (),
        planned_paths: Iterable[object] = (),
        binding_deficits: Iterable[BindingDeficit] = (),
        finalize_actions: bool = False,
    ) -> CoverageMatrix:
        """Build coverage from the QDL source and optional runtime evidence."""

        if not isinstance(source, QdlGraph):
            raise TypeError("coverage source must be a QdlGraph")
        return self._build_qdl(
            source,
            context=context,
            service=service,
            invariants=invariants,
            events=events,
            scope=scope,
            paths=paths,
            planned_paths=planned_paths,
            binding_deficits=binding_deficits,
            finalize_actions=finalize_actions,
        )

    def build_plan(
        self,
        plan: QdlPlan,
        graph: QdlGraph,
        *,
        context: Context = Context.CONTRACT,
        service: str | None = None,
        invariants: Mapping[str, InvariantProjection] | None = None,
        events: Iterable[DomainEvent] | None = None,
        scope: EventScope | None = None,
        paths: Iterable[object] = (),
        planned_paths: Iterable[object] = (),
        binding_deficits: Iterable[BindingDeficit] = (),
        finalize_actions: bool = False,
    ) -> CoverageMatrix:
        """Build QDL coverage for one derived plan over its source graph.

        The plan never becomes a second source of truth: the graph supplies
        every coverage decision, while the plan only contributes derived
        planned-path references and its provenance hash.
        """

        if plan.graph_hash != graph.content_hash:
            raise ValueError(
                "plan does not match the graph: "
                f"plan_hash={plan.graph_hash} graph_hash={graph.content_hash}"
            )
        return self._build_qdl(
            graph,
            context=context,
            service=service,
            plan=plan,
            invariants=invariants,
            events=events,
            scope=scope,
            paths=paths,
            planned_paths=planned_paths,
            binding_deficits=binding_deficits,
            finalize_actions=finalize_actions,
        )

    def _build_qdl(
        self,
        graph: QdlGraph,
        *,
        context: Context,
        service: str | None,
        plan: QdlPlan | None = None,
        invariants: Mapping[str, InvariantProjection] | None = None,
        events: Iterable[DomainEvent] | None = None,
        scope: EventScope | None = None,
        paths: Iterable[object] = (),
        planned_paths: Iterable[object] = (),
        binding_deficits: Iterable[BindingDeficit] = (),
        finalize_actions: bool = False,
    ) -> CoverageMatrix:
        runtime_events = (
            scope.run_events(events or ()) if scope is not None else tuple(events or ())
        )
        request_field_executions = _request_field_executions(runtime_events)
        view_contexts = frozenset({context, Context.ACCEPTED})
        plan_paths = _plan_paths_by_action(plan)
        state_plan_paths = _state_plan_paths_by_action(plan)
        runtime_targets, runtime_field_actions, runtime_effects = (
            self._runtime_evidence(
                graph,
                view_contexts,
                invariants or {},
                runtime_events,
            )
        )
        action_runtime = build_action_runtime_ledger(
            graph,
            paths=paths,
            planned_paths=planned_paths
            or (plan.bound_paths if plan is not None else ()),
            events=runtime_events,
            binding_deficits=binding_deficits,
            finalize=finalize_actions,
        )
        return CoverageMatrix(
            service=service or _service_id(graph, context),
            source="qdl",
            plan_hash=plan.graph_hash if plan is not None else "",
            campaign_id=scope.campaign_id if scope is not None else None,
            run_id=scope.run_id if scope is not None else None,
            fields=self._build_field_cells(
                graph,
                view_contexts,
                plan_paths,
                runtime_targets,
                runtime_field_actions,
                request_field_executions,
                _observations_by_target(graph),
            ),
            effects=self._build_effect_cells(
                graph,
                view_contexts,
                plan_paths,
                runtime_effects,
                _observations_by_effect(graph),
            ),
            state_machine=self._build_state_machine(
                graph,
                context,
                state_plan_paths,
            ),
            action_runtime=action_runtime,
        )

    def _build_field_cells(
        self,
        graph: QdlGraph,
        view_contexts: frozenset[Context],
        plan_paths: Mapping[str, tuple[str, ...]],
        runtime_targets: Mapping[tuple[str, str, Primitive], set[str]],
        runtime_field_actions: Mapping[str, set[str]],
        request_field_executions: Mapping[tuple[str, str], set[str]],
        observations: Mapping[tuple[str, str, Primitive], set[str]],
    ) -> tuple[FieldCoverageCell, ...]:
        """Build per-field coverage units from derived views."""

        units = _field_units(graph, view_contexts)
        roles_by_field: dict[str, dict[str, set[str]]] = defaultdict(
            lambda: {"causes": set(), "declared": set()}
        )
        for row in derive_field_roles(graph, contexts=view_contexts):
            source = "causes" if row.source_predicate == "causes" else "declared"
            roles_by_field[canonical_json(row.field_term)][source].add(row.role)

        supports: dict[tuple[str, str], dict[Primitive, frozenset[str]]] = defaultdict(
            dict
        )
        for row in derive_primitive_supports(graph, contexts=view_contexts):
            if not derivable(_support_requirement(row), graph, contexts=view_contexts):
                continue
            key = (canonical_json(row.field_term), row.role)
            supports[key][row.primitive] = supports[key].get(
                row.primitive, frozenset()
            ) | frozenset(row.norm_ids)

        runtime_by_field_role: dict[tuple[str, str], dict[Primitive, set[str]]] = (
            defaultdict(dict)
        )
        for (field_key, role, primitive), ids in runtime_targets.items():
            runtime_by_field_role[(field_key, role)][primitive] = set(ids)
        observed_by_field_role: dict[tuple[str, str], dict[Primitive, set[str]]] = (
            defaultdict(dict)
        )
        for (field_key, role, primitive), ids in observations.items():
            observed_by_field_role[(field_key, role)][primitive] = set(ids)

        cells: list[FieldCoverageCell] = []
        for (field_key, _unit_kind), unit in sorted(
            units.items(),
            key=lambda item: (canonical_json(item[1].field_term), item[0][1]),
        ):
            semantic_derivable = any(
                derivable(requirement, graph, contexts=view_contexts)
                for requirement in _semantic_requirements(unit)
            )
            field_roles = roles_by_field.get(
                field_key, {"causes": set(), "declared": set()}
            )
            if unit.field_kind == "resource":
                roles = set(field_roles["causes"])
            else:
                roles = set(field_roles["declared"])
            if not semantic_derivable:
                roles = set()
            if not roles:
                roles = {UNCLASSIFIED_FIELD_ROLE}
            action_ids = tuple(
                sorted(unit.action_ids | runtime_field_actions.get(field_key, set()))
            )
            plan_path_ids = _plan_paths_for_actions(unit.action_ids, plan_paths)
            setup_derivable = _requirements_derivable(
                graph,
                view_contexts,
                derive_setup_requirements(unit.field_term, aspect=unit.field_kind),
            )
            request_execution_ids = tuple(
                sorted(
                    {
                        observation_id
                        for action_id in action_ids
                        for observation_id in request_field_executions.get(
                            (action_id, unit.field_name), ()
                        )
                    }
                )
            )
            request_executed = bool(request_execution_ids)
            request_deficit = unit.field_kind == "input" and not request_executed

            for role in sorted(roles):
                semantic_factor = semantic_derivable and (
                    role != UNCLASSIFIED_FIELD_ROLE
                )
                static_supports = supports.get((field_key, role), {})
                runtime_primitives = runtime_by_field_role.get((field_key, role), {})
                observed = observed_by_field_role.get((field_key, role), {})
                primitives = sorted({*static_supports, *runtime_primitives, *observed})
                for primitive in primitives or ("unknown",):
                    observation_ids = tuple(
                        sorted(
                            runtime_primitives.get(primitive, set())
                            | observed.get(primitive, set())
                        )
                    )
                    norm_ids = tuple(sorted(static_supports.get(primitive, ())))
                    factors = TermFactors(
                        semantic=semantic_factor,
                        setup=setup_derivable or bool(observation_ids),
                        oracle_channel=bool(primitives),
                        oracle_primitive=primitive != "unknown",
                        runtime=bool(observation_ids),
                    )
                    evaluation = evaluate_term_coverage(factors)
                    rationale = evaluation.rationale
                    if observation_ids:
                        rationale = "field has runtime evidence for this primitive"
                    elif request_executed and evaluation.missing_factor == "runtime":
                        rationale = (
                            "request field was executed but no oracle witness observed"
                        )

                    cells.append(
                        FieldCoverageCell(
                            field_id=field_key,
                            field_name=unit.field_name,
                            field_kind=unit.field_kind,
                            semantic_role=role,
                            primitive=primitive,
                            status=evaluation.status,
                            deficit=evaluation.deficit,
                            action_ids=action_ids,
                            norm_ids=norm_ids,
                            observation_ids=observation_ids,
                            request_executed=request_executed,
                            request_execution_ids=request_execution_ids,
                            request_deficit=request_deficit,
                            oracle_witness_observed=bool(observation_ids),
                            plan_path_ids=plan_path_ids,
                            rationale=rationale,
                            missing_factor=evaluation.missing_factor,
                            factors=factors,
                        )
                    )
        return tuple(cells)

    def _build_effect_cells(
        self,
        graph: QdlGraph,
        view_contexts: frozenset[Context],
        plan_paths: Mapping[str, tuple[str, ...]],
        runtime_effects: Mapping[str, _RuntimeEffectEvidence],
        observations: Mapping[str, set[str]],
    ) -> tuple[EffectCoverageCell, ...]:
        """Build per-effect coverage units from ``causes`` facts."""

        units = _effect_units(graph, view_contexts)
        cells: list[EffectCoverageCell] = []
        for declared, source in ((True, units), (False, runtime_effects)):
            for effect_key, unit in sorted(source.items()):
                if not declared and effect_key in units:
                    continue
                primitive = EFFECT_PRIMITIVES.get(unit.effect.name, "unknown")
                runtime = runtime_effects.get(effect_key)
                observation_ids = tuple(
                    sorted(
                        (observations.get(effect_key, set()) if declared else set())
                        | (runtime.observation_ids if runtime is not None else set())
                    )
                )
                action_ids = tuple(
                    sorted(
                        unit.action_ids
                        | (runtime.action_ids if runtime is not None else set())
                    )
                )
                norm_ids = tuple(
                    sorted(
                        unit.norm_ids
                        | (runtime.norm_ids if runtime is not None else set())
                    )
                )
                plan_path_ids = (
                    _plan_paths_for_actions(unit.action_ids, plan_paths)
                    if declared
                    else ()
                )
                factors = TermFactors(
                    semantic=True,
                    setup=(
                        not declared
                        or _requirements_derivable(
                            graph,
                            view_contexts,
                            derive_setup_requirements(unit.effect, aspect="effect"),
                        )
                        or bool(observation_ids)
                    ),
                    oracle_channel=True,
                    oracle_primitive=primitive != "unknown",
                    runtime=bool(observation_ids),
                )
                evaluation = evaluate_term_coverage(factors)
                rationale = evaluation.rationale
                if evaluation.status == "covered":
                    rationale = (
                        "effect has runtime evidence"
                        if declared
                        else "runtime evidence proves the effect without a causes fact"
                    )
                cells.append(
                    EffectCoverageCell(
                        effect_id=effect_key,
                        effect_kind=unit.effect.name,
                        primitive=primitive,
                        status=evaluation.status,
                        deficit=evaluation.deficit,
                        action_ids=action_ids,
                        norm_ids=norm_ids,
                        observation_ids=observation_ids,
                        plan_path_ids=(
                            plan_path_ids
                            if declared
                            else _plan_paths_for_actions(unit.action_ids, plan_paths)
                        ),
                        rationale=rationale,
                        missing_factor=evaluation.missing_factor,
                        factors=factors,
                    )
                )
        return tuple(
            sorted(
                cells, key=lambda cell: (cell.effect_id, cell.primitive, cell.status)
            )
        )

    def _runtime_evidence(
        self,
        graph: QdlGraph,
        view_contexts: frozenset[Context],
        invariants: Mapping[str, InvariantProjection],
        events: Iterable[DomainEvent],
    ) -> tuple[
        dict[tuple[str, str, Primitive], set[str]],
        dict[str, set[str]],
        dict[str, _RuntimeEffectEvidence],
    ]:
        """Extract per-field and per-effect evidence from runtime events."""

        events = tuple(events)
        observations_by_check = {
            event.observation.check_id: event.observation
            for event in events
            if isinstance(event, CheckCompleted)
        }
        # The runner publishes scheduler-safe progress: PASS/FAIL here already
        # requires a deterministic, grounded PolicyVerdict. CoverageUpdated
        # alone is emitted before oracle evaluation and proves only execution.
        witnessed_steps = {
            (
                event.check_id,
                event.observation_id,
                canonical_action_id(event.action_id),
                canonical_json(event.norm_fact),
            ): event
            for event in events
            if isinstance(event, QdlStepEvaluated)
            and event.action_id is not None
            and event.norm_fact is not None
        }
        roles_by_field: dict[str, set[str]] = defaultdict(set)
        for row in derive_field_roles(graph, contexts=view_contexts):
            roles_by_field[canonical_json(row.field_term)].add(row.role)

        targets: dict[tuple[str, str, Primitive], set[str]] = defaultdict(set)
        field_actions: dict[str, set[str]] = defaultdict(set)
        effects: dict[str, _RuntimeEffectEvidence] = {}

        for event in events:
            if not isinstance(event, CoverageUpdated):
                continue
            event_actions = _action_ids_for_method(event.method_id)

            invariant = invariants.get(event.invariant_id)
            if invariant is None or invariant.norm_fact is None:
                continue
            try:
                compilation = self._norm_compiler.compile(invariant.norm_fact)
            except ValueError:
                continue

            observation = observations_by_check.get(event.check_id)
            if observation is None:
                continue
            witness = witnessed_steps.get(
                (
                    event.check_id,
                    observation.observation_id,
                    canonical_action_id(event.method_id),
                    canonical_json(invariant.norm_fact),
                )
            )
            if (
                witness is None
                or witness.verdict not in {VerdictStatus.PASS, VerdictStatus.FAIL}
                or witness.norm_fact is None
                or witness.norm_fact != invariant.norm_fact
                or (
                    event.observation_id is not None
                    and event.observation_id != observation.observation_id
                )
                or (event.path_id is not None and event.path_id != witness.path_id)
                or (event.step_id is not None and event.step_id != witness.step_id)
            ):
                continue

            effect_key = canonical_json(compilation.effect)
            runtime_effect = effects.setdefault(
                effect_key,
                _RuntimeEffectEvidence(effect=compilation.effect),
            )
            runtime_effect.observation_ids.add(observation.observation_id)
            runtime_effect.action_ids.update(event_actions)
            runtime_effect.norm_ids.add(invariant.norm_id)

            for field_term in _effect_field_terms(compilation.effect):
                field_key = canonical_json(field_term)
                field_actions[field_key].update(event_actions)
                if compilation.effect.name == "changed":
                    field_roles = {STATE_TRANSITION_DERIVED_ROLE}
                else:
                    field_roles = roles_by_field.get(field_key) or {
                        UNCLASSIFIED_FIELD_ROLE
                    }
                for role in field_roles:
                    targets[(field_key, role, compilation.primitive)].add(
                        observation.observation_id
                    )

        return dict(targets), dict(field_actions), effects

    def _build_state_machine(
        self,
        graph: QdlGraph,
        context: Context,
        plan_paths: Mapping[str, tuple[str, ...]],
    ) -> StateMachineCoverage:
        specification = _state_machine_transitions(graph, context)
        observed = _state_machine_transitions(graph, Context.RUNTIME)
        initial_states = _initial_states(graph, context)
        forbidden = _forbidden_states(graph, context)
        declared_states = _declared_identifiers(graph, context, "State")

        states = {
            *declared_states,
            *initial_states,
            *(state for _, state in forbidden),
            *(from_state for _, from_state, _ in specification),
            *(to_state for _, _, to_state in specification),
            *(from_state for _, from_state, _ in observed),
            *(to_state for _, _, to_state in observed),
        }

        solution = self._state_machine_engine.solve(graph, context=context)
        mismatches = self._state_machine_engine.mismatches(
            graph,
            specification_context=context,
            observed_context=Context.RUNTIME,
        )
        violations = {
            (violation.norm, violation.state): violation
            for violation in solution.violations
        }
        transition_norms = self._transition_norms(graph, context)

        return StateMachineCoverage(
            states=_state_machine_state_cells(
                states,
                specification,
                observed,
                initial_states,
                forbidden,
                solution.reachable_states,
            ),
            transitions=_state_machine_transition_cells(
                specification,
                observed,
                transition_norms,
                plan_paths,
            ),
            forbidden_states=_forbidden_state_cells(
                forbidden,
                initial_states,
                solution.reachable_states,
                violations,
                solution_complete=(solution.status is StateMachineStatus.COMPLETE),
            ),
            mismatches=tuple(
                StateMachineMismatchCoverage(
                    action_id=mismatch.action,
                    from_state=mismatch.from_state,
                    to_state=mismatch.to_state,
                )
                for mismatch in mismatches
            ),
            initial_states=tuple(sorted(initial_states)),
            reachable_states=solution.reachable_states,
        )

    def _transition_norms(
        self,
        graph: QdlGraph,
        context: Context,
    ) -> dict[StateTransition, set[str]]:
        """Link accepted transition norms to the actions that cause them."""

        actions_by_effect: dict[str, set[str]] = defaultdict(set)
        for fact in graph.facts:
            if fact.context is not context:
                continue
            if fact.predicate.name == "transition" and len(fact.args) == 3:
                action, from_state, to_state = fact.args
                effect = transition(from_state, to_state)
            elif fact.predicate.name == "causes" and len(fact.args) == 2:
                action, effect = fact.args
                if not isinstance(effect, Struct) or effect.name != "transition":
                    continue
            else:
                continue
            action_id = _term_key(action)
            if action_id is not None:
                actions_by_effect.setdefault(canonical_json(effect), set()).add(
                    action_id
                )

        norms: dict[StateTransition, set[str]] = defaultdict(set)
        for fact in graph.facts:
            if fact.context is not Context.ACCEPTED:
                continue
            if fact.predicate.name != "prevents" or len(fact.args) != 2:
                continue
            try:
                compilation = self._norm_compiler.compile(fact)
            except ValueError:
                continue
            if compilation.effect.name != "transition":
                continue
            from_state = _term_key(compilation.effect.args[0])
            to_state = _term_key(compilation.effect.args[1])
            if from_state is None or to_state is None:
                continue
            norm_id = _term_key(fact.args[0])
            for action_id in actions_by_effect.get(
                canonical_json(compilation.effect),
                (),
            ):
                norms[(action_id, from_state, to_state)].add(norm_id)
        return dict(norms)


def _requirements_derivable(
    graph: QdlGraph,
    contexts: frozenset[Context],
    requirements: tuple[DerivedSetupRequirement, ...],
) -> bool:
    """Return whether at least one setup requirement is derivable.

    The S24R setup factor holds when one requirement of the term's
    disjunction is derivable from the graph.
    """

    if not requirements:
        return True
    return any(
        derivable(
            QdlSubgoal(
                predicate=requirement.predicate,
                args=requirement.args,
            ),
            graph,
            contexts=contexts,
        )
        for requirement in requirements
    )


def _semantic_requirements(unit: _FieldUnit) -> tuple[QdlSubgoal, ...]:
    """Return the semantic-fact requirement subgoals for one field unit."""

    if unit.field_kind == "resource":
        if unit.field_term.name == "field" and len(unit.field_term.args) == 2:
            effect = changed(unit.field_term.args[0], unit.field_term.args[1])
            return (QdlSubgoal(predicate="causes", args=(_ANY_ACTION, effect)),)
        return ()
    return (
        QdlSubgoal(predicate="has", args=(unit.field_term, _ANY_ROLE)),
        QdlSubgoal(predicate="refers_to", args=(unit.field_term, _ANY_TARGET)),
    )


def _support_requirement(row: DerivedPrimitiveSupport) -> QdlSubgoal:
    """Return the derivation subgoal behind one derived primitive support."""

    if row.source_predicate == "exposes":
        return QdlSubgoal(predicate="exposes", args=(_ANY_ACTION, row.field_term))
    if row.source_predicate == "has":
        return QdlSubgoal(predicate="has", args=(row.field_term, Atom(value=row.role)))
    if row.effect is None:
        return QdlSubgoal(predicate="causes", args=(_ANY_ACTION, _ANY_EFFECT))
    return QdlSubgoal(predicate="causes", args=(_ANY_ACTION, row.effect))


def _plan_paths_by_action(
    plan: QdlPlan | None,
) -> dict[str, tuple[str, ...]]:
    if plan is None:
        return {}
    paths: dict[str, set[str]] = defaultdict(set)
    for path in plan.bound_paths:
        for action in _plan_path_actions(path):
            paths[action].add(path.path_id)
    return {action: tuple(sorted(ids)) for action, ids in paths.items()}


def _state_plan_paths_by_action(
    plan: QdlPlan | None,
) -> dict[str, tuple[str, ...]]:
    if plan is None:
        return {}
    paths: dict[str, set[str]] = defaultdict(set)
    for path in plan.state_paths:
        for action in path.actions:
            paths[action].add(path.path_id)
    for forbidden in plan.forbidden_paths:
        for action in forbidden.path.actions:
            paths[action].add(forbidden.path_id)
    return {action: tuple(sorted(ids)) for action, ids in paths.items()}


def _plan_paths_for_actions(
    actions: Iterable[str],
    plan_paths: Mapping[str, tuple[str, ...]],
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {path_id for action in actions for path_id in plan_paths.get(action, ())}
        )
    )


def _plan_path_actions(
    path: QdlAttackPath | QdlStatePath | QdlForbiddenPath,
) -> tuple[str, ...]:
    if isinstance(path, QdlForbiddenPath):
        return path.path.actions
    return path.actions


def _service_id(graph: QdlGraph, context: Context) -> str:
    services = sorted(
        _term_key(fact.args[0])
        for fact in graph.facts_for("is", contexts={context})
        if len(fact.args) == 2 and _term_key(fact.args[1]) == "Service"
    )
    return services[0] if services else ""


def _declared_identifiers(
    graph: QdlGraph,
    context: Context,
    type_name: str,
) -> set[str]:
    return {
        _term_key(fact.args[0])
        for fact in graph.facts_for("is", contexts={context})
        if len(fact.args) == 2 and _term_key(fact.args[1]) == type_name
    }


def _field_units(
    graph: QdlGraph,
    contexts: frozenset[Context],
) -> dict[tuple[str, TargetFieldKind], _FieldUnit]:
    """Project the per-field coverage universe from base QDL facts.

    A field term may participate in several aspects (an exposed response
    witness, a mutated resource field); each aspect is its own coverage
    unit keyed by ``(term, kind)``.
    """

    declarations = {
        canonical_json(fact.args[0]): _term_key(fact.args[1])
        for fact in graph.facts_for("is", contexts=contexts)
        if len(fact.args) == 2
    }
    units: dict[tuple[str, TargetFieldKind], _FieldUnit] = {}

    def unit_for(
        field_term: Struct,
        field_name: str,
        field_kind: TargetFieldKind,
        action_id: str | None,
    ) -> None:
        key = (canonical_json(field_term), field_kind)
        unit = units.setdefault(
            key,
            _FieldUnit(
                field_term=field_term,
                field_name=field_name,
                field_kind=field_kind,
            ),
        )
        if action_id:
            unit.action_ids.add(action_id)

    for fact in graph.facts_for("is", contexts=contexts):
        if len(fact.args) != 2 or not isinstance(fact.args[0], Struct):
            continue
        field_term, declared_type = fact.args
        if not isinstance(declared_type, Atom):
            continue
        if declared_type.value == "InputField":
            field_kind: TargetFieldKind = "input"
        elif declared_type.value == "OutputField":
            field_kind = "output"
        else:
            continue
        action_term = field_term.args[0] if field_term.args else None
        action_id = _term_key(action_term) if isinstance(action_term, Atom) else None
        unit_for(field_term, _field_name(field_term), field_kind, action_id)

    for fact in graph.facts_for("part", contexts=contexts):
        field_term, action = fact.args
        if not isinstance(field_term, Struct):
            continue
        declaration = declarations.get(canonical_json(field_term))
        if declaration == "InputField":
            kind: TargetFieldKind = "input"
        elif declaration == "OutputField":
            kind = "output"
        else:
            continue
        unit_for(field_term, _field_name(field_term), kind, _term_key(action))

    for fact in graph.facts_for("exposes", contexts=contexts):
        if len(fact.args) != 2:
            continue
        action, witness = fact.args
        if not isinstance(witness, Struct):
            continue
        if witness.name not in EXPOSURE_WITNESS_NAMES or len(witness.args) != 2:
            continue
        unit_for(
            witness,
            _term_key(witness.args[1]),
            "output",
            _term_key(action),
        )

    for fact in graph.facts_for("causes", contexts=contexts):
        action, effect = fact.args
        if not isinstance(effect, Struct) or effect.name != "changed":
            continue
        field_term = resource_field(effect.args[0], effect.args[1])
        unit_for(
            field_term,
            _term_key(effect.args[1]),
            "resource",
            _term_key(action),
        )

    return units


def _effect_units(
    graph: QdlGraph,
    contexts: frozenset[Context],
) -> dict[str, _EffectUnit]:
    """Project the per-effect coverage universe from ``causes`` facts.

    Transition effects are excluded: the state-machine projection owns
    state and transition coverage.
    """

    norms_by_effect: dict[str, set[str]] = defaultdict(set)
    for fact in graph.facts:
        if fact.context is not Context.ACCEPTED:
            continue
        if fact.predicate.name != "prevents" or len(fact.args) != 2:
            continue
        norm, effect = fact.args
        if not isinstance(effect, Struct):
            continue
        norms_by_effect[canonical_json(effect)].add(_term_key(norm))

    units: dict[str, _EffectUnit] = {}
    for fact in graph.facts:
        if fact.context not in contexts or fact.predicate.name != "causes":
            continue
        if len(fact.args) != 2:
            continue
        action, effect = fact.args
        if not isinstance(effect, Struct) or effect.name == "transition":
            continue
        key = canonical_json(effect)
        unit = units.setdefault(key, _EffectUnit(effect=effect))
        unit.action_ids.add(_term_key(action))
        unit.norm_ids.update(norms_by_effect.get(key, ()))

    return units


def _field_name(field_term: Struct) -> str:
    if field_term.name in {"input_field", "output_field", "field"}:
        return _term_key(field_term.args[1])
    return canonical_json(field_term)


def _term_key(term: Term) -> str:
    if isinstance(term, Atom):
        return str(term.value)
    return canonical_json(term)


def _action_ids_for_method(method_id: str) -> set[str]:
    """Return both action spellings used by QDL and method repositories."""

    if method_id.startswith("action:"):
        return {method_id, method_id.removeprefix("action:")}
    return {method_id, f"action:{method_id}"}


def _request_field_executions(
    events: Iterable[DomainEvent],
) -> dict[tuple[str, str], set[str]]:
    """Project actually executed request fields independently of oracle witnesses."""

    executions: dict[tuple[str, str], set[str]] = defaultdict(set)
    for event in events:
        if not isinstance(event, CheckCompleted):
            continue
        observation = event.observation
        if observation.trace is None:
            continue
        for step in observation.trace.steps:
            if step.observation_id != observation.observation_id:
                continue
            for field_name in step.request_fields:
                if not isinstance(field_name, str):
                    continue
                for action_id in _action_ids_for_method(step.method_id):
                    executions[(action_id, field_name)].add(observation.observation_id)
    return dict(executions)


def _effect_field_terms(effect: Struct) -> tuple[Struct, ...]:
    """Extract the target field addressed by a norm effect."""

    if effect.name == "changed" and len(effect.args) == 2:
        return (resource_field(effect.args[0], effect.args[1]),)
    if effect.name == "has" and len(effect.args) == 2:
        value = effect.args[1]
        if isinstance(value, Struct):
            return (value,)
        if isinstance(value, Atom):
            return (resource_field(effect.args[0], value),)
    return ()


def _observations_by_target(
    graph: QdlGraph,
) -> dict[tuple[str, str, Primitive], set[str]]:
    """Index runtime ``evidence_target`` bindings per coverage unit."""

    observations: dict[tuple[str, str, Primitive], set[str]] = defaultdict(set)
    observed_ids = {
        _term_key(fact.args[0])
        for fact in graph.facts_for("evidence", contexts={Context.RUNTIME})
    }
    for fact in graph.facts_for("evidence_target", contexts={Context.RUNTIME}):
        observation, _action, field_term, role, primitive = fact.args
        observation_id = _term_key(observation)
        if observation_id not in observed_ids:
            continue
        primitive_name = _term_key(primitive)
        if primitive_name not in _PRIMITIVES:
            raise ValueError(f"unknown primitive: {primitive_name}")
        observations[
            (
                canonical_json(field_term),
                _term_key(role),
                primitive_name,
            )
        ].add(observation_id)
    return dict(observations)


def _observations_by_effect(graph: QdlGraph) -> dict[str, set[str]]:
    """Index runtime ``evidence(Observation, Effect)`` facts per effect."""

    observations: dict[str, set[str]] = defaultdict(set)
    for fact in graph.facts_for("evidence", contexts={Context.RUNTIME}):
        if len(fact.args) != 2:
            continue
        observation, effect = fact.args
        if not isinstance(effect, Struct) or effect.name == "transition":
            continue
        observations[canonical_json(effect)].add(_term_key(observation))
    return dict(observations)


def _state_machine_transitions(
    graph: QdlGraph,
    context: Context,
) -> set[StateTransition]:
    return {
        (_term_key(fact.args[0]), _term_key(fact.args[1]), _term_key(fact.args[2]))
        for fact in graph.facts_for("transition", contexts={context})
    }


def _initial_states(graph: QdlGraph, context: Context) -> set[str]:
    return {
        _term_key(fact.args[0])
        for fact in graph.facts_for("initial", contexts={context})
    }


def _forbidden_states(
    graph: QdlGraph,
    context: Context,
) -> set[ForbiddenState]:
    return {
        (_term_key(fact.args[0]), _term_key(fact.args[1]))
        for fact in graph.facts_for("forbidden", contexts={context})
    }


def _state_machine_state_cells(
    states: set[str],
    specification: set[StateTransition],
    observed: set[StateTransition],
    initial_states: set[str],
    forbidden: set[ForbiddenState],
    reachable_states: tuple[str, ...],
) -> tuple[StateMachineStateCoverage, ...]:
    transitions = sorted(specification | observed)
    cells: list[StateMachineStateCoverage] = []
    for state_id in sorted(states):
        incoming = tuple(
            _transition_id(action, from_state, to_state)
            for action, from_state, to_state in transitions
            if to_state == state_id
        )
        outgoing = tuple(
            _transition_id(action, from_state, to_state)
            for action, from_state, to_state in transitions
            if from_state == state_id
        )
        observed_touch = any(
            from_state == state_id or to_state == state_id
            for _, from_state, to_state in observed
        )
        reachable = state_id in reachable_states
        factors = TermFactors(
            semantic=True,
            setup=reachable or observed_touch,
            oracle_channel=True,
            oracle_primitive=True,
            runtime=observed_touch,
        )
        evaluation = evaluate_term_coverage(
            factors,
            rationale="state has runtime transition evidence" if observed_touch else "",
        )
        cells.append(
            StateMachineStateCoverage(
                state_id=state_id,
                initial=state_id in initial_states,
                reachable=reachable,
                incoming_transition_ids=incoming,
                outgoing_transition_ids=outgoing,
                forbidden_norm_ids=tuple(
                    sorted(norm for norm, state in forbidden if state == state_id)
                ),
                status=evaluation.status,
                deficit=evaluation.deficit,
                rationale=evaluation.rationale,
                missing_factor=evaluation.missing_factor,
                factors=factors,
            )
        )
    return tuple(cells)


def _state_machine_transition_cells(
    specification: set[StateTransition],
    observed: set[StateTransition],
    transition_norms: Mapping[StateTransition, set[str]],
    plan_paths: Mapping[str, tuple[str, ...]],
) -> tuple[StateMachineTransitionCoverage, ...]:
    specification_keys = set(specification)
    observed_keys = set(observed)
    cells: list[StateMachineTransitionCoverage] = []
    for action, from_state, to_state in sorted(specification | observed):
        transition_id = _transition_id(action, from_state, to_state)
        in_specification = (action, from_state, to_state) in specification_keys
        is_observed = (action, from_state, to_state) in observed_keys
        factors = TermFactors(
            semantic=True,
            setup=True,
            oracle_channel=True,
            oracle_primitive=True,
            runtime=is_observed,
            # An observed transition absent from the specification is
            # runtime counter-evidence about the specification, not a
            # coverage requirement: it stays informational and is reported
            # through the mismatch projection.
            required=in_specification,
        )
        evaluation = evaluate_term_coverage(
            factors,
            rationale=(
                "observed transition is absent from the specification"
                if not in_specification
                else ""
            ),
        )
        cells.append(
            StateMachineTransitionCoverage(
                transition_id=transition_id,
                action_id=action,
                from_state=from_state,
                to_state=to_state,
                in_specification=in_specification,
                observed=is_observed,
                norm_ids=tuple(
                    sorted(
                        transition_norms.get(
                            (action, from_state, to_state),
                            (),
                        )
                    )
                ),
                plan_path_ids=plan_paths.get(action, ()),
                status=evaluation.status,
                deficit=evaluation.deficit,
                rationale=evaluation.rationale,
                missing_factor=evaluation.missing_factor,
                factors=factors,
            )
        )
    return tuple(cells)


def _forbidden_state_cells(
    forbidden: set[ForbiddenState],
    initial_states: set[str],
    reachable_states: tuple[str, ...],
    violations: Mapping[tuple[str, str], StateMachineViolation],
    *,
    solution_complete: bool,
) -> tuple[ForbiddenStateCoverage, ...]:
    cells: list[ForbiddenStateCoverage] = []
    for norm_id, state_id in sorted(forbidden):
        violation = violations.get((norm_id, state_id))
        reachable = state_id in reachable_states
        rationale = ""
        if not initial_states:
            factors = TermFactors(
                semantic=True,
                setup=False,
                oracle_channel=True,
                oracle_primitive=True,
                runtime=False,
            )
            rationale = "state machine has no initial state"
        elif reachable:
            factors = TermFactors(
                semantic=True,
                setup=True,
                oracle_channel=True,
                oracle_primitive=True,
                runtime=False,
            )
            rationale = "forbidden state is reachable and requires verification"
        elif solution_complete:
            factors = TermFactors(
                semantic=True,
                setup=True,
                oracle_channel=True,
                oracle_primitive=True,
                runtime=True,
            )
            rationale = (
                "state is unreachable in the complete solution; the ban is proven"
            )
        else:
            factors = TermFactors(
                semantic=True,
                setup=True,
                oracle_channel=True,
                oracle_primitive=False,
                runtime=False,
            )
            rationale = "no bounded witness exists; absence is not proven"
        evaluation = evaluate_term_coverage(factors, rationale=rationale)
        cells.append(
            ForbiddenStateCoverage(
                norm_id=norm_id,
                state_id=state_id,
                reachable=reachable,
                witness_initial_state=(
                    violation.path.initial_state if violation is not None else ""
                ),
                witness_actions=violation.path.actions if violation is not None else (),
                status=evaluation.status,
                deficit=evaluation.deficit,
                rationale=evaluation.rationale,
                missing_factor=evaluation.missing_factor,
                factors=factors,
            )
        )
    return tuple(cells)


def _transition_id(action: str, from_state: str, to_state: str) -> str:
    return f"{action}:{from_state}->{to_state}"
