from __future__ import annotations

from dataclasses import replace

import pytest

from cloud_dast.consultation import (
    ConsultationBudget,
)
from cloud_dast.contracts.execution import ScenarioBinding
from cloud_dast.contracts.feedback import Signal
from cloud_dast.contracts.plan import (
    InvariantProjection,
    QdlExecutionPath,
    QdlExecutionStep,
    QdlExecutionView,
    VerificationPlan,
)
from cloud_dast.model import (
    AccessOutcome,
    EndpointLayer,
    ExecutionTrace,
    FieldSpec,
    MethodSpec,
    Observation,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
    TraceStep,
    VerdictStatus,
)
from cloud_dast.model.events import QdlPathEvaluated, QdlStepEvaluated
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Struct,
    Variable,
    allowed,
    canonical_json,
    changed,
    create,
    denied,
    differs,
    duration,
    field,
    has,
    input_field,
    reached,
    remove,
)
from cloud_dast.qdl.reasoning import QdlInvariant, QdlPlan, QdlSubgoal, derivable
from cloud_dast.runtime.deficits import (
    Deficit,
    axis_for_subgoal,
    blocked_step_deficit,
    classify_step_event,
    consultation_request,
    grounding_result_closes_deficit,
    missing_irreversibility_deficit,
    response_semantics_deficits,
    signal_deficits,
    unprovable_subgoal,
    variance_deficit,
)
from cloud_dast.runtime.deficits import (
    coverage_gaps as coverage_deficits,
)
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)
from cloud_dast.verification.differential.report import DiffReport

_ANY_ACTION = Variable(name="AnyAction")
_ANY_EFFECT = Variable(name="AnyEffect")
_ANY_FIELD = Variable(name="AnyField")
_ANY_ROLE = Variable(name="AnyRole")
_ANY_MS = Variable(name="AnyMilliseconds")
_ANY_NODE = Variable(name="AnyNode")
_ANY_RESOURCE = Variable(name="AnyResource")
_ANY_TARGET = Variable(name="AnyTarget")
_ANY_FROM = Variable(name="AnyFrom")
_ANY_SUBJECT = Variable(name="AnySubject")
_ANY_NORM = Variable(name="AnyNorm")
_ANY_DIMENSION = Variable(name="AnyDimension")
_ANY = Variable(name="Any")


def classify_path_event(
    event: QdlPathEvaluated,
    path: QdlExecutionPath,
) -> Deficit | None:
    """Classify one terminal path event into a reactive deficit."""

    if event.outcome != "blocked" or not path.steps:
        return None
    step_index = min(event.attempted_steps, len(path.steps) - 1)
    return blocked_step_deficit(path, path.steps[step_index], reason=event.reason)


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.ACCEPTED,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _extension_fact(predicate: str, args: tuple[object, ...]) -> Fact:
    schema = next(
        schema for schema in EXTENSION_PREDICATE_SCHEMAS if schema.name == predicate
    )
    return Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_schema(schema),
        args=args,  # type: ignore[arg-type]
    )


def _method(method_id: str) -> MethodSpec:
    return MethodSpec(
        method_id=method_id,
        service="svc",
        name=method_id.rsplit(".", 1)[-1],
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="resource_id", type="string", required=True),),
    )


def _scenario() -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="scenario",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PRIVATE,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(),
    )


def _invariant(method_id: str) -> InvariantProjection:
    return InvariantProjection(
        invariant_id=f"invariant:{method_id}",
        norm_id=f"norm:{method_id}",
        statement="test invariant",
        severity=Severity.HIGH,
    )


def _plan(method_id: str) -> VerificationPlan:
    return VerificationPlan(
        plan_id=f"plan:{method_id}",
        invariant_id=f"invariant:{method_id}",
        method_id=method_id,
        scenario_id="scenario",
    )


def _step(step_id: str, method_id: str = "get") -> QdlExecutionStep:
    return QdlExecutionStep(
        step_id=step_id,
        goal_id="goal:test",
        plan=_plan(method_id),
        method=_method(method_id),
        scenario=_scenario(),
        invariant=_invariant(method_id),
    )


def _path(
    path_id: str,
    method_ids: tuple[str, ...] = ("get",),
) -> QdlExecutionPath:
    return QdlExecutionPath(
        path_id=path_id,
        goal_id=f"goal:{path_id}",
        kind="invariant",
        description="test path",
        steps=tuple(
            _step(f"step:{path_id}:{index}", method_id)
            for index, method_id in enumerate(method_ids)
        ),
    )


def _effect_step(step_id: str, effect: Struct) -> QdlExecutionStep:
    step = _step(step_id, "get")
    norm_fact = Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name("prevents"),
        args=(Atom(value=f"norm:{step_id}"), effect),
    )
    return replace(
        step, invariant=step.invariant.model_copy(update={"norm_fact": norm_fact})
    )


def _blocked_path(path_id: str, effects: tuple[Struct, ...]) -> QdlExecutionPath:
    return QdlExecutionPath(
        path_id=path_id,
        goal_id=f"goal:{path_id}",
        kind="invariant",
        description="test blocked path",
        steps=tuple(
            _effect_step(f"step:{path_id}:{index}", effect)
            for index, effect in enumerate(effects)
        ),
    )


def _response_invariant(action: str, field_name: str) -> QdlInvariant:
    effect = has(
        Atom(value=action),
        field(Atom(value="resource:secret"), Atom(value=field_name)),
    )
    return QdlInvariant(
        norm=Atom(value=f"norm:{action}:{field_name}"),
        effect=effect,
        primitive="response_field",
        required_evidence=("response_field",),
        verdict_policy="deterministic",
        fact=_fact("prevents", (Atom(value=f"norm:{action}:{field_name}"), effect)),
    )


def _binding(
    graph: QdlGraph,
    *,
    paths: tuple[QdlExecutionPath, ...] = (),
    invariants: tuple[QdlInvariant, ...] = (),
) -> ScenarioBinding:
    graph_hash = graph.content_hash
    return ScenarioBinding(
        scenario=_scenario(),
        graph=graph,
        plan=QdlPlan(graph_hash=graph_hash, invariants=invariants),
        execution=QdlExecutionView(
            graph_hash=graph_hash,
            paths=paths,
            invariants={},
        ),
        invariants={},
        methods=(),
    )


def _graph_with_input_role(action_key: str) -> QdlGraph:
    action = Atom(value=action_key)
    role_field = input_field(action, Atom(value="resource_id"))
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (role_field, Atom(value="InputField"))),
            _fact("has", (role_field, Atom(value="object_ref"))),
        )
    )


def _graph_with_exposed_field(action_key: str, field_name: str) -> QdlGraph:
    action = Atom(value=action_key)
    resource = Atom(value="resource:secret")
    witness = field(Atom(value="resource:secret"), Atom(value=field_name))
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("is", (witness, Atom(value="Witness"))),
            _fact("exposes", (action, witness)),
        )
    )


def _response_observation(
    *,
    action: str = "svc.GetUser",
    field_name: str = "email",
    outcome: AccessOutcome = AccessOutcome.ALLOWED,
    response_tree: tuple[tuple[str, object], ...] | None = None,
    observation_id: str = "observation:response",
) -> Observation:
    return Observation(
        check_id="check:response",
        scenario_id="scenario",
        observed_outcome=outcome,
        response_summary="structured response",
        response_tree=(
            ((field_name, "response-value"),)
            if response_tree is None
            else response_tree
        ),
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id=observation_id,
                    step_id="step:response",
                    method_id=action,
                    scenario_id="scenario",
                    status=outcome,
                    request_fields=(field_name,),
                ),
            )
        ),
        observation_id=observation_id,
    )


def _path_event(
    path: QdlExecutionPath,
    *,
    outcome: str,
    attempted_steps: int,
) -> QdlPathEvaluated:
    return QdlPathEvaluated(
        path_id=path.path_id,
        outcome=outcome,  # type: ignore[arg-type]
        attempted_steps=attempted_steps,
        step_count=len(path.steps),
        probe_count=0,
        reason=(
            "QDL effect chain was not verified"
            if outcome == "blocked"
            else "QDL effect chain verified"
        ),
    )


def test_deficit_is_an_unprovable_subgoal_not_a_reason_string() -> None:
    """S21 v2: the deficit is the QDL subgoal; context is provenance."""

    path = _blocked_path("blocked", (denied(Atom(value="action:get")),))
    deficit = blocked_step_deficit(path, path.steps[0])

    assert deficit.subgoal.predicate == "causes"
    assert deficit.subgoal == QdlSubgoal(
        "causes",
        (_ANY_ACTION, denied(Atom(value="action:get"))),
    )
    assert deficit.predicate_class == "causes"
    assert deficit.axis == "alternatives"
    # The action, path, step, and reason never enter the deficit identity.
    assert deficit.action == "get"
    assert all(
        name not in deficit.key for name in ("path_id", "step_id", "reason", "get")
    )


@pytest.mark.parametrize(
    ("subgoal", "expected_axis", "live_response"),
    [
        (
            QdlSubgoal(
                "refers_to",
                (input_field(Atom(value="get"), _ANY_FIELD), _ANY_TARGET),
            ),
            "fixture",
            False,
        ),
        (QdlSubgoal("reaches", (Atom(value="get"), _ANY_NODE)), "dataflows", False),
        (
            QdlSubgoal("causes", (Atom(value="get"), changed(Atom(value="r"), _ANY))),
            "alternatives",
            False,
        ),
        (
            QdlSubgoal(
                "causes",
                (Atom(value="get"), duration(Atom(value="get"), _ANY_MS)),
            ),
            "availability",
            False,
        ),
        (
            QdlSubgoal(
                "causes",
                (_ANY_ACTION, create(Atom(value="lockbox.secret"))),
            ),
            "fixture",
            False,
        ),
        (
            QdlSubgoal(
                "causes",
                (_ANY_ACTION, remove(Atom(value="resource:order"))),
            ),
            "dataflows",
            False,
        ),
        (
            QdlSubgoal(
                "transition",
                (Atom(value="get"), _ANY, Atom(value="archived")),
            ),
            "state",
            False,
        ),
        (
            QdlSubgoal(
                "has",
                (input_field(Atom(value="get"), _ANY_FIELD), _ANY_ROLE),
            ),
            "roles",
            False,
        ),
        (
            QdlSubgoal(
                "exposes",
                (Atom(value="get"), field(_ANY_RESOURCE, Atom(value="email"))),
            ),
            "exposures",
            False,
        ),
        (
            QdlSubgoal(
                "exposes",
                (Atom(value="get"), field(_ANY_RESOURCE, _ANY_FIELD)),
            ),
            "response_semantics",
            True,
        ),
        (
            QdlSubgoal(
                "prevents",
                (_ANY_NORM, differs(Atom(value="get"), _ANY_DIMENSION)),
            ),
            "variance",
            False,
        ),
    ],
)
def test_consultation_axis_is_selected_by_predicate_class(
    subgoal: QdlSubgoal,
    expected_axis: str,
    live_response: bool,
) -> None:
    """S21R: axis is a total function of class and evidence context."""

    assert axis_for_subgoal(subgoal, live_response=live_response) == expected_axis


def test_consultation_deficit_materializes_missing_axis_image() -> None:
    """S21R: a class without an image is a typed deficit, never a KeyError."""

    subgoal = QdlSubgoal(
        "sink_interprets",
        (Atom(value="marker"), _ANY_NODE),
    )

    deficit = unprovable_subgoal(subgoal, QdlGraph(), action="get")

    assert deficit is not None
    assert deficit.subgoal == subgoal
    assert deficit.predicate_class == "sink_interprets"
    assert deficit.axis is None
    assert deficit.is_consultation_deficit
    assert ("deficit_kind", "consultation_deficit") in deficit.context


def test_may_deficit_has_no_false_consultation_image() -> None:
    """No consultation may author a ``may`` fact; absence must be honest.

    Routing a policy-class deficit to ``roles`` would be a false image:
    the roles alphabet is ``{is, has}``, so the consultation could never
    close the deficit.  S21R surfaces the missing producer instead.
    """

    subgoal = QdlSubgoal(
        "may",
        (_ANY_SUBJECT, Atom(value="get"), _ANY_RESOURCE),
    )

    deficit = unprovable_subgoal(subgoal, QdlGraph(), action="get")

    assert deficit is not None
    assert deficit.axis is None
    assert deficit.is_consultation_deficit


def test_consultation_deficit_is_never_dispatched_to_a_model() -> None:
    """The typed gap stays operational: no request, no queue dispatch."""

    deficit = unprovable_subgoal(
        QdlSubgoal("sink_interprets", (Atom(value="marker"), _ANY_NODE)),
        QdlGraph(),
        action="get",
    )
    assert deficit is not None

    request = consultation_request(
        deficit,
        graph=QdlGraph(),
        budget=ConsultationBudget(),
    )
    queue = DeficitQueue(max_tasks=1)

    assert request is None
    assert queue.add((deficit,)) == 1
    assert queue.pop_next() is None
    assert queue.pop_wave() == ()
    assert queue.pending_count == 1
    assert queue.dispatchable is False


def test_unprovable_subgoal_implements_the_deficit_rule() -> None:
    """deficit(R, G) :- requirement(R, G), not derivable(R, G)."""

    subgoal = QdlSubgoal(
        "causes",
        (Atom(value="get"), _ANY_EFFECT),
    )
    derivable_graph = QdlGraph(
        facts=(
            _fact("is", (Atom(value="action:get"), Atom(value="Action"))),
            _fact("is", (denied(Atom(value="action:get")), Atom(value="Effect"))),
            _fact(
                "causes", (Atom(value="action:get"), denied(Atom(value="action:get")))
            ),
        )
    )

    assert unprovable_subgoal(subgoal, derivable_graph) is None

    deficit = unprovable_subgoal(subgoal, QdlGraph(), action="get")
    assert deficit is not None
    assert deficit.subgoal == subgoal
    assert deficit.predicate_class == "causes"
    assert deficit.axis == "alternatives"


def test_blocked_paths_over_one_effect_coalesce_into_one_dispatch() -> None:
    """One subgoal covers every path deficit that requires it."""

    effect = denied(Atom(value="action:get"))
    path_one = _blocked_path("path-one", (effect, effect))
    path_two = _blocked_path("path-two", (effect,))
    other_action = _blocked_path("path-three", (denied(Atom(value="action:delete")),))
    deficits = (
        blocked_step_deficit(path_one, path_one.steps[0]),
        blocked_step_deficit(
            path_one,
            path_one.steps[1],
            reason="different report text",
            recovery_action="reuse_clue",
        ),
        blocked_step_deficit(path_two, path_two.steps[0], clue_observation_id="obs:1"),
        blocked_step_deficit(other_action, other_action.steps[0]),
    )
    queue = DeficitQueue()

    # Three path/step deficits over one subgoal coalesce into one deficit;
    # a different effect stays a different subgoal.
    assert queue.add(deficits) == 2
    wave = queue.pop_wave()
    assert len(wave) == 1
    assert wave[0].predicate_class == "causes"
    assert wave[0].axis == "alternatives"
    assert wave[0].fan_out == 3


def test_missing_irreversibility_requires_exact_action_causes() -> None:
    effect = denied(Atom(value="action:get"))
    path = _blocked_path("missing-irreversibility", (effect,))

    deficit = blocked_step_deficit(
        path,
        path.steps[0],
        reason="missing_irreversibility_fact",
    )

    assert deficit.subgoal == QdlSubgoal(
        "causes",
        (Atom(value="get"), effect),
    )
    assert deficit.axis == "alternatives"


def test_other_action_causing_effect_does_not_unblock_exact_step() -> None:
    effect = denied(Atom(value="action:get"))
    path = _blocked_path("exact-closure", (effect,))
    deficit = blocked_step_deficit(
        path,
        path.steps[0],
        reason="missing_irreversibility_fact",
    )
    other_action = Atom(value="action:other")

    other_action_graph = QdlGraph(
        facts=(
            _fact("is", (Atom(value="action:get"), Atom(value="Action"))),
            _fact("is", (other_action, Atom(value="Action"))),
            _fact("is", (effect, Atom(value="Effect"))),
            _fact("causes", (other_action, effect)),
        )
    )
    exact_action_graph = QdlGraph(
        facts=(
            _fact("is", (Atom(value="action:get"), Atom(value="Action"))),
            _fact("is", (Atom(value="get"), Atom(value="Action"))),
            _fact("is", (effect, Atom(value="Effect"))),
            _fact("causes", (Atom(value="get"), effect)),
        )
    )

    assert not grounding_result_closes_deficit(deficit, other_action_graph)
    assert grounding_result_closes_deficit(deficit, exact_action_graph)


def test_missing_refers_to_creates_reference_deficit() -> None:
    effect = denied(Atom(value="action:get"))
    path = _blocked_path("missing-reference", (effect,))
    step = replace(
        path.steps[0],
        plan=path.steps[0].plan.model_copy(update={"resource_params": ("secret_id",)}),
    )
    deficit = blocked_step_deficit(path, step, reason="missing_refers_to")
    assert deficit.subgoal == QdlSubgoal(
        "refers_to",
        (
            input_field(Atom(value="get"), Atom(value="secret_id")),
            _ANY_TARGET,
        ),
    )
    assert deficit.predicate_class == "refers_to"
    assert dict(deficit.context)["field"] == "secret_id"


def test_missing_state_semantics_creates_state_deficit() -> None:
    effect = denied(Atom(value="action:get"))
    path = _blocked_path("missing-state", (effect,))
    step = path.steps[0]

    deficit = blocked_step_deficit(
        path,
        step,
        reason="missing_state_semantics",
    )

    assert deficit.subgoal == QdlSubgoal(
        "transition",
        (_ANY_ACTION, _ANY_FROM, Atom(value="existing")),
    )
    assert deficit.predicate_class == "transition"
    assert deficit.axis == "state"


def test_derivable_checks_may_through_the_policy_rules() -> None:
    """A may subgoal derivs from the Clingo policy rule pack."""

    subject = Atom(value="subject:admin")
    action = Atom(value="action:get")
    resource = Atom(value="resource:order")
    permission = Atom(value="permission:read")
    resource_type = Atom(value="order")
    graph = QdlGraph(
        facts=(
            _fact("is", (subject, Atom(value="Subject"))),
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("is", (permission, Atom(value="Permission"))),
            _fact("is", (resource_type, Atom(value="ResourceType"))),
            _fact("owner", (resource, subject)),
            _fact("requires", (action, permission)),
            _fact("targets", (action, resource_type)),
            _fact("applies_to", (permission, resource_type)),
            _fact("is", (resource, resource_type)),
        )
    )

    assert derivable(
        QdlSubgoal("may", (subject, action, resource)),
        graph,
    )
    assert not derivable(
        QdlSubgoal("may", (Atom(value="subject:attacker"), action, resource)),
        graph,
    )


def test_classify_path_event_blocked_selects_the_last_attempted_step() -> None:
    path = _path("blocked", ("get", "delete"))
    event = _path_event(path, outcome="blocked", attempted_steps=2)

    deficit = classify_path_event(event, path)

    assert deficit is not None
    assert deficit.predicate_class == "causes"
    assert deficit.action == "delete"
    assert deficit.axis == "alternatives"
    assert deficit.subgoal == QdlSubgoal(
        "causes",
        (Atom(value="delete"), _ANY_EFFECT),
    )
    assert dict(deficit.context)["path_id"] == "blocked"
    assert dict(deficit.context)["reason"] == "QDL effect chain was not verified"


def test_classify_path_event_completed_returns_no_deficit() -> None:
    path = _path("completed", ("get", "delete"))
    event = _path_event(path, outcome="completed", attempted_steps=2)

    assert classify_path_event(event, path) is None


def test_blocked_step_deficit_carries_recovery_and_clue() -> None:
    path = _path("blocked", ("get",))

    deficit = blocked_step_deficit(
        path,
        path.steps[0],
        recovery_action="reuse_clue",
        clue_observation_id="observation:clue",
    )

    context = dict(deficit.context)
    assert context["recovery_action"] == "reuse_clue"
    assert context["clue_observation_id"] == "observation:clue"


def test_blocked_step_key_is_subgoal_level_and_coalesces_paths() -> None:
    action = Atom(value="action:get")
    denied_effect = denied(action)
    allowed_effect = allowed(action)
    path = _blocked_path("path-one", (denied_effect, denied_effect))
    other_path = _blocked_path("path-two", (denied_effect,))
    other_effect = _blocked_path("path-one", (allowed_effect,))

    first = blocked_step_deficit(path, path.steps[0])
    duplicate = blocked_step_deficit(path, path.steps[0])
    next_step = blocked_step_deficit(path, path.steps[1])
    path_variant = blocked_step_deficit(other_path, other_path.steps[0])
    effect_variant = blocked_step_deficit(other_effect, other_effect.steps[0])

    assert first.key == duplicate.key
    # Path, step, and reason provenance never split the subgoal identity.
    assert first.key == next_step.key
    assert first.key == path_variant.key
    assert first.key == (
        "causes",
        "causes",
        canonical_json(_ANY_ACTION),
        canonical_json(denied_effect),
    )
    assert first.key != effect_variant.key


def test_missing_irreversibility_deficit_carries_step_and_effect() -> None:
    effect = changed(Atom(value="resource:order"), Atom(value="total"))
    path = _blocked_path("setup", (effect,))

    deficit = missing_irreversibility_deficit(
        path,
        path.steps[0],
        effect=canonical_json(effect),
    )

    assert deficit.predicate_class == "causes"
    assert deficit.action == "get"
    assert deficit.axis == "alternatives"
    assert deficit.subgoal == QdlSubgoal("causes", (Atom(value="get"), effect))
    assert deficit.key == (
        "causes",
        "causes",
        canonical_json(Atom(value="get")),
        canonical_json(effect),
    )
    assert dict(deficit.context)["reason"] == "missing_irreversibility_fact"


def test_grounding_result_closes_missing_irreversibility_with_effect() -> None:
    action = Atom(value="action:get")
    other_action = Atom(value="action:other")
    effect = changed(Atom(value="resource:order"), Atom(value="total"))
    wrong_effect = changed(Atom(value="resource:order"), Atom(value="state"))
    path = _blocked_path("setup", (effect,))
    deficit = missing_irreversibility_deficit(
        path,
        path.steps[0],
        effect=canonical_json(effect),
    )
    matching = QdlGraph(
        facts=(
            _fact(
                "is",
                (Atom(value="resource:order"), Atom(value="Resource")),
                Context.PROPOSAL,
            ),
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (effect, Atom(value="Effect")), Context.PROPOSAL),
            _fact("causes", (action, effect), Context.PROPOSAL),
        )
    )
    wrong_effect_graph = QdlGraph(
        facts=(
            _fact(
                "is",
                (Atom(value="resource:order"), Atom(value="Resource")),
                Context.PROPOSAL,
            ),
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (wrong_effect, Atom(value="Effect")), Context.PROPOSAL),
            _fact("causes", (action, wrong_effect), Context.PROPOSAL),
        )
    )
    other_action_graph = QdlGraph(
        facts=(
            _fact(
                "is",
                (Atom(value="resource:order"), Atom(value="Resource")),
                Context.PROPOSAL,
            ),
            _fact("is", (other_action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (effect, Atom(value="Effect")), Context.PROPOSAL),
            _fact("causes", (other_action, effect), Context.PROPOSAL),
        )
    )

    assert grounding_result_closes_deficit(deficit, matching)
    assert not grounding_result_closes_deficit(deficit, wrong_effect_graph)
    assert not grounding_result_closes_deficit(deficit, other_action_graph)


def test_grounding_closure_applies_persisted_supersedes() -> None:
    action = Atom(value="action:get")
    old_effect = changed(Atom(value="resource:order"), Atom(value="state"))
    new_effect = changed(Atom(value="resource:order"), Atom(value="total"))
    deficit = Deficit(
        subgoal=QdlSubgoal("causes", (action, old_effect)),
        predicate_class="causes",
        axis="alternatives",
        action="get",
    )
    superseded = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (old_effect, Atom(value="Effect"))),
            _fact("is", (new_effect, Atom(value="Effect"))),
            _fact("is", (Atom(value="resource:order"), Atom(value="Resource"))),
            _fact("causes", (action, old_effect)),
            _fact("supersedes", (new_effect, old_effect)),
        )
    )

    assert not grounding_result_closes_deficit(deficit, superseded)

    superseded = QdlGraph(
        facts=tuple(
            fact for fact in superseded.facts if fact.predicate.name != "supersedes"
        )
    )
    assert grounding_result_closes_deficit(deficit, superseded)


def test_grounding_result_closes_blocked_step_without_observation() -> None:
    action = Atom(value="action:get")
    other_action = Atom(value="action:other")
    denied_effect = denied(action)
    allowed_effect = allowed(action)
    path = _blocked_path("blocked", (denied_effect,))
    deficit = blocked_step_deficit(path, path.steps[0])
    observation = Observation(
        check_id="check:blocked",
        scenario_id="scenario",
        observed_outcome=AccessOutcome.DENIED,
        response_summary="denied",
    )
    matching = QdlGraph(
        facts=(
            _fact("is", (other_action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (denied_effect, Atom(value="Effect")), Context.PROPOSAL),
            _fact(
                "causes",
                (other_action, denied_effect),
                Context.PROPOSAL,
            ),
        )
    )
    wrong_effect = QdlGraph(
        facts=(
            _fact("is", (other_action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (allowed_effect, Atom(value="Effect")), Context.PROPOSAL),
            _fact("causes", (other_action, allowed_effect), Context.PROPOSAL),
        )
    )
    declaration_only = QdlGraph(
        facts=(_fact("is", (other_action, Atom(value="Action")), Context.PROPOSAL),)
    )

    assert grounding_result_closes_deficit(
        deficit,
        matching,
        observation=observation,
    )
    assert not grounding_result_closes_deficit(
        deficit,
        wrong_effect,
        observation=observation,
    )
    assert not grounding_result_closes_deficit(
        deficit,
        declaration_only,
        observation=observation,
    )
    # BUG FIX: observation is no longer required — blocked paths have no
    # observation by definition; requiring it creates chicken-and-egg.
    assert grounding_result_closes_deficit(deficit, matching)


def test_record_success_without_closure_leaves_deficit_pending() -> None:
    queue = DeficitQueue()
    path = _blocked_path("blocked", (denied(Atom(value="action:get")),))
    deficit = blocked_step_deficit(path, path.steps[0])
    queue.add((deficit,))

    first = queue.pop_next()
    assert queue.record_success(first, gap_closed=False) is False
    assert queue.closed_count == 0
    assert queue.pending_count == 1

    second = queue.pop_next()
    assert queue.record_success(second, gap_closed=False) is False
    assert queue.closed_count == 0
    assert queue.pending_count == 1


def test_grounding_result_closes_response_semantics_only_after_all_fields() -> None:
    deficit = Deficit(
        subgoal=QdlSubgoal(
            "exposes",
            (Atom(value="get"), field(_ANY_RESOURCE, _ANY_FIELD)),
        ),
        predicate_class="exposes",
        axis="response_semantics",
        action="get",
        context=(("fields", "email,payment_token"),),
    )
    action = Atom(value="action:get")
    resource = Atom(value="resource:user")
    email_witness = field(resource, Atom(value="email"))
    payment_witness = field(resource, Atom(value="payment_token"))
    partial = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.ACCEPTED),
            _fact("is", (resource, Atom(value="Resource")), Context.ACCEPTED),
            _fact("is", (email_witness, Atom(value="Witness")), Context.ACCEPTED),
            _fact(
                "exposes",
                (action, email_witness),
                Context.ACCEPTED,
            ),
        )
    )
    complete = QdlGraph(
        facts=(
            _fact("is", (payment_witness, Atom(value="Witness")), Context.ACCEPTED),
            *partial.facts,
            _fact(
                "exposes",
                (action, payment_witness),
                Context.ACCEPTED,
            ),
        )
    )

    assert not grounding_result_closes_deficit(deficit, partial)
    assert grounding_result_closes_deficit(deficit, complete)


def test_grounding_result_closes_variance_only_for_measured_field() -> None:
    report = DiffReport(
        action_id="get",
        control_observation_id="observation:control",
        treatment_observation_id="observation:treatment",
        value_differs=("email",),
    )
    deficit = variance_deficit(report)
    action = Atom(value="action:get")

    def role_graph(field_name: str) -> QdlGraph:
        request_field = input_field(action, Atom(value=field_name))
        return QdlGraph(
            facts=(
                _fact("is", (action, Atom(value="Action")), Context.ACCEPTED),
                _fact("is", (request_field, Atom(value="Field")), Context.ACCEPTED),
                _fact("has", (request_field, Atom(value="object_ref"))),
            )
        )

    assert not grounding_result_closes_deficit(deficit, role_graph("unrelated"))
    assert grounding_result_closes_deficit(deficit, role_graph("email"))


def test_classify_step_event_detects_missing_latency_baseline() -> None:
    event = QdlStepEvaluated(
        path_id="latency",
        step_id="step:latency:0",
        verdict=VerdictStatus.UNSCOREABLE,
        phase="unscoreable",
        reason="no runtime latency baseline for method action:get",
        step_index=0,
    )

    deficit = classify_step_event(event)

    assert deficit is not None
    assert deficit.predicate_class == "causes"
    assert deficit.action == "action:get"
    assert deficit.axis == "availability"
    assert dict(deficit.context)["path_id"] == "latency"


def test_classify_step_event_ignores_other_unscoreable_reasons() -> None:
    event = QdlStepEvaluated(
        path_id="transport",
        step_id="step:transport:0",
        verdict=VerdictStatus.UNSCOREABLE,
        phase="unscoreable",
        reason="transport or application error cannot be scored as a policy outcome",
        step_index=0,
    )

    assert classify_step_event(event) is None


def test_missing_baseline_deficit_is_dispatchable() -> None:
    event = QdlStepEvaluated(
        path_id="latency",
        step_id="step:latency:0",
        verdict=VerdictStatus.UNSCOREABLE,
        phase="unscoreable",
        reason="no runtime latency baseline for method action:get",
        step_index=0,
    )
    deficit = classify_step_event(event)
    assert deficit is not None

    queue = DeficitQueue()
    queue.add((deficit,))

    assert queue.dispatchable is True
    assert queue.pop_next() == deficit


def _variance_report(
    *,
    outcome_differs: bool = False,
    fields_only_treatment: tuple[str, ...] = (),
) -> DiffReport:
    return DiffReport(
        action_id="get",
        control_observation_id="observation:control",
        treatment_observation_id="observation:treatment",
        outcome_differs=outcome_differs,
        fields_only_treatment=fields_only_treatment,
    )


def test_variance_deficit_classifies_unexplained_variance() -> None:
    report = _variance_report(outcome_differs=True)

    deficit = variance_deficit(report)

    assert deficit.predicate_class == "prevents"
    assert deficit.action == "get"
    assert deficit.axis == "variance"
    assert deficit.context == (
        ("diff", report.signature),
        ("control", "observation:control"),
        ("treatment", "observation:treatment"),
        ("variance_fields", ""),
    )
    assert deficit.work_item_key[-1] == report.signature


def test_variance_deficit_keys_distinguish_different_diffs() -> None:
    outcome = variance_deficit(_variance_report(outcome_differs=True))
    fields = variance_deficit(
        _variance_report(fields_only_treatment=("payment_token",))
    )

    assert outcome.key != fields.key
    assert outcome.key[-1] == "outcome:True"
    assert fields.key[-1] == "fields:('payment_token',)"


def test_deficit_queue_keeps_different_diffs_on_one_action() -> None:
    queue = DeficitQueue()
    first = variance_deficit(_variance_report(outcome_differs=True))
    second = variance_deficit(
        _variance_report(fields_only_treatment=("payment_token",))
    )

    assert queue.add((first, second)) == 2
    assert queue.add((first,)) == 0
    assert queue.pending_count == 2


def test_variance_deficit_is_dispatchable() -> None:
    queue = DeficitQueue()
    deficit = variance_deficit(_variance_report(outcome_differs=True))

    queue.add((deficit,))

    assert queue.dispatchable is True
    assert queue.pop_next() == deficit


def test_signal_deficits_extend_response_semantics_and_variance() -> None:
    marker = Signal(
        kind="marker_echo",
        action_id="action:get",
        evidence_refs=("observation:marker",),
        paths=("response.file",),
        marker="dast-marker",
    )
    latency = Signal(
        kind="latency_delta",
        action_id="action:get",
        evidence_refs=("observation:control", "observation:treatment"),
        delta_ms=6.0,
    )

    deficits = signal_deficits((marker, latency))

    assert [(item.predicate_class, item.axis) for item in deficits] == [
        ("exposes", "response_semantics"),
        ("prevents", "variance"),
    ]
    assert dict(deficits[0].context)["signal"] == "marker_echo"
    assert dict(deficits[0].context)["fields"] == "response.file"
    assert dict(deficits[1].context)["signal"] == "latency_delta"


def test_signal_deficit_closes_after_complete_qdl_interpretation() -> None:
    signal = Signal(
        kind="marker_echo",
        action_id="action:get",
        evidence_refs=("observation:marker",),
        paths=("response.file",),
    )
    action = Atom(value="action:get")
    sink = Atom(value="sink:interpreter")
    effect = reached(action, sink)
    partial = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (sink, Atom(value="Sink"))),
            _fact("is", (Atom(value="norm:marker"), Atom(value="Norm"))),
            _fact("signal_grounds", (Atom(value="marker_echo"), effect)),
            _fact("prevents", (Atom(value="norm:marker"), effect)),
            _fact("causes", (action, effect)),
        )
    )
    complete = QdlGraph(
        facts=(
            *partial.facts,
            _fact("sink_interprets", (Atom(value="marker_echo"), sink)),
        )
    )

    deficit = signal_deficits((signal,), partial)[0]

    assert deficit is not None
    assert not grounding_result_closes_deficit(deficit, partial)
    assert grounding_result_closes_deficit(deficit, complete)
    assert signal_deficits((signal,), complete) == ()


def test_coverage_deficits_detects_missing_input_roles() -> None:
    binding = _binding(
        QdlGraph(),
        paths=(_path("one", ("get", "delete")), _path("two", ("get",))),
    )

    deficits = coverage_deficits(binding)

    assert [(item.predicate_class, item.action, item.axis) for item in deficits] == [
        ("has", "delete", "roles"),
        ("has", "get", "roles"),
    ]


@pytest.mark.parametrize("action_key", ["get", "action:get"])
def test_coverage_deficits_accepts_both_action_key_forms(action_key: str) -> None:
    binding = _binding(
        _graph_with_input_role(action_key),
        paths=(_path("role", ("get",)),),
    )

    assert coverage_deficits(binding) == ()


def test_coverage_deficits_detects_declared_action_without_bound_path() -> None:
    graph = QdlGraph(
        facts=(
            _fact(
                "is",
                (Atom(value="action:orphan"), Atom(value="Action")),
                context=Context.CONTRACT,
            ),
            _fact(
                "is",
                (Atom(value="action:bound"), Atom(value="Action")),
                context=Context.CONTRACT,
            ),
        )
    )
    binding = _binding(graph, paths=(_path("bound", ("bound",)),))

    deficits = coverage_deficits(binding)

    assert [(item.predicate_class, item.action, item.axis) for item in deficits] == [
        ("has", "bound", "roles"),
        ("has", "orphan", "roles"),
        ("reaches", "orphan", "dataflows"),
    ]


def test_coverage_deficits_can_defer_declared_actions_until_paths_drain() -> None:
    graph = QdlGraph(
        facts=(
            _fact(
                "is",
                (Atom(value="action:orphan"), Atom(value="Action")),
                context=Context.CONTRACT,
            ),
            _fact(
                "is",
                (Atom(value="action:bound"), Atom(value="Action")),
                context=Context.CONTRACT,
            ),
        )
    )
    binding = _binding(graph, paths=(_path("bound", ("bound",)),))

    deficits = coverage_deficits(binding, include_declared_actions=False)

    assert [(item.predicate_class, item.action, item.axis) for item in deficits] == [
        ("has", "bound", "roles"),
    ]


def test_coverage_deficits_detects_declared_field_without_bound_path() -> None:
    action = Atom(value="action:orphan")
    role_field = input_field(action, Atom(value="secret_id"))
    graph = QdlGraph(
        facts=(
            _fact(
                "is",
                (action, Atom(value="Action")),
                context=Context.CONTRACT,
            ),
            _fact(
                "is",
                (role_field, Atom(value="InputField")),
                context=Context.CONTRACT,
            ),
            _fact("part", (role_field, action), context=Context.CONTRACT),
        )
    )
    binding = _binding(graph)

    deficits = coverage_deficits(binding)

    assert [(item.predicate_class, item.action, item.axis) for item in deficits] == [
        ("has", "orphan", "roles"),
        ("reaches", "orphan", "dataflows"),
    ]


def test_graph_growth_deficit_consults_dataflows_and_closes_on_effect_edge() -> None:
    graph = QdlGraph(
        facts=(
            _fact(
                "is",
                (Atom(value="action:orphan"), Atom(value="Action")),
                context=Context.CONTRACT,
            ),
        )
    )
    deficits = coverage_deficits(_binding(graph, paths=()))
    deficit = next(item for item in deficits if item.predicate_class == "reaches")
    queue = DeficitQueue(max_tasks=1)
    queue.add((deficit,))

    work_item = queue.pop_wave()[0]

    assert work_item is not None
    assert work_item.consultation_kind == "dataflows"
    effect = create(Atom(value="resource:thing"))
    promoted = QdlGraph(
        facts=(
            _fact("is", (Atom(value="action:orphan"), Atom(value="Action"))),
            _fact("is", (Atom(value="action:existing"), Atom(value="Action"))),
            _fact("is", (Atom(value="resource:thing"), Atom(value="ResourceType"))),
            _fact("is", (effect, Atom(value="Effect"))),
            _fact("causes", (Atom(value="action:orphan"), effect)),
            _fact("requires", (Atom(value="action:existing"), effect)),
        )
    )
    assert grounding_result_closes_deficit(deficit, promoted)


def test_coverage_deficits_detects_missing_exposes() -> None:
    binding = _binding(
        QdlGraph(
            facts=(_fact("is", (Atom(value="action:get"), Atom(value="Action"))),)
        ),
        invariants=(_response_invariant("action:get", "secret"),),
    )

    deficits = coverage_deficits(binding)

    assert [(item.predicate_class, item.action, item.axis) for item in deficits] == [
        ("exposes", "action:get", "exposures")
    ]
    assert dict(deficits[0].context)["field"] == "secret"


def test_coverage_deficits_accepts_an_exposed_response_field() -> None:
    binding = _binding(
        _graph_with_exposed_field("action:get", "secret"),
        invariants=(
            _response_invariant("action:get", "secret"),
            _response_invariant("action:get", "secret"),
        ),
    )

    assert coverage_deficits(binding) == ()


def test_response_semantics_deficit_uses_successful_structured_response() -> None:
    binding = _binding(QdlGraph())
    observation = _response_observation()

    deficits = response_semantics_deficits(binding, (observation,))

    assert [(item.predicate_class, item.action, item.axis) for item in deficits] == [
        ("exposes", "svc.GetUser", "response_semantics")
    ]
    context = dict(deficits[0].context)
    assert context["fields"] == "email"
    assert context["observation_id"] == observation.observation_id


def test_response_semantics_deficit_accepts_a_bound_response_field() -> None:
    binding = _binding(
        _graph_with_exposed_field("action:svc.GetUser", "email"),
        invariants=(_response_invariant("action:svc.GetUser", "email"),),
    )

    deficits = response_semantics_deficits(binding, (_response_observation(),))

    assert deficits == ()


def test_response_semantics_deficit_is_field_level() -> None:
    binding = _binding(
        _graph_with_exposed_field("action:svc.GetUser", "username"),
        invariants=(_response_invariant("action:svc.GetUser", "username"),),
    )
    observation = _response_observation(
        response_tree=(
            ("username", "victim"),
            ("email", "response-value"),
        )
    )

    deficits = response_semantics_deficits(binding, (observation,))

    assert [(item.predicate_class, item.action, item.axis) for item in deficits] == [
        ("exposes", "svc.GetUser", "response_semantics")
    ]
    context = dict(deficits[0].context)
    assert context["fields"] == "email"
    assert context["observation_id"] == observation.observation_id


def test_response_semantics_deficit_groups_ungrounded_fields_per_action() -> None:
    binding = _binding(QdlGraph())
    observation = _response_observation(
        response_tree=(
            ("username", "victim"),
            ("email", "response-value"),
            ("phone", "contact-value"),
        )
    )

    deficits = response_semantics_deficits(binding, (observation,))

    assert [(item.predicate_class, item.action, item.axis) for item in deficits] == [
        ("exposes", "svc.GetUser", "response_semantics")
    ]
    context = dict(deficits[0].context)
    assert context["fields"] == "email,phone,username"
    assert context["observation_id"] == observation.observation_id


def test_response_semantics_deficit_keys_distinguish_field_sets() -> None:
    binding = _binding(QdlGraph())
    email_only = _response_observation(response_tree=(("email", "response-value"),))
    email_and_username = _response_observation(
        response_tree=(
            ("email", "response-value"),
            ("username", "victim"),
        )
    )

    email_deficit = response_semantics_deficits(binding, (email_only,))[0]
    grouped_deficit = response_semantics_deficits(
        binding,
        (email_and_username,),
    )[0]

    assert email_deficit.key != grouped_deficit.key
    assert email_deficit.key[-1] == "email"
    assert grouped_deficit.key[-1] == "email,username"
    assert email_deficit.work_item_key[:-1] == grouped_deficit.work_item_key[:-1]


def test_response_semantics_deficit_keeps_latest_observation_per_action() -> None:
    first = _response_observation(
        observation_id="observation:first",
        response_tree=(("username", "victim"),),
    )
    second = _response_observation(
        observation_id="observation:second",
        response_tree=(("email", "response-value"),),
    )

    deficits = response_semantics_deficits(
        _binding(QdlGraph()),
        (first, second),
    )

    assert len(deficits) == 1
    context = dict(deficits[0].context)
    assert context["fields"] == "email,username"
    assert context["observation_id"] == second.observation_id


@pytest.mark.parametrize(
    ("outcome", "response_tree"),
    [
        (AccessOutcome.DENIED, (("email", "response-value"),)),
        (AccessOutcome.ALLOWED, ()),
    ],
)
def test_response_semantics_deficit_requires_successful_response_tree(
    outcome: AccessOutcome,
    response_tree: tuple[tuple[str, object], ...],
) -> None:
    observation = _response_observation(
        outcome=outcome,
        response_tree=response_tree,
    )

    deficits = response_semantics_deficits(_binding(QdlGraph()), (observation,))

    assert deficits == ()


def _generic_deficit(action: str) -> Deficit:
    return Deficit(
        subgoal=QdlSubgoal("reaches", (Atom(value=action), _ANY_NODE)),
        predicate_class="reaches",
        axis="dataflows",
        action=action,
    )


def _baseline_deficit(action: str) -> Deficit:
    action_term = Atom(value=action)
    return Deficit(
        subgoal=QdlSubgoal(
            "causes",
            (action_term, duration(action_term, _ANY_MS)),
        ),
        predicate_class="causes",
        axis="availability",
        action=action,
    )


def _response_semantics_deficit(action: str) -> Deficit:
    return Deficit(
        subgoal=QdlSubgoal(
            "exposes",
            (Atom(value=action), field(_ANY_RESOURCE, _ANY_FIELD)),
        ),
        predicate_class="exposes",
        axis="response_semantics",
        action=action,
    )


def test_deficit_queue_maximizes_information_gain_inside_one_fair_class() -> None:
    queue = DeficitQueue()
    low = _generic_deficit("low")
    high = _generic_deficit("high")

    queue.add((low,))
    queue.add((high, high))

    assert queue.pop_next() == high


def test_missing_baseline_does_not_consume_llm_task_slots() -> None:
    queue = DeficitQueue(max_tasks=1)
    baseline = _baseline_deficit("baseline")
    generic = _generic_deficit("generic")
    queue.add((baseline, generic))

    first = queue.pop_next()
    assert first == baseline
    assert queue.dispatched == 0
    assert queue.budget_exhausted is False
    assert queue.deterministic_dispatched == 1

    queue.record_failure(first)
    second = queue.pop_next()

    assert second == generic
    assert queue.dispatched == 1
    assert queue.budget_exhausted is True


def test_missing_baseline_retries_on_the_next_dispatch_window() -> None:
    queue = DeficitQueue(max_tasks=1)
    baseline = _baseline_deficit("baseline")
    queue.add((baseline,))

    first = queue.pop_next()
    queue.record_failure(first)
    assert queue.pop_next() is None
    assert queue.pending_count == 1

    second = queue.pop_next()
    queue.record_failure(second)

    assert queue.closed_count == 1
    assert queue.dispatched == 0


def test_fair_share_selects_every_deficit_class_before_a_repeat() -> None:
    queue = DeficitQueue(max_tasks=3)
    generics = tuple(_generic_deficit(f"generic-{index}") for index in range(3))
    responses = tuple(
        _response_semantics_deficit(f"response-{index}") for index in range(3)
    )
    variances = tuple(
        variance_deficit(
            DiffReport(
                action_id=f"get-{index}",
                control_observation_id=f"observation:control-{index}",
                treatment_observation_id=f"observation:treatment-{index}",
                value_differs=(f"field-{index}",),
            )
        )
        for index in range(3)
    )
    queue.add((*generics, *responses, *variances))

    selected_classes = []
    for _ in range(3):
        deficit = queue.pop_next()
        assert deficit is not None
        selected_classes.append(deficit.predicate_class)
        queue.record_success(deficit, gap_closed=True)

    assert selected_classes == ["reaches", "exposes", "prevents"]
    assert queue.dispatched == 3
    assert queue.budget_exhausted is True


def test_fair_share_does_not_starve_a_low_gain_class() -> None:
    queue = DeficitQueue(max_tasks=6)

    for round_index in range(3):
        high = _generic_deficit(f"high-{round_index}")
        low = _response_semantics_deficit(f"low-{round_index}")
        queue.add((high,) * 4)
        queue.add((low,))

        first = queue.pop_next()
        second = queue.pop_next()
        assert first is not None and second is not None
        assert (first.predicate_class, second.predicate_class) == (
            "reaches",
            "exposes",
        )
        queue.record_success(first, gap_closed=True)
        queue.record_success(second, gap_closed=True)

    assert queue.dispatched == 6
    assert queue.budget_exhausted is True


def test_llm_budget_exhaustion_is_explicit() -> None:
    queue = DeficitQueue(max_tasks=2)
    first = _response_semantics_deficit("first")
    second = _response_semantics_deficit("second")
    generic = _generic_deficit("generic")
    queue.add((first, second, generic))

    assert queue.pop_next() == first
    queue.record_success(first, gap_closed=True)
    assert queue.pop_next() == generic
    queue.record_success(generic, gap_closed=True)

    assert queue.pop_next() is None
    assert queue.dispatched == 2
    assert queue.budget_exhausted is True
    assert queue.dispatchable is False


def test_deficit_queue_deduplicates_and_tracks_fan_out() -> None:
    queue = DeficitQueue()
    first = Deficit(
        subgoal=QdlSubgoal(
            "causes",
            (_ANY_ACTION, denied(Atom(value="action:get"))),
        ),
        predicate_class="causes",
        axis="alternatives",
        action="get",
        context=(
            ("path_id", "one"),
            ("step_id", "step:one"),
            ("effect", "denied(action:get)"),
        ),
    )
    duplicate = Deficit(
        subgoal=first.subgoal,
        predicate_class="causes",
        axis="alternatives",
        action="get",
        context=(
            ("path_id", "two"),
            ("step_id", "step:two"),
            ("effect", "denied(action:get)"),
            ("reason", "different report text"),
        ),
    )

    assert queue.add((first, duplicate)) == 1
    assert queue.add((first,)) == 0
    assert queue.pending_count == 1
    assert queue.pop_next() == first
    assert queue.pending_count == 0
    assert queue.dispatchable is False


def test_deficit_queue_prefers_higher_fan_out() -> None:
    queue = DeficitQueue()
    low = _generic_deficit("low")
    high = _generic_deficit("high")

    queue.add((low,))
    queue.add((high, high))

    assert queue.pop_next() == high


def test_deficit_queue_enforces_the_dispatch_budget() -> None:
    queue = DeficitQueue(max_tasks=1)
    first = _generic_deficit("first")
    second = _generic_deficit("second")

    queue.add((first, second))

    assert queue.pop_next() == first
    assert queue.pop_next() is None
    assert queue.dispatched == 1
    assert queue.dispatchable is False


def test_deficit_queue_closes_after_two_failures_and_ignores_closed_adds() -> None:
    queue = DeficitQueue()
    deficit = _generic_deficit("get")
    queue.add((deficit,))

    first = queue.pop_next()
    queue.record_failure(first)
    assert queue.pending_count == 1
    assert queue.dispatchable is True

    second = queue.pop_next()
    queue.record_failure(second)

    assert queue.closed_count == 1
    assert queue.add((deficit,)) == 0
    assert queue.pop_next() is None
    assert queue.dispatchable is False


def test_deficit_queue_closes_successes_and_does_not_redispatch() -> None:
    queue = DeficitQueue()
    deficit = _generic_deficit("get")
    queue.add((deficit,))

    dispatched = queue.pop_next()
    queue.record_success(dispatched, gap_closed=True)

    assert queue.closed_count == 1
    assert queue.add((deficit,)) == 0
    assert queue.pop_next() is None


@pytest.mark.parametrize("termination", ["saturation", "absorption"])
def test_evidence_reopens_only_revision_closed_keys(termination: str) -> None:
    queue = DeficitQueue(max_tasks=None, max_attempts=1)
    base = _response_semantics_deficit("get")
    evidence = (("observation_id", "obs:one"), ("clue_observation_id", "obs:clue"))
    closed, pending = (
        replace(base, context=(("fields", name), *evidence))
        for name in ("email", "phone")
    )
    assert queue.add((closed, pending)) == 2
    (item,) = queue.pop_wave()
    assert queue.record_success(closed, gap_closed=True)
    if termination == "saturation":
        queue.record_work_item_failure(item)
    else:
        queue.absorb_work_item(item)
    assert (queue.closed_count, queue.saturated_count, queue.pending_count) == (2, 1, 0)

    for context in (
        pending.context,
        (("fields", "phone"), ("observation_id", "obs:one")),
        (("fields", "phone"),),
    ):
        assert queue.add((replace(pending, context=context),)) == 0
        assert queue.pop_wave() == ()
        assert (queue.closed_count, queue.saturated_count) == (2, 1)

    # Even evidence supplied on the semantically closed sibling reopens only
    # the keys that were closed by the evidence revision's terminal outcome.
    fresh = replace(
        closed, context=(("fields", "email"), ("observation_id", "obs:two"))
    )
    assert queue.add((fresh,)) == 0
    assert (queue.closed_count, queue.saturated_count, queue.pending_count) == (1, 0, 1)
    (reopened,) = queue.pop_wave()
    assert reopened.deficits == (pending,)
    assert reopened.attempts == 0
    queue.record_work_item_success(reopened)
    assert queue.closed_count == 2
    assert queue.pop_wave() == ()
    assert queue.dispatched == 2


@pytest.mark.parametrize(
    "feedback", ["deficit_failure", "deficit_result", "item_failure", "item_result"]
)
def test_untrusted_feedback_releases_flight_without_charging(feedback: str) -> None:
    queue = DeficitQueue(max_tasks=None, max_attempts=1)
    deficit = replace(
        _response_semantics_deficit("get"), context=(("fields", "email"),)
    )
    queue.add((deficit,))
    graph = _graph_with_exposed_field("action:get", "email")

    for signals in (1, 2):
        (item,) = queue.pop_wave()
        assert queue.pending_count == 0
        assert item.attempts == 0
        if feedback == "deficit_failure":
            queue.record_failure(deficit, trusted=False)
        elif feedback == "deficit_result":
            assert not queue.record_success(deficit, gap_closed=True, trusted=False)
        elif feedback == "item_failure":
            queue.record_work_item_failure(item, trusted=False)
        else:
            outcome = queue.record_work_item_result(item, graph, trusted=False)
            assert outcome.closed_deficit_ids == ()
        assert queue.quarantined_signals == signals
        assert (queue.pending_count, queue.closed_count, queue.saturated_count) == (
            1,
            0,
            0,
        )
        assert queue.dispatchable

    (item,) = queue.pop_wave()
    assert item.attempts == 0
    queue.record_work_item_failure(item)
    assert (queue.pending_count, queue.closed_count, queue.saturated_count) == (0, 1, 1)
    assert queue.quarantined_signals == 2
    assert queue.dispatched == 3
    assert queue.pop_wave() == ()


def test_mixed_result_charges_once_for_multiple_unsatisfied_siblings() -> None:
    queue = DeficitQueue(max_tasks=None, max_attempts=2)
    base = _response_semantics_deficit("get")
    email, phone, username = (
        replace(base, context=(("fields", name),))
        for name in ("email", "phone", "username")
    )
    queue.add((email, phone, username))
    (item,) = queue.pop_wave()
    outcome = queue.record_work_item_result(
        item, _graph_with_exposed_field("action:get", "email")
    )
    assert outcome.closed_deficit_ids == (email.consultation_id,)
    assert (queue.closed_count, queue.pending_count, queue.saturated_count) == (1, 2, 0)
    (retry,) = queue.pop_wave()
    assert retry.deficits == (phone, username)
    assert retry.attempts == 1
    outcome = queue.record_work_item_result(retry, None)
    assert outcome.closed_deficit_ids == ()
    assert (queue.closed_count, queue.pending_count, queue.saturated_count) == (3, 0, 1)
    assert queue.dispatched == 2
    assert queue.pop_wave() == ()


def test_stale_key_stays_stale_after_revision_reopens_and_late_feedback() -> None:
    queue = DeficitQueue(max_tasks=None, max_attempts=1)
    base = _response_semantics_deficit("get")
    stale = replace(base, context=(("fields", "email"), ("path_id", "removed")))
    live = replace(base, context=(("fields", "phone"),))
    queue.add((stale, live))
    (item,) = queue.pop_wave()
    queue.defer_work_item(item)
    propagation = queue.propagate_work_item_result(
        item,
        _graph_with_exposed_field("action:other", "email"),
        active_path_ids=frozenset(),
    )
    assert propagation.stale_deficit_ids == (stale.consultation_id,)
    queue.absorb_work_item(item)
    assert (queue.stale_count, queue.closed_count, queue.saturated_count) == (1, 1, 1)
    fresh = replace(stale, context=(*stale.context, ("observation_id", "obs:new")))
    assert queue.add((fresh,)) == 0
    assert (queue.stale_count, queue.closed_count, queue.pending_count) == (1, 0, 1)
    (reopened,) = queue.pop_wave()
    assert reopened.deficits == (live,)
    queue.record_work_item_success(reopened)

    # A late successful result for the old work item cannot close or revive
    # the stale key; fresh evidence and repeated enqueue cannot revive it either.
    outcome = queue.record_work_item_result(
        item, _graph_with_exposed_field("action:get", "email")
    )
    assert outcome.closed_deficit_ids == ()
    assert queue.add((fresh, live)) == 0
    assert (queue.stale_count, queue.closed_count, queue.pending_count) == (1, 1, 0)
    assert queue.pop_wave() == ()
    assert queue.dispatched == 2


def test_deficit_queue_dispatches_reference_typing_consultations() -> None:
    queue = DeficitQueue()
    reference = Deficit(
        subgoal=QdlSubgoal(
            "refers_to",
            (
                input_field(Atom(value="get"), Atom(value="order_id")),
                Atom(value="resource:order"),
            ),
        ),
        predicate_class="refers_to",
        axis="fixture",
        action="get",
        context=(("reason", "missing_refers_to"),),
    )
    queue.add((reference,))

    assert queue.pop_next() == reference

    graph = QdlGraph(
        facts=(
            _fact("is", (Atom(value="action:get"), Atom(value="Action"))),
            _fact(
                "is",
                (
                    input_field(Atom(value="action:get"), Atom(value="order_id")),
                    Atom(value="Field"),
                ),
            ),
            _fact(
                "is",
                (Atom(value="resource:order"), Atom(value="ResourceType")),
            ),
            _extension_fact(
                "refers_to",
                (
                    input_field(Atom(value="action:get"), Atom(value="order_id")),
                    Atom(value="resource:order"),
                ),
            ),
        )
    )
    assert grounding_result_closes_deficit(reference, graph)


def test_causal_obligation_is_not_replaced_by_a_step_security_norm():
    effect = create(Atom(value="resource:order"))
    step = replace(
        _effect_step("ordinary-create", denied(Atom(value="get"))),
        required_effects=(effect,),
    )
    path = replace(_path("ordinary-create"), steps=(step,))
    deficit = blocked_step_deficit(path, step)
    assert deficit.subgoal == QdlSubgoal("causes", (_ANY_ACTION, effect))
    unrelated = QdlGraph(
        facts=(
            _fact("is", (Atom(value="get"), Atom(value="Action"))),
            _fact("is", (denied(Atom(value="get")), Atom(value="Effect"))),
            _fact("causes", (Atom(value="get"), denied(Atom(value="get")))),
        )
    )
    assert not grounding_result_closes_deficit(deficit, unrelated)
    producer = Atom(value="action:producer")
    matching = QdlGraph(
        facts=(
            _fact("is", (producer, Atom(value="Action"))),
            _fact("is", (Atom(value="resource:order"), Atom(value="ResourceType"))),
            _fact("causes", (producer, effect)),
        )
    )
    assert grounding_result_closes_deficit(deficit, matching)


@pytest.mark.parametrize(
    "context,expected_count",
    [(Context.CONTRACT, 0), (Context.ACCEPTED, 0), (Context.PROPOSAL, 1)],
)
def test_reference_obligation_closes_only_from_executable_qdl(context, expected_count):
    from cloud_dast.runtime.deficits import reference_deficits

    step = _step("ordinary-reference")
    step = replace(
        step, plan=step.plan.model_copy(update={"resource_params": ("resource_id",)})
    )
    path = replace(_path("ordinary-reference"), steps=(step,))
    action = Atom(value="action:get")
    field_term = input_field(action, Atom(value="resource_id"))
    target = Atom(value="resource:order")
    reference = _extension_fact("refers_to", (field_term, target)).model_copy(
        update={"context": context}
    )
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (field_term, Atom(value="InputField"))),
            _fact("is", (target, Atom(value="ResourceType"))),
            reference,
        )
    )
    assert len(reference_deficits(_binding(graph, paths=(path,)))) == expected_count


def test_optional_object_ref_does_not_block_ordinary_execution():
    from cloud_dast.runtime.deficits import reference_deficits

    step = _step("optional-reference")
    method = step.method.model_copy(
        update={
            "fields": (FieldSpec(name="resource_id", type="string", required=False),)
        }
    )
    step = replace(
        step,
        method=method,
        plan=step.plan.model_copy(update={"resource_params": ("resource_id",)}),
    )
    path = replace(_path("optional-reference"), steps=(step,))
    assert reference_deficits(_binding(QdlGraph(), paths=(path,))) == ()


@pytest.mark.parametrize("derived", [False, True])
@pytest.mark.parametrize("fields", ["", "state"])
def test_retired_effect_cannot_close_variance_through_retained_norm_or_requirement(
    derived, fields
):
    from cloud_dast.qdl.graph_ops import current_facts

    action, resource = Atom(value="action:get"), Atom(value="resource:order")
    old, new = (
        changed(resource, Atom(value="state")),
        changed(resource, Atom(value="total")),
    )
    nodes = (
        _fact("is", (old, Atom(value="Effect"))),
        _fact("is", (new, Atom(value="Effect"))),
    )
    edge = _fact("supersedes", (new, old))
    norm = _fact("prevents", (action, old))
    requirement = _fact("requires", (action, old))
    signal = _fact("signal_grounds", (Atom(value="marker_echo"), old))
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            *nodes,
            _fact("causes", (action, old)),
            norm,
            requirement,
            signal,
            *(() if derived else (edge,)),
        ),
        rules=(Rule(body=nodes, head=(edge,)),) if derived else (),
    )
    deficit = Deficit(
        subgoal=QdlSubgoal("prevents", (action, old)),
        predicate_class="prevents",
        axis="variance",
        action="get",
        context=(("variance_fields", fields),),
    )
    assert not grounding_result_closes_deficit(deficit, graph)
    rows = current_facts(graph)
    assert norm in rows and requirement in rows and signal in rows
    fresh = QdlGraph(facts=tuple(f for f in graph.facts if f != edge), rules=())
    assert grounding_result_closes_deficit(deficit, fresh)


def test_rule_tombstone_blocks_causal_and_signal_closure_but_not_raw_history():
    action, sink, other = (
        Atom(value="action:get"),
        Atom(value="sink:sql"),
        Atom(value="sink:template"),
    )
    old, new = reached(action, sink), reached(action, other)
    nodes = (
        _fact("is", (old, Atom(value="Effect"))),
        _fact("is", (new, Atom(value="Effect"))),
    )
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (sink, Atom(value="Sink"))),
            _fact("is", (other, Atom(value="Sink"))),
            *nodes,
            _fact("causes", (action, old)),
            _fact("prevents", (action, old)),
            _fact("signal_grounds", (Atom(value="marker_echo"), old)),
            _fact("sink_interprets", (Atom(value="marker_echo"), sink)),
        ),
        rules=(Rule(body=nodes, head=(_fact("supersedes", (new, old)),)),),
    )
    causal = Deficit(
        subgoal=QdlSubgoal("causes", (action, old)),
        predicate_class="causes",
        axis="alternatives",
        action="get",
    )
    signal = Deficit(
        subgoal=QdlSubgoal("prevents", (action, old)),
        predicate_class="prevents",
        axis="variance",
        action="get",
        context=(("signal", "marker_echo"),),
    )
    assert derivable(causal.subgoal, graph)
    assert not grounding_result_closes_deficit(causal, graph)
    assert not grounding_result_closes_deficit(signal, graph)
    fresh = QdlGraph(facts=graph.facts)
    assert grounding_result_closes_deficit(causal, fresh)
    assert grounding_result_closes_deficit(signal, fresh)


@pytest.mark.parametrize("context", list(Context))
def test_stale_explicit_effect_path_remains_distinct_from_current_closure(context):
    from cloud_dast.runtime.deficits.closure import deficit_is_stale

    action, resource = Atom(value="action:get"), Atom(value="resource:order")
    old, new = (
        changed(resource, Atom(value="state")),
        changed(resource, Atom(value="total")),
    )
    nodes = (
        _fact("is", (old, Atom(value="Effect")), context),
        _fact("is", (new, Atom(value="Effect")), context),
    )
    edge = _fact("supersedes", (new, old), context)
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            *nodes,
            _fact("causes", (action, old)),
            edge,
        )
    )
    deficit = Deficit(
        subgoal=QdlSubgoal("causes", (action, old)),
        predicate_class="causes",
        axis="alternatives",
        action="get",
        context=(("effect", canonical_json(old)), ("path_id", "old-path")),
    )
    assert deficit_is_stale(deficit, graph, active_path_ids=None)
    assert grounding_result_closes_deficit(deficit, graph) == (
        context != Context.ACCEPTED
    )
    derived = QdlGraph(
        facts=tuple(f for f in graph.facts if f != edge),
        rules=(Rule(body=nodes, head=(edge,)),),
    )
    assert not deficit_is_stale(deficit, derived, active_path_ids=None)
    assert deficit_is_stale(deficit, derived, active_path_ids=frozenset())


@pytest.mark.parametrize(
    "predicate,fields", [("prevents", ""), ("prevents", "state"), ("requires", "state")]
)
def test_variance_norm_without_provider_still_explains_fresh_effect(predicate, fields):
    action, resource = Atom(value="action:get"), Atom(value="resource:order")
    effect = changed(resource, Atom(value="state"))
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("is", (effect, Atom(value="Effect"))),
            _fact(predicate, (action, effect)),
        )
    )
    deficit = Deficit(
        subgoal=QdlSubgoal("prevents", (action, effect)),
        predicate_class="prevents",
        axis="variance",
        action="get",
        context=(("variance_fields", fields),),
    )
    assert grounding_result_closes_deficit(deficit, graph)


@pytest.mark.parametrize(
    "predicate,fields", [("prevents", ""), ("prevents", "state"), ("requires", "state")]
)
def test_rule_derived_retired_provider_cannot_be_replaced_by_variance_norm(
    predicate, fields
):
    action, resource = Atom(value="action:get"), Atom(value="resource:order")
    old, new = (
        changed(resource, Atom(value="state")),
        changed(resource, Atom(value="total")),
    )
    action_node = _fact("is", (action, Atom(value="Action")))
    old_node = _fact("is", (old, Atom(value="Effect")))
    new_node = _fact("is", (new, Atom(value="Effect")))
    graph = QdlGraph(
        facts=(
            action_node,
            old_node,
            new_node,
            _fact("is", (resource, Atom(value="Resource"))),
            _fact(predicate, (action, old)),
        ),
        rules=(
            Rule(body=(action_node, old_node), head=(_fact("causes", (action, old)),)),
            Rule(body=(old_node, new_node), head=(_fact("supersedes", (new, old)),)),
        ),
    )
    deficit = Deficit(
        subgoal=QdlSubgoal("prevents", (action, old)),
        predicate_class="prevents",
        axis="variance",
        action="get",
        context=(("variance_fields", fields),),
    )
    assert not grounding_result_closes_deficit(deficit, graph)


@pytest.mark.parametrize("norm_context", [Context.CONTRACT, Context.ACCEPTED])
def test_variance_retirement_does_not_cross_proof_contexts(norm_context):
    action, resource = Atom(value="action:get"), Atom(value="resource:order")
    old, new = (
        changed(resource, Atom(value="state")),
        changed(resource, Atom(value="total")),
    )
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (resource, Atom(value="Resource"))),
            _fact("is", (old, Atom(value="Effect"))),
            _fact("is", (new, Atom(value="Effect"))),
            _fact("causes", (action, old)),
            _fact("supersedes", (new, old)),
            _fact("prevents", (action, old), norm_context),
        )
    )
    deficit = Deficit(
        subgoal=QdlSubgoal("prevents", (action, old)),
        predicate_class="prevents",
        axis="variance",
        action="get",
    )
    assert grounding_result_closes_deficit(deficit, graph) == (
        norm_context != Context.ACCEPTED
    )
