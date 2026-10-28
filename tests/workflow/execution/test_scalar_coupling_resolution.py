"""Joint scalar witnesses and current-call readiness at the transport boundary."""

from __future__ import annotations

import pytest

from cloud_dast.binding import scenario_scope
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.couplings import FieldCoupling, couplings_from_plan
from cloud_dast.model import (
    AccessOutcome,
    Check,
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    Observation,
    ResponseData,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    QdlGraph,
    Rule,
    Struct,
    create,
    input_field,
    output_field,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.coupling.resolve import Binder
from cloud_dast.runtime.coupling.resolve import Context as CouplingContext
from cloud_dast.runtime.execution.scenarios import Checker
from cloud_dast.verification.projection import (
    ObservationProjector,
)
from cloud_dast_fuzzing import TemplateGenerator
from tests.workflow.execution.test_durable_coupling import (
    INPUT,
    MAKE,
    OUTPUT,
    RESOURCE,
    USE,
    Guardrail,
    bindings,
    declarations,
    fact,
    generate,
    history,
    scenario,
    workflow,
)


@pytest.mark.parametrize(
    "kind,value,allowed",
    (
        ("future", None, False),
        ("future", "fixed", True),
        ("missing", "fixed", False),
        ("sibling", None, True),
        ("own_output", None, True),
    ),
)
def test_constraint_applicability_preserves_current_input_deferral(
    kind, value, allowed
):
    a, b, outside = (Atom(value=f"action:{name}") for name in ("A", "B", "outside"))
    field = Atom(value="nonce")
    endpoints = {
        "future": (input_field(a, field), output_field(b, field)),
        "missing": (input_field(a, field), output_field(outside, field)),
        "sibling": (input_field(outside, field), output_field(b, field)),
        "own_output": (output_field(a, field), input_field(b, field)),
    }[kind]
    method = MethodSpec(
        method_id="A",
        name="A",
        service="s",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="nonce", type="string"),),
    )
    position = scenario("A")
    check = Check(
        invariant_id="norm",
        identities=("actor",),
        method_id="A",
        scenario_id=position.scenario_id,
        request=(("nonce", value),),
    )
    state = CouplingContext(
        couplings=(FieldCoupling(*endpoints, "eq"),),
        evidence_graph=None,
        methods={"A": method, "B": method.model_copy(update={"method_id": "B"})},
        scenarios={("A", position.scenario_id): position},
        outputs={},
    )

    result = Binder().resolve_check(check, state)

    assert result == (check if allowed else None)


def test_evidence_refresh_keeps_actual_path_outputs_and_default_reset_clears_them():
    context = bindings()
    service, target, _ = workflow(context)
    assert service.execute_check(generate(service, context[0])) is not None
    service.set_coupling_context(context, evidence_graph=declarations(), reset=False)
    assert service.execute_check(generate(service, context[1])) is not None
    assert dict(target.calls[-1].request)["widget_id"] == "live-id"
    service.set_coupling_context(context, evidence_graph=declarations())
    assert service.execute_check(generate(service, context[1])) is None


def _retained_source():
    context = bindings()
    service, target, _ = workflow(context)
    observation = service.execute_check(generate(service, context[0]))
    assert observation is not None
    return context, target.calls[-1], observation


def test_retained_occurrence_seeds_values_without_new_checks_or_calls():
    context, check, observation = _retained_source()
    service, target, guardrail = workflow(context)
    service.set_coupling_context(context, observations=((check, observation),))
    assert service.checks == ()
    assert target.calls == guardrail.checks == []
    consumer = generate(service, context[1])
    assert service.execute_check(consumer) is not None
    assert len(service.checks) == len(target.calls) == len(guardrail.checks) == 1
    assert dict(target.calls[0].request) == {"widget_id": "live-id"}


@pytest.mark.parametrize(
    "change",
    [
        {"identities": ("foreign",)},
        {"scenario_id": "foreign"},
        {"method_id": "foreign"},
    ],
)
def test_retained_occurrence_is_still_scoped_by_actual_check(change):
    context, check, observation = _retained_source()
    service, target, guardrail = workflow(context)
    service.set_coupling_context(
        context, observations=((check.model_copy(update=change), observation),)
    )
    assert service.execute_check(generate(service, context[1])) is None
    assert service.checks == ()
    assert target.calls == guardrail.checks == []


def test_retained_occurrence_preserves_pair_snapshots():
    context, check, observation = _retained_source()
    service, target, _ = workflow(context)
    service.set_coupling_context(context, observations=((check, observation),))
    control, treatment = service.execute_pair(
        generate(service, context[1]), generate(service, context[1])
    )
    assert control is not None and treatment is not None
    assert service.execute_check(generate(service, context[1])) is not None
    assert len(service.checks) == len(target.calls) == 3
    assert all(dict(c.request) == {"widget_id": "live-id"} for c in target.calls)


def test_retained_value_occurrence_does_not_establish_causal_proof():
    context, check, observation = _retained_source()
    graph = QdlGraph(
        facts=declarations().facts
        + (
            fact("has", INPUT, Atom(value="object_ref"), context=Context.ACCEPTED),
            fact("requires", USE, create(RESOURCE), context=Context.ACCEPTED),
        )
    )
    service, target, guardrail = workflow(context)
    service.set_coupling_context(
        context, evidence_graph=graph, observations=((check, observation),)
    )
    assert service.execute_check(generate(service, context[1])) is None
    assert service.checks == ()
    assert target.calls == guardrail.checks == []


def _live_value_context():
    context = bindings()
    service, target, guardrail = workflow(context)
    check = generate(service, context[0])
    observation = service.execute_check(check)
    assert observation is not None
    # This is a value-only path: no declared creation or causal requirement.
    declarations_only = QdlGraph(
        facts=tuple(f for f in declarations().facts if f.predicate.name != "causes")
    )
    projection = ObservationProjector().project(
        observation,
        check.method_id,
        graph=declarations_only,
        check=check,
        scope=scenario_scope(context[0][2]),
        identities=check.identities,
        observed_at=7.0,
    )
    return (
        service,
        target,
        guardrail,
        context,
        check,
        observation,
        declarations_only,
        projection,
    )


@pytest.mark.parametrize("canonical", [False, True])
def test_live_typed_value_uses_canonical_or_transient_output_query(
    canonical, monkeypatch
):
    service, target, guardrail, context, _, _, graph, projection = _live_value_context()
    if canonical:
        graph = merge_graphs(graph, projection)

        def forbid_projection(*args, **kwargs):
            pytest.fail(
                "canonical observation must retain its original projection/time"
            )

        monkeypatch.setattr(ObservationProjector, "project", forbid_projection)
    service.set_coupling_context(context, evidence_graph=graph, reset=False)
    assert service.execute_check(generate(service, context[1])) is not None
    assert dict(target.calls[-1].request) == {"widget_id": "live-id"}
    assert len(target.calls) == len(guardrail.checks) == 2


@pytest.mark.parametrize("canonical", [False, True])
@pytest.mark.parametrize(
    "revoked", ["observation", "check", "link", "field", "value", "role"]
)
def test_live_typed_value_honors_canonical_revocations(canonical, revoked):
    service, target, guardrail, context, check, observation, graph, projection = (
        _live_value_context()
    )
    instance = next(
        f.args[1]
        for f in projection.facts
        if f.predicate.name == "has" and f.args[0] == OUTPUT
    )
    link = Struct(name="replacement", args=(OUTPUT, instance))
    old = {
        "observation": Atom(value=observation.observation_id),
        "check": Atom(value=check.check_id),
        "link": link,
        "field": OUTPUT,
        "value": Atom(value="live-id"),
        "role": Struct(name="replacement", args=(OUTPUT, Atom(value="object_ref"))),
    }[revoked]
    if canonical:
        graph = merge_graphs(graph, projection)
    extra = [
        fact("is", Atom(value="revoker"), Atom(value="Node")),
        fact("supersedes", Atom(value="revoker"), old),
    ]
    if not any(f.predicate.name == "is" and f.args[0] == old for f in graph.facts):
        extra.append(fact("is", old, Atom(value="Node")))
    if revoked == "link" and not canonical:
        extra.append(fact("is", instance, Atom(value="Resource")))
    if revoked == "role":
        extra.append(
            fact(
                "is",
                Atom(value="object_ref"),
                Atom(value="Node"),
                context=Context.ACCEPTED,
            )
        )
    graph = QdlGraph(facts=graph.facts + tuple(extra))
    service.set_coupling_context(context, evidence_graph=graph, reset=False)
    assert service.execute_check(generate(service, context[1])) is None
    assert len(target.calls) == len(guardrail.checks) == 1


@pytest.mark.parametrize("canonical", [False, True])
@pytest.mark.parametrize("revoked", [False, True])
def test_rule_derived_object_ref_cannot_bypass_canonical_revocation(canonical, revoked):
    service, target, guardrail, context, _, observation, graph, projection = (
        _live_value_context()
    )
    graph = QdlGraph(
        facts=tuple(
            f
            for f in graph.facts
            if not (
                f.predicate.name == "has"
                and f.args == (OUTPUT, Atom(value="object_ref"))
            )
        ),
        rules=(
            Rule(
                body=(fact("refers_to", OUTPUT, RESOURCE, context=Context.ACCEPTED),),
                head=(
                    fact(
                        "has",
                        OUTPUT,
                        Atom(value="object_ref"),
                        context=Context.ACCEPTED,
                    ),
                ),
            ),
        ),
    )
    if canonical:
        graph = merge_graphs(graph, projection)
    if revoked:
        extra = (
            fact("is", Atom(value="revoker"), Atom(value="Node")),
            fact(
                "supersedes",
                Atom(value="revoker"),
                Atom(value=observation.observation_id),
            ),
        )
        if not canonical:
            extra += (
                fact("is", Atom(value=observation.observation_id), Atom(value="Node")),
            )
        graph = QdlGraph(facts=graph.facts + extra, rules=graph.rules)
    service.set_coupling_context(context, evidence_graph=graph, reset=False)
    assert (service.execute_check(generate(service, context[1])) is not None) == (
        not revoked
    )
    assert len(target.calls) == len(guardrail.checks) == 1 + int(not revoked)


def test_incomplete_canonical_observation_is_not_reprojected_with_new_time(monkeypatch):
    service, target, guardrail, context, _, _, graph, projection = _live_value_context()
    projection = QdlGraph(
        facts=tuple(
            f
            for f in projection.facts
            if not (
                f.predicate.name == "evidence"
                and isinstance(f.args[1], Struct)
                and f.args[1].name == "source"
                and f.args[1].args[0] == Atom(value="observed_at")
            )
        )
    )

    def forbid_projection(*args, **kwargs):
        pytest.fail("incomplete canonical metadata must not trigger a new projection")

    monkeypatch.setattr(ObservationProjector, "project", forbid_projection)
    service.set_coupling_context(
        context, evidence_graph=merge_graphs(graph, projection), reset=False
    )
    assert service.execute_check(generate(service, context[1])) is None
    assert len(target.calls) == len(guardrail.checks) == 1


def test_scalar_live_binding_remains_available_without_object_ref_role():
    service, target, guardrail, context, _, observation, graph, _ = (
        _live_value_context()
    )
    graph = QdlGraph(
        facts=tuple(
            f
            for f in graph.facts
            if not (
                f.predicate.name == "has"
                and f.args == (OUTPUT, Atom(value="object_ref"))
            )
        )
        + (
            fact(
                "is", Atom(value=observation.observation_id), Atom(value="Observation")
            ),
            fact("is", Atom(value="revoker"), Atom(value="Node")),
            fact(
                "supersedes",
                Atom(value="revoker"),
                Atom(value=observation.observation_id),
            ),
        )
    )
    service.set_coupling_context(context, evidence_graph=graph, reset=False)
    assert service.execute_check(generate(service, context[1])) is not None
    assert len(target.calls) == len(guardrail.checks) == 2


@pytest.mark.parametrize("outcome", [AccessOutcome.DENIED, AccessOutcome.ERROR])
def test_failed_latest_typed_occurrence_cannot_fall_back_to_canonical_history(outcome):
    service, target, guardrail, context, _, _, graph, projection = _live_value_context()
    service.set_coupling_context(
        context, evidence_graph=merge_graphs(graph, projection), reset=False
    )
    target.outcome = outcome
    assert service.execute_check(generate(service, context[0])) is not None
    assert service.execute_check(generate(service, context[1])) is None
    assert len(target.calls) == len(guardrail.checks) == 2


@pytest.mark.parametrize("outcome", [AccessOutcome.DENIED, AccessOutcome.ERROR])
def test_latest_failed_call_blocks_older_success(outcome):
    context = bindings()
    service, target, guardrail = workflow(context)
    service.execute_check(generate(service, context[0]))
    target.outcome = outcome
    service.execute_check(generate(service, context[0]))
    assert service.execute_check(generate(service, context[1])) is None
    assert len(target.calls) == len(guardrail.checks) == 2


@pytest.mark.parametrize("live", (False, True))
@pytest.mark.parametrize("latest", ("no_response", "foreign_identity"))
def test_latest_live_attempt_blocks_retained_and_durable_fallback(live, latest):
    service, _, _, context, previous, observation, graph, projection = (
        _live_value_context()
    )
    current = previous.model_copy(update={"check_id": "latest-attempt"})
    if latest == "foreign_identity":
        current = current.model_copy(update={"identities": ("foreign",)})
    check = generate(service, context[1])
    state = CouplingContext(
        couplings=couplings_from_plan(context[1][0].couplings),
        evidence_graph=merge_graphs(graph, projection),
        methods={method.method_id: method for _, method, _ in context},
        scenarios={
            (method.method_id, position.scenario_id): position
            for _, method, position in context
        },
        outputs={
            previous.check_id: (previous, observation, False),
            current.check_id: (current, None, live),
        },
    )

    result = Binder().resolve_check(check, state)

    assert (result is not None) == (not live)
    if result is not None:
        assert (
            dict(result.request)["widget_id"] == dict(observation.output.fields)["id"]
        )


def test_concrete_target_selects_compatible_durable_occurrence():
    one, _ = history("X")
    two, _ = history("Y")
    context = bindings()
    service, target, _ = workflow(context, graph=merge_graphs(one, two))
    check = generate(service, context[1]).model_copy(
        update={"request": (("widget_id", "Y"),)}
    )
    assert service.execute_check(check) is not None
    assert target.calls == [check]


def _correlated_history():
    token_output = output_field(MAKE, Atom(value="token"))
    token_input = input_field(USE, Atom(value="token"))
    extra = tuple(
        fact("is", field, Atom(value=kind), context=Context.ACCEPTED)
        for field, kind in ((token_output, "OutputField"), (token_input, "InputField"))
    ) + (
        fact("has", token_output, Atom(value="object_ref"), context=Context.ACCEPTED),
        fact("refers_to", token_output, RESOURCE, context=Context.ACCEPTED),
        fact("refers_to", token_input, RESOURCE, context=Context.ACCEPTED),
        fact(
            "coupled",
            token_output,
            token_input,
            Atom(value="eq"),
            context=Context.ACCEPTED,
        ),
    )
    graph = QdlGraph(facts=declarations().facts + extra)
    context = bindings()
    extra_coupling = (token_output, token_input, "eq")
    context = tuple(
        (
            p.model_copy(update={"couplings": (*p.couplings, extra_coupling)}),
            m
            if i == 0
            else m.model_copy(
                update={"fields": (*m.fields, FieldSpec(name="token", type="string"))}
            ),
            s,
        )
        for i, (p, m, s) in enumerate(context)
    )
    for index, (identifier, token) in enumerate((("X", "red"), ("Y", "blue"))):
        observation = Observation(
            check_id=f"check-{index}",
            scenario_id=context[0][2].scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="OK",
            output=ResponseData(fields=(("id", identifier), ("token", token))),
        )
        graph = merge_graphs(
            graph,
            ObservationProjector().project(
                observation,
                context[0][1].method_id,
                graph=graph,
                identities=("actor",),
                scope=scenario_scope(context[0][2]),
                observed_at=float(index + 1),
            ),
        )
    return graph, context


@pytest.mark.parametrize(
    "identifier,allowed", [(None, True), ("Y", True), ("X", False)]
)
def test_durable_fields_join_same_observation_after_all_constraints(
    identifier, allowed
):
    graph, context = _correlated_history()
    service, target, guardrail = workflow(context, graph=graph)
    check = generate(service, context[1]).model_copy(
        update={"request": (("widget_id", identifier), ("token", "blue"))}
    )
    assert (service.execute_check(check) is not None) == allowed
    assert len(target.calls) == len(guardrail.checks) == int(allowed)
    if allowed:
        assert dict(target.calls[-1].request) == {"widget_id": "Y", "token": "blue"}


@pytest.mark.parametrize("echo,allowed", [("marker", True), ("foreign", False)])
def test_input_to_later_output_is_a_consumption_postcondition(echo, allowed):
    a, b, c = (Atom(value=f"action:{name}") for name in ("A", "B", "C"))
    couplings = (
        (
            input_field(a, Atom(value="nonce")),
            output_field(b, Atom(value="echo")),
            "eq",
        ),
        (output_field(b, Atom(value="id")), input_field(c, Atom(value="target")), "eq"),
    )
    context = []
    for name, fields in (("A", ("nonce",)), ("B", ()), ("C", ("target",))):
        method = MethodSpec(
            method_id=name,
            name=name,
            service="s",
            layer=EndpointLayer.PRIVATE,
            fields=tuple(FieldSpec(name=f, type="string") for f in fields),
        )
        context.append(
            (
                VerificationPlan(
                    plan_id=name,
                    invariant_id="inv",
                    method_id=name,
                    couplings=couplings,
                ),
                method,
                scenario(name),
            )
        )
    calls = []

    def target(check):
        calls.append(check)
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="OK",
            output=ResponseData(fields=(("echo", echo), ("id", "chosen")))
            if check.method_id == "B"
            else None,
        )

    guardrail = Guardrail()
    service = Checker(target, TemplateGenerator(), guardrail)
    service.set_coupling_context(context)
    checks = [
        Check(
            invariant_id="inv",
            method_id=name,
            scenario_id=name,
            identities=("actor",),
            request=request,
        )
        for name, request in (
            ("A", (("nonce", "marker"),)),
            ("B", ()),
            ("C", (("target", None),)),
        )
    ]
    assert service.execute_check(checks[0]) is not None
    assert service.execute_check(checks[1]) is not None
    assert (service.execute_check(checks[2]) is not None) == allowed
    assert len(calls) == len(guardrail.checks) == 2 + int(allowed)


def _required_graph(*, second=False, second_proof=False, context=Context.ACCEPTED):
    graph, _ = history("X")
    effect = create(RESOURCE)
    extra = [
        fact("has", INPUT, Atom(value="object_ref"), context=Context.ACCEPTED),
        fact("requires", USE, effect, context=context),
    ]
    if second:
        other = Struct(name="remove", args=(RESOURCE,))
        extra.extend(
            (
                fact("is", other, Atom(value="Effect"), context=Context.ACCEPTED),
                fact("causes", MAKE, other, context=Context.ACCEPTED),
                fact("requires", USE, other, context=Context.ACCEPTED),
            )
        )
        if second_proof:
            observation = next(
                f.args[0]
                for f in graph.facts
                if f.predicate.name == "evidence" and f.args[1] == effect
            )
            extra.append(fact("evidence", observation, other))
    return QdlGraph(facts=graph.facts + tuple(extra))


@pytest.mark.parametrize("target_id,allowed", [("X", True), ("Y", False)])
def test_adaptive_requires_match_actual_typed_target_without_source_norm(
    target_id, allowed
):
    graph = _required_graph()
    context = bindings()
    # Isolate causal readiness from the output/input equality constraint.
    context = tuple(
        (p.model_copy(update={"couplings": ()}), m, s) for p, m, s in context
    )
    service, target, guardrail = workflow(context, graph=graph)
    check = generate(service, context[1]).model_copy(
        update={"request": (("widget_id", target_id),)}
    )
    assert (service.resolve_check(check) is not None) == allowed
    assert (service.execute_check(check) is not None) == allowed
    assert len(target.calls) == len(guardrail.checks) == int(allowed)


@pytest.mark.parametrize("second_proof", [False, True])
def test_every_causal_requires_needs_its_own_evidence(second_proof):
    graph = _required_graph(second=True, second_proof=second_proof)
    context = bindings()
    service, target, _ = workflow(context, graph=graph)
    assert (
        service.execute_check(generate(service, context[1])) is not None
    ) == second_proof
    assert len(target.calls) == int(second_proof)


def test_declared_causes_alone_do_not_meet_requires():
    graph = _required_graph()
    graph = QdlGraph(
        facts=tuple(f for f in graph.facts if f.context != Context.RUNTIME)
    )
    context = tuple(
        (p.model_copy(update={"couplings": ()}), m, s) for p, m, s in bindings()
    )
    service, target, guardrail = workflow(context, graph=graph)
    check = generate(service, context[1]).model_copy(
        update={"request": (("widget_id", "X"),)}
    )
    assert service.execute_check(check) is None
    assert target.calls == guardrail.checks == []


def test_atom_permission_and_proposal_causal_requirement_do_not_gate_dast():
    graph = QdlGraph(
        facts=declarations().facts
        + (
            fact(
                "is",
                Atom(value="permission:denied"),
                Atom(value="Permission"),
                context=Context.ACCEPTED,
            ),
            fact(
                "requires",
                USE,
                Atom(value="permission:denied"),
                context=Context.ACCEPTED,
            ),
            fact("requires", USE, create(RESOURCE), context=Context.PROPOSAL),
        )
    )
    context = tuple(
        (p.model_copy(update={"couplings": ()}), m, s) for p, m, s in bindings()
    )
    service, target, _ = workflow(context, graph=graph)
    assert service.execute_check(generate(service, context[1])) is not None
    assert len(target.calls) == 1


@pytest.mark.parametrize("current_requires", [False, True])
def test_struct_action_requirement_is_unrelated_to_runtime_method(current_requires):
    structured_action = Struct(name="allowed", args=(MAKE,))
    extra = (
        fact("is", structured_action, Atom(value="Action"), context=Context.ACCEPTED),
        fact("requires", structured_action, create(RESOURCE), context=Context.ACCEPTED),
    )
    if current_requires:
        extra += (fact("requires", USE, create(RESOURCE), context=Context.ACCEPTED),)
    graph = QdlGraph(facts=declarations().facts + extra)
    context = tuple(
        (p.model_copy(update={"couplings": ()}), m, s) for p, m, s in bindings()
    )
    service, target, guardrail = workflow(context, graph=graph)
    check = generate(service, context[1])
    assert (service.execute_check(check) is not None) == (not current_requires)
    assert len(target.calls) == len(guardrail.checks) == int(not current_requires)
