from __future__ import annotations

import hashlib
import logging

import pytest

from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Rule,
    Variable,
    allowed,
    canonical_json,
    changed,
    completed,
    create,
    duration,
    external_call,
    field,
    has,
    input_field,
    output_field,
    reached,
    transition,
)
from cloud_dast.qdl.semantic_norm_compiler import (
    DerivedSetupRequirement,
    FormalCompilationError,
    SemanticNormCompiler,
    derive_setup_requirements,
    norm_requirement,
)


def fact(
    name: str,
    *args: object,
    context: Context = Context.ACCEPTED,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(name),
        args=args,  # type: ignore[arg-type]
    )


def graph(*facts: Fact) -> QdlGraph:
    return QdlGraph(facts=facts)


def setup_requirement(name: str, *args: object) -> DerivedSetupRequirement:
    return DerivedSetupRequirement(
        predicate=name,
        args=args,  # type: ignore[arg-type]
    )


def test_setup_requirements_are_total_over_term_aspects() -> None:
    """S24R setup factor: one structural derivation for every term aspect."""

    resource = Atom(value="resource:order")
    status = Atom(value="status")
    action = Atom(value="action:orders.Update")
    any_witness = Variable(name="AnyWitness")
    any_action = Variable(name="AnyAction")
    any_type = Variable(name="AnyType")

    mutation_fixture = (
        setup_requirement("refers_to", any_witness, resource),
        setup_requirement("causes", any_action, create(resource)),
    )
    assert (
        derive_setup_requirements(changed(resource, status), aspect="effect")
        == mutation_fixture
    )
    assert (
        derive_setup_requirements(field(resource, status), aspect="resource")
        == mutation_fixture
    )

    # Request and response positions carry no fixture obligation.
    assert derive_setup_requirements(input_field(action, status), aspect="input") == ()
    assert derive_setup_requirements(field(resource, status), aspect="output") == ()

    witness = field(resource, Atom(value="email"))
    assert derive_setup_requirements(
        has(Atom(value="principal:attacker"), witness), aspect="effect"
    ) == (setup_requirement("exposes", any_action, witness),)

    assert derive_setup_requirements(
        duration(action, Atom(value=5000)), aspect="effect"
    ) == (setup_requirement("is", action, any_type),)
    assert (
        derive_setup_requirements(Atom(value="resource:order"), aspect="effect") == ()
    )


def effects(facts: tuple[Fact, ...]) -> tuple[object, ...]:
    return tuple(
        item.args[1]
        for item in facts
        if item.predicate.name == "prevents" and len(item.args) == 2
    )


def test_executable_rules_survive_context_filtering() -> None:
    action = Atom(value="action:search")
    query = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:sql")
    source = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action"), context=Context.CONTRACT),
            fact("is", query, Atom(value="Field"), context=Context.CONTRACT),
            fact("is", sink, Atom(value="interpreter"), context=Context.CONTRACT),
        ),
        rules=(
            Rule(
                body=(
                    fact(
                        "is",
                        Variable(name="Source"),
                        Atom(value="Field"),
                        context=Context.CONTRACT,
                    ),
                    fact(
                        "is",
                        Variable(name="Sink"),
                        Atom(value="interpreter"),
                        context=Context.CONTRACT,
                    ),
                ),
                head=(
                    fact(
                        "reaches",
                        Variable(name="Source"),
                        Variable(name="Sink"),
                        context=Context.CONTRACT,
                    ),
                ),
            ),
        ),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == (reached(action, sink),)


def test_invalid_filtered_graph_is_not_an_empty_result() -> None:
    action = Atom(value="action:search")
    query = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:sql")
    source = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action"), context=Context.CONTRACT),
            fact("is", sink, Atom(value="interpreter"), context=Context.CONTRACT),
            fact("is", query, Atom(value="Field"), context=Context.PROPOSAL),
        ),
        rules=(
            Rule(
                body=(
                    fact(
                        "is",
                        query,
                        Atom(value="Field"),
                        context=Context.CONTRACT,
                    ),
                ),
                head=(
                    fact(
                        "reaches",
                        query,
                        sink,
                        context=Context.CONTRACT,
                    ),
                ),
            ),
        ),
    )

    with pytest.raises(FormalCompilationError, match="invalid QDL graph"):
        SemanticNormCompiler().compile(source)


def test_permission_gap_compiles_allowed_effect() -> None:
    action = Atom(value="action:admin.delete")
    permission = Atom(value="permission:admin.delete")
    attacker = Atom(value="principal:attacker")
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", permission, Atom(value="Permission")),
        fact("is", attacker, Atom(value="Subject")),
        fact("attacker", attacker),
        fact("requires", action, permission),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == (allowed(action),)
    assert QdlGraph(facts=result)


def test_permission_gap_includes_rule_derived_requires() -> None:
    """A permission requirement derived by QDL is not lost by the compiler."""

    action = Atom(value="action:admin.delete")
    permission = Atom(value="permission:admin.delete")
    resource_type = Atom(value="resource:order")
    source = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action")),
            fact("is", permission, Atom(value="Permission")),
            fact("is", resource_type, Atom(value="ResourceType")),
            fact("targets", action, resource_type),
            fact("applies_to", permission, resource_type),
        ),
        rules=(
            Rule(
                body=(
                    fact("targets", Variable(name="Action"), Variable(name="Type")),
                    fact(
                        "applies_to",
                        Variable(name="Permission"),
                        Variable(name="Type"),
                    ),
                ),
                head=(
                    fact(
                        "requires",
                        Variable(name="Action"),
                        Variable(name="Permission"),
                    ),
                ),
            ),
        ),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == (allowed(action),)


def test_norm_requirement_returns_the_chain_subgoal_effect() -> None:
    """S21 v2: a prevents-norm requires its effect to be producible."""

    action = Atom(value="action:admin.delete")
    effect = allowed(action)
    norm = fact("prevents", Atom(value="norm:n1"), effect)

    assert norm_requirement(norm) == effect
    assert norm_requirement(fact("causes", action, effect)) is None


def test_permission_gap_does_not_require_an_attacker_hypothesis() -> None:
    action = Atom(value="action:admin.delete")
    permission = Atom(value="permission:admin.delete")
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", permission, Atom(value="Permission")),
        fact("requires", action, permission),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == (allowed(action),)


def test_existing_attacker_permission_closes_gap() -> None:
    action = Atom(value="action:get")
    permission = Atom(value="permission:read")
    attacker = Atom(value="principal:attacker")
    resource = Atom(value="resource:secret")
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", permission, Atom(value="Permission")),
        fact("is", attacker, Atom(value="Subject")),
        fact("is", resource, Atom(value="Resource")),
        fact("attacker", attacker),
        fact("requires", action, permission),
        fact("may", attacker, action, resource),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == ()


def test_permission_gap_uses_derived_iam_permission() -> None:
    action = Atom(value="action:get")
    permission = Atom(value="permission:read")
    attacker = Atom(value="principal:attacker")
    role = Atom(value="role:reader")
    folder = Atom(value="folder:secret")
    resource_type = Atom(value="resource:secret")
    resource = Atom(value="resource:secret-1")
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", permission, Atom(value="Permission")),
        fact("is", attacker, Atom(value="Subject")),
        fact("is", role, Atom(value="Role")),
        fact("is", folder, Atom(value="Scope")),
        fact("is", resource_type, Atom(value="ResourceType")),
        fact("is", resource, resource_type),
        fact("attacker", attacker),
        fact("binding", attacker, role, folder),
        fact("grants", role, permission),
        fact("requires", action, permission),
        fact("targets", action, resource_type),
        fact("applies_to", permission, resource_type),
        fact("part", resource, folder),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == ()


def test_rule_derived_requires_use_the_same_iam_permission_path() -> None:
    """Derived ``may`` still closes a requirement emitted by a QDL rule."""

    action = Atom(value="action:get")
    permission = Atom(value="permission:read")
    attacker = Atom(value="principal:attacker")
    resource_type = Atom(value="resource:secret")
    resource = Atom(value="resource:secret-1")
    source = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action")),
            fact("is", permission, Atom(value="Permission")),
            fact("is", attacker, Atom(value="Subject")),
            fact("is", resource_type, Atom(value="ResourceType")),
            fact("is", resource, resource_type),
            fact("attacker", attacker),
            fact("owner", resource, attacker),
            fact("targets", action, resource_type),
            fact("applies_to", permission, resource_type),
        ),
        rules=(
            Rule(
                body=(
                    fact("targets", Variable(name="Action"), Variable(name="Type")),
                    fact(
                        "applies_to",
                        Variable(name="Permission"),
                        Variable(name="Type"),
                    ),
                ),
                head=(
                    fact(
                        "requires",
                        Variable(name="Action"),
                        Variable(name="Permission"),
                    ),
                ),
            ),
        ),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == ()


def test_permission_gap_solver_failure_is_explicit(
    monkeypatch,
    caplog,
) -> None:
    action = Atom(value="action:admin.delete")
    permission = Atom(value="permission:admin.delete")
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", permission, Atom(value="Permission")),
        fact("requires", action, permission),
    )

    def fail_derivation(self, graph):
        raise RuntimeError("solver unavailable")

    monkeypatch.setattr(ClingoEngine, "derive_may_pairs", fail_derivation)
    with caplog.at_level(
        logging.ERROR,
        logger="cloud_dast.formal.semantic_norm_compiler",
    ):
        with pytest.raises(
            FormalCompilationError,
            match="permission-gap Clingo derivation failed",
        ) as exc_info:
            SemanticNormCompiler().compile(source)

    assert isinstance(exc_info.value.__cause__, RuntimeError)
    assert "permission_gap_derivation_failed" in caplog.text
    assert "solver unavailable" in caplog.text


def test_sensitive_exposure_compiles_possession_effect() -> None:
    action = Atom(value="action:profile.get")
    resource = Atom(value="resource:user")
    token = field(resource, Atom(value="api_token"))
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", resource, Atom(value="Resource")),
        fact("is", token, Atom(value="Field")),
        fact("exposes", action, token),
        fact("has", token, Atom(value="credential")),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == (has(Atom(value="attacker"), token),)
    assert QdlGraph(facts=result)


def test_sensitive_exposure_uses_graph_declared_principal() -> None:
    action = Atom(value="action:profile.get")
    resource = Atom(value="resource:user")
    principal = Atom(value="principal:attacker")
    token = field(resource, Atom(value="api_token"))
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", resource, Atom(value="Resource")),
        fact("is", principal, Atom(value="Principal")),
        fact("is", token, Atom(value="Field")),
        fact("exposes", action, token),
        fact("has", token, Atom(value="credential")),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == (has(principal, token),)
    assert QdlGraph(facts=result)


def test_shared_witness_requires_consistent_sensitive_roles() -> None:
    sensitive_action = Atom(value="action:secret.get")
    public_action = Atom(value="action:status.get")
    resource = Atom(value="resource:record")
    witness = field(resource, Atom(value="value"))
    sensitive_field = output_field(sensitive_action, Atom(value="value"))
    public_field = output_field(public_action, Atom(value="value"))
    source = graph(
        fact("is", sensitive_action, Atom(value="Action")),
        fact("is", public_action, Atom(value="Action")),
        fact("is", resource, Atom(value="Resource")),
        fact("is", witness, Atom(value="Field")),
        fact("exposes", sensitive_action, witness),
        fact("exposes", public_action, witness),
        fact("is", sensitive_field, Atom(value="Field")),
        fact("has", sensitive_field, Atom(value="sensitive")),
        fact("is", public_field, Atom(value="Field")),
        fact("has", public_field, Atom(value="verbose")),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == ()


def test_shared_witness_promotes_when_all_actions_mark_it_sensitive() -> None:
    first = Atom(value="action:first.get")
    second = Atom(value="action:second.get")
    resource = Atom(value="resource:record")
    witness = field(resource, Atom(value="value"))
    source = graph(
        fact("is", first, Atom(value="Action")),
        fact("is", second, Atom(value="Action")),
        fact("is", resource, Atom(value="Resource")),
        fact("is", witness, Atom(value="Field")),
        fact("exposes", first, witness),
        fact("exposes", second, witness),
        fact("has", witness, Atom(value="sensitive")),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == (has(Atom(value="attacker"), witness),)


def test_interpreter_reach_compiles_reached_effect() -> None:
    action = Atom(value="action:search")
    query = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:sql")
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", query, Atom(value="Field")),
        fact("is", sink, Atom(value="interpreter")),
        fact("reaches", query, sink),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == (reached(action, sink),)
    assert QdlGraph(facts=result)


def test_transitive_interpreter_reach_compiles_reached_effect() -> None:
    action = Atom(value="action:search")
    query = input_field(action, Atom(value="query"))
    middle = Atom(value="sink:join")
    sink = Atom(value="sink:sql")
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", query, Atom(value="Field")),
        fact("is", middle, Atom(value="Resource")),
        fact("is", sink, Atom(value="interpreter")),
        fact("reaches", query, middle),
        fact("reaches", middle, sink),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == (reached(action, sink),)
    assert QdlGraph(facts=result)


def test_external_net_reach_without_cause_is_not_executable() -> None:
    action = Atom(value="action:webhook")
    url = input_field(action, Atom(value="url"))
    marker = Atom(value="collaborator:oob")
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", url, Atom(value="Field")),
        fact("is", marker, Atom(value="external_net")),
        fact("reaches", url, marker),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == ()
    assert QdlGraph(facts=result)


def test_direct_external_call_cause_without_reach_is_not_executable() -> None:
    action = Atom(value="action:fetch")
    marker = Atom(value="marker:oob")
    effect = external_call(action, marker)
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", marker, Atom(value="Marker")),
        fact("causes", action, effect),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == ()


def test_external_call_cause_with_input_reach_is_executable() -> None:
    action = Atom(value="action:webhook")
    url = input_field(action, Atom(value="url"))
    marker = Atom(value="collaborator:oob")
    effect = external_call(action, marker)
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", url, Atom(value="Field")),
        fact("is", marker, Atom(value="external_net")),
        fact("causes", action, effect),
        fact("reaches", url, marker),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == (effect,)


def test_privileged_target_field_compiles_changed_effect() -> None:
    action = Atom(value="action:order.update")
    total = input_field(action, Atom(value="total"))
    resource = Atom(value="resource:order")
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", total, Atom(value="Field")),
        fact("is", resource, Atom(value="Resource")),
        fact("targets", action, resource),
        fact("has", total, Atom(value="privileged")),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == (changed(resource, Atom(value="total")),)
    assert QdlGraph(facts=result)


def test_compiler_ignores_proposal_and_runtime_semantics() -> None:
    action = Atom(value="action:order.update")
    resource = Atom(value="resource:order")
    total = input_field(action, Atom(value="total"))
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", resource, Atom(value="Resource")),
        fact("is", total, Atom(value="Field")),
        fact("targets", action, resource),
        fact("has", total, Atom(value="privileged"), context=Context.RUNTIME),
        fact("has", total, Atom(value="privileged"), context=Context.PROPOSAL),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == ()


def test_duration_ignores_static_numeric_guesses() -> None:
    action = Atom(value="action:list")
    source_with_one_sample = graph(
        fact("is", action, Atom(value="Action")),
        fact("causes", action, duration(action, Atom(value=150))),
    )
    source_with_distribution = graph(
        fact("is", action, Atom(value="Action")),
        fact("causes", action, duration(action, Atom(value=150))),
        fact("causes", action, duration(action, Atom(value=160))),
        fact("causes", action, duration(action, Atom(value=170))),
    )
    source_without_samples = graph(fact("is", action, Atom(value="Action")))

    with_one_sample = SemanticNormCompiler().compile(source_with_one_sample)
    with_distribution = SemanticNormCompiler().compile(source_with_distribution)
    without_samples = SemanticNormCompiler().compile(source_without_samples)

    assert effects(with_one_sample) == ()
    assert effects(with_distribution) == ()
    assert effects(without_samples) == ()


def test_duration_uses_runtime_observation_distribution_as_baseline() -> None:
    action = Atom(value="action:list")
    observations = tuple(Atom(value=f"observation:{index}") for index in range(3))
    source = graph(
        fact("is", action, Atom(value="Action")),
        *(
            fact(
                "is",
                observation,
                Atom(value="Observation"),
                context=Context.RUNTIME,
            )
            for observation in observations
        ),
        *(
            fact(
                "evidence",
                observation,
                duration(action, Atom(value=value)),
                context=Context.RUNTIME,
            )
            for observation, value in zip(
                observations,
                (100, 102, 104),
                strict=True,
            )
        ),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == (duration(action, Atom(value=113)),)


def test_state_machine_compiles_supported_effects() -> None:
    action = Atom(value="action:approve")
    from_state = Atom(value="created")
    to_state = Atom(value="approved")
    flow = Atom(value="flow:approve")
    resource = Atom(value="resource:order")
    completed_effect = completed(flow)
    changed_effect = changed(resource, Atom(value="state"))
    transition_effect = transition(from_state, to_state)
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", from_state, Atom(value="State")),
        fact("is", to_state, Atom(value="State")),
        fact("is", flow, Atom(value="Flow")),
        fact("is", resource, Atom(value="Resource")),
        fact("transition", action, from_state, to_state),
        fact("causes", action, completed_effect),
        fact("causes", action, changed_effect),
        fact("causes", action, transition_effect),
    )

    result = SemanticNormCompiler().compile(source)

    assert set(effects(result)) == {
        completed_effect,
        changed_effect,
        transition_effect,
    }
    assert QdlGraph(facts=result)


def test_causal_transition_compiles_without_a_transition_fact() -> None:
    action = Atom(value="action:approve")
    from_state = Atom(value="created")
    to_state = Atom(value="approved")
    effect = transition(from_state, to_state)
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", from_state, Atom(value="State")),
        fact("is", to_state, Atom(value="State")),
        fact("causes", action, effect),
    )

    result = SemanticNormCompiler().compile(source)

    assert effects(result) == (effect,)
    assert QdlGraph(facts=result)


def test_transition_norm_bundle_is_self_contained() -> None:
    action = Atom(value="action:approve")
    from_state = Atom(value="created")
    to_state = Atom(value="approved")
    effect = transition(from_state, to_state)
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", from_state, Atom(value="State")),
        fact("is", to_state, Atom(value="State")),
        fact("transition", action, from_state, to_state),
    )

    result = SemanticNormCompiler().compile(source)
    norm = next(
        item.args[0]
        for item in result
        if item.predicate.name == "prevents" and len(item.args) == 2
    )
    declarations = {
        (item.args[0], item.args[1])
        for item in result
        if item.predicate.name == "is" and len(item.args) == 2
    }

    assert effects(result) == (effect,)
    assert (from_state, Atom(value="State")) in declarations
    assert (to_state, Atom(value="State")) in declarations
    assert (norm, Atom(value="Norm")) in declarations
    assert QdlGraph(facts=result)


def test_compiler_is_deterministic_and_content_addressed() -> None:
    action = Atom(value="action:get")
    permission = Atom(value="permission:read")
    attacker = Atom(value="principal:attacker")
    source = graph(
        fact("is", action, Atom(value="Action")),
        fact("is", permission, Atom(value="Permission")),
        fact("is", attacker, Atom(value="Subject")),
        fact("attacker", attacker),
        fact("requires", action, permission),
    )
    compiler = SemanticNormCompiler()

    first = compiler.compile(source)
    second = compiler.compile(source)
    prevents = next(item for item in first if item.predicate.name == "prevents")
    digest = hashlib.sha256(canonical_json(allowed(action)).encode()).hexdigest()[:12]

    assert first == second
    assert prevents.args[0].value == f"norm:synthetic:allowed:{digest}"
