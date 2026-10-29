from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from cloud_dast.qdl.graph import (
    PREDICATE_SCHEMAS,
    RECURSIVE_PREDICATES,
    ArgumentSchema,
    Atom,
    Context,
    Fact,
    Predicate,
    PredicateSchema,
    QdlGraph,
    Rule,
    Struct,
    TermKind,
    Variable,
    allowed,
    ambiguous,
    canonical_json,
    changed,
    completed,
    denied,
    differs,
    duration,
    external_call,
    field,
    has,
    hash_content,
    identity,
    input_field,
    missing,
    outcome,
    output_field,
    reached,
    response_status,
    source,
    transition,
    unmapped,
)

ACTION = Atom(value="action:get_secret")
PERMISSION = Atom(value="permission:secret.get")
RESOURCE = Atom(value="resource:secret")
NORM = Atom(value="norm:secret_visibility")
OBSERVATION = Atom(value="observation:get_secret:1")


def make_fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.CONTRACT,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def make_graph(*facts: Fact, rules: tuple[Rule, ...] = ()) -> QdlGraph:
    return QdlGraph(facts=facts, rules=rules)


def make_closure_predicate(name: str) -> Predicate:
    return Predicate.from_schema(
        PredicateSchema(
            name=name,
            arguments=(
                ArgumentSchema(
                    name="source",
                    ground_types=(TermKind.ATOM, TermKind.STRUCT),
                    reference=True,
                ),
                ArgumentSchema(
                    name="target",
                    ground_types=(TermKind.ATOM, TermKind.STRUCT),
                    reference=True,
                ),
            ),
        )
    )


def make_closure_fact(
    predicate: Predicate,
    args: tuple[object, ...],
    context: Context = Context.CONTRACT,
) -> Fact:
    return Fact(
        context=context,
        predicate=predicate,
        args=args,  # type: ignore[arg-type]
    )


def make_valid_graph() -> QdlGraph:
    return make_graph(
        make_fact("is", (ACTION, Atom(value="Action"))),
        make_fact("is", (PERMISSION, Atom(value="Permission"))),
        make_fact("requires", (ACTION, PERMISSION)),
    )


def test_terms_are_immutable_and_round_trip() -> None:
    terms = (
        Atom(value="logical-id"),
        Atom(value=42),
        Atom(value=True),
        Variable(name="Action"),
        changed(RESOURCE, Atom(value="role")),
    )

    for term in terms:
        with pytest.raises(ValidationError):
            setattr(term, "kind", "changed")
        restored = type(term).model_validate_json(term.model_dump_json())
        assert restored == term
        assert canonical_json(restored) == canonical_json(term)


def test_atom_keeps_string_integer_and_boolean_distinct() -> None:
    assert Atom(value="1") != Atom(value=1)
    assert Atom(value=1) != Atom(value=True)
    assert Atom(value=1) != Atom(value=1.5)
    assert Atom(value=True).literal_type == "boolean"
    assert Atom(value=1.5).literal_type == "float"


def test_path_qualified_field_names_do_not_collapse() -> None:
    nested = input_field(ACTION, Atom(value="request.user.role"))
    flat = input_field(ACTION, Atom(value="role"))

    assert nested != flat
    assert canonical_json(nested) != canonical_json(flat)


@pytest.mark.parametrize(
    "constructor",
    [
        lambda: allowed(ACTION),
        lambda: input_field(ACTION, Atom(value="request.user.role")),
        lambda: output_field(ACTION, Atom(value="response.secret")),
        lambda: changed(RESOURCE, Atom(value="role")),
        lambda: external_call(ACTION, Atom(value="marker:downstream")),
        lambda: duration(ACTION, Atom(value=150)),
        lambda: duration(ACTION, Atom(value=150.5)),
        lambda: reached(ACTION, Atom(value="sink:database")),
        lambda: completed(Atom(value="flow:create-user")),
        lambda: denied(ACTION),
        lambda: differs(ACTION, Atom(value="outcome")),
        lambda: identity(
            Atom(value="principal:attacker"), Atom(value="principal:victim")
        ),
        lambda: missing(changed(RESOURCE, Atom(value="role"))),
        lambda: response_status(ACTION, Atom(value="grpc.OK")),
        lambda: outcome(ACTION, Atom(value="allowed")),
        lambda: source(Atom(value="neo4j"), Atom(value="logical:method:get")),
        lambda: unmapped(
            Atom(value="param"),
            Atom(value="legacy:key"),
            Atom(value="no canonical naming"),
        ),
        lambda: ambiguous(
            Atom(value="permission"),
            Atom(value="legacy:secret.get"),
            Atom(value="permission:secret.get|permission:secrets.get"),
        ),
    ],
)
def test_typed_constructors_build_structural_terms(constructor) -> None:
    term = constructor()

    assert isinstance(term, Struct)
    assert term.kind == "struct"


def test_struct_rejects_unknown_constructor_and_wrong_arity() -> None:
    with pytest.raises(ValidationError, match="unknown term constructor"):
        Struct(name="free_text", args=(Atom(value="mass assignment"),))

    with pytest.raises(ValidationError, match="input_field expects 2 arguments"):
        Struct(name="input_field", args=(ACTION,))


def test_struct_rejects_wrong_literal_type() -> None:
    with pytest.raises(
        ValidationError, match="milliseconds must be integer, float atom"
    ):
        duration(ACTION, Atom(value="150"))


def test_runtime_evidence_constructors_are_canonical_and_hash_stable() -> None:
    terms = (
        response_status(ACTION, Atom(value="grpc.PERMISSION_DENIED")),
        outcome(ACTION, Atom(value="denied")),
        source(Atom(value="neo4j"), Atom(value="logical:method:get")),
        unmapped(Atom(value="param"), Atom(value="legacy:key"), Atom(value="no name")),
        ambiguous(
            Atom(value="permission"),
            Atom(value="legacy:secret.get"),
            Atom(value="permission:secret.get|permission:secrets.get"),
        ),
    )

    for term in terms:
        copy = type(term).model_validate_json(term.model_dump_json())
        assert copy == term
        assert canonical_json(copy) == canonical_json(term)
        assert hash_content(copy) == hash_content(term)


def test_runtime_evidence_graph_is_canonical_across_fact_order() -> None:
    facts = (
        make_fact("is", (ACTION, Atom(value="Action"))),
        make_fact("is", (OBSERVATION, Atom(value="Observation"))),
        make_fact(
            "evidence",
            (OBSERVATION, response_status(ACTION, Atom(value="grpc.OK"))),
            context=Context.RUNTIME,
        ),
        make_fact(
            "evidence",
            (OBSERVATION, outcome(ACTION, Atom(value="allowed"))),
            context=Context.RUNTIME,
        ),
        make_fact(
            "evidence",
            (
                OBSERVATION,
                unmapped(
                    Atom(value="param"),
                    Atom(value="legacy:key"),
                    Atom(value="no canonical name"),
                ),
            ),
            context=Context.RUNTIME,
        ),
    )
    first = QdlGraph(facts=facts)
    second = QdlGraph(facts=tuple(reversed(facts)))

    assert first == second
    assert first.facts == second.facts
    assert first.content_hash == second.content_hash


def test_runtime_evidence_qualified_identifiers_do_not_collapse() -> None:
    qualified = response_status(ACTION, Atom(value="grpc.PERMISSION_DENIED"))
    local = response_status(ACTION, Atom(value="PERMISSION_DENIED"))
    transport = response_status(ACTION, Atom(value="http:403"))

    assert qualified != local
    assert qualified != transport
    assert local != transport
    assert (
        len(
            {
                canonical_json(qualified),
                canonical_json(local),
                canonical_json(transport),
            }
        )
        == 3
    )

    first_source = source(Atom(value="neo4j"), Atom(value="logical:method:get"))
    second_source = source(Atom(value="openapi"), Atom(value="logical:method:get"))
    assert first_source != second_source


def test_runtime_evidence_rejects_unknown_constructor_and_wrong_arity() -> None:
    with pytest.raises(ValidationError, match="unknown term constructor"):
        Struct(name="bogus", args=(ACTION, Atom(value="grpc.OK")))

    with pytest.raises(ValidationError, match="response_status expects 2 arguments"):
        Struct(name="response_status", args=(ACTION,))

    with pytest.raises(ValidationError, match="ambiguous expects 3 arguments"):
        Struct(
            name="ambiguous",
            args=(Atom(value="permission"), Atom(value="legacy:secret.get")),
        )


def test_runtime_evidence_constructors_are_strictly_typed() -> None:
    with pytest.raises(ValidationError, match="status must be string atom"):
        response_status(ACTION, Atom(value=7))

    with pytest.raises(ValidationError, match="result must be string atom"):
        outcome(ACTION, Atom(value=True))

    with pytest.raises(ValidationError, match="kind must be string atom"):
        source(Atom(value=1), Atom(value="logical:method:get"))

    with pytest.raises(ValidationError, match="reason must be string atom"):
        unmapped(Atom(value="param"), Atom(value="legacy:key"), Atom(value=404))


def test_evidence_accepts_runtime_records() -> None:
    graph = make_graph(
        make_fact("is", (ACTION, Atom(value="Action"))),
        make_fact("is", (OBSERVATION, Atom(value="Observation"))),
        make_fact(
            "evidence",
            (OBSERVATION, response_status(ACTION, Atom(value="grpc.OK"))),
            context=Context.RUNTIME,
        ),
        make_fact(
            "evidence",
            (OBSERVATION, outcome(ACTION, Atom(value="allowed"))),
            context=Context.RUNTIME,
        ),
    )

    assert len(graph.facts) == 4


def test_evidence_accepts_differential_witness() -> None:
    graph = make_graph(
        make_fact("is", (ACTION, Atom(value="Action"))),
        make_fact("is", (OBSERVATION, Atom(value="Observation"))),
        make_fact(
            "evidence",
            (OBSERVATION, differs(ACTION, Atom(value="outcome"))),
            context=Context.RUNTIME,
        ),
    )

    assert len(graph.facts) == 3


def test_evidence_accepts_adapter_mapping_records_without_references() -> None:
    graph = make_graph(
        make_fact("is", (OBSERVATION, Atom(value="Observation"))),
        make_fact(
            "evidence",
            (OBSERVATION, source(Atom(value="neo4j"), Atom(value="slice:v1"))),
            context=Context.RUNTIME,
        ),
        make_fact(
            "evidence",
            (
                OBSERVATION,
                ambiguous(
                    Atom(value="permission"),
                    Atom(value="legacy:secret.get"),
                    Atom(value="permission:secret.get|permission:secrets.get"),
                ),
            ),
            context=Context.RUNTIME,
        ),
    )

    assert len(graph.facts) == 3


def test_prevents_and_causes_reject_runtime_evidence_effects() -> None:
    evidence = (
        response_status(ACTION, Atom(value="grpc.OK")),
        outcome(ACTION, Atom(value="allowed")),
        differs(ACTION, Atom(value="outcome")),
        source(Atom(value="neo4j"), Atom(value="slice:v1")),
        unmapped(Atom(value="param"), Atom(value="legacy:key"), Atom(value="no name")),
        ambiguous(
            Atom(value="permission"),
            Atom(value="legacy:secret.get"),
            Atom(value="permission:secret.get"),
        ),
    )

    for term in evidence:
        with pytest.raises(
            ValidationError,
            match=f"effect must be .* struct, got {term.name}",
        ):
            make_fact("prevents", (NORM, term))

        with pytest.raises(
            ValidationError,
            match=f"effect must be .* struct, got {term.name}",
        ):
            make_fact("causes", (ACTION, term))


def test_response_status_action_reference_must_be_declared() -> None:
    with pytest.raises(ValidationError, match="unknown reference"):
        make_graph(
            make_fact(
                "evidence",
                (OBSERVATION, response_status(ACTION, Atom(value="grpc.OK"))),
                context=Context.RUNTIME,
            )
        )


def test_base_predicate_set_is_canonical() -> None:
    assert {schema.name for schema in PREDICATE_SCHEMAS} == {
        "is",
        "part",
        "has",
        "may",
        "requires",
        "causes",
        "executes",
        "binds",
        "observes",
        "reaches",
        "exposes",
        "accepts",
        "required",
        "targets",
        "owner",
        "binding",
        "attacker",
        "grants",
        "applies_to",
        "transition",
        "initial",
        "forbidden",
        "coupled",
        "format",
        "constraint",
        "dialect",
        "prevents",
        "evidence",
        "observed_outcome",
        "observed_transition",
        "observed_reached",
        "observed_response_status",
        "observed_field",
        "observed_error",
        "observed_marker",
        "observed_external_call",
        "observed_duration",
        "observed_unmapped",
        "paired",
        "supersedes",
        "signal",
        "signal_grounds",
        "sink_interprets",
    }


def test_unknown_predicate_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown predicate"):
        Predicate.from_name("target")


def test_wrong_predicate_arity_is_rejected() -> None:
    with pytest.raises(ValidationError, match="requires expects 2 arguments"):
        make_fact("requires", (ACTION,))


def test_effect_predicate_rejects_free_text_atom() -> None:
    with pytest.raises(ValidationError, match="effect must be a struct"):
        make_fact("prevents", (NORM, Atom(value="mass assignment")))


def test_outcome_effects_are_causal() -> None:
    graph = make_graph(
        make_fact("is", (ACTION, Atom(value="Action"))),
        make_fact("is", (NORM, Atom(value="Norm"))),
        make_fact("prevents", (NORM, allowed(ACTION))),
        make_fact("prevents", (NORM, denied(ACTION))),
    )

    assert len(graph.facts) == 4


def test_has_effect_value_must_be_graph_grounded() -> None:
    witness = field(RESOURCE, Atom(value="private_key"))
    principal = Atom(value="principal:attacker")
    declarations = (
        make_fact("is", (principal, Atom(value="Principal"))),
        make_fact("is", (RESOURCE, Atom(value="Resource"))),
        make_fact("is", (witness, Atom(value="Witness"))),
        make_fact("is", (NORM, Atom(value="Norm"))),
    )

    grounded = make_graph(
        *declarations,
        make_fact("prevents", (NORM, has(principal, witness))),
    )
    assert any(fact.predicate.name == "prevents" for fact in grounded.facts)

    with pytest.raises(ValidationError, match="unknown reference"):
        make_graph(
            *(fact for fact in declarations if fact.args[0] != witness),
            make_fact("prevents", (NORM, has(principal, witness))),
        )


def test_nested_has_effect_value_must_be_graph_grounded() -> None:
    outer = Atom(value="principal:attacker")
    relay = Atom(value="principal:relay")
    secret = Atom(value="secret")
    nested = has(relay, secret)
    declarations = (
        make_fact("is", (outer, Atom(value="Principal"))),
        make_fact("is", (relay, Atom(value="Principal"))),
        make_fact("is", (secret, Atom(value="Secret"))),
        make_fact("is", (nested, Atom(value="Possession"))),
        make_fact("is", (NORM, Atom(value="Norm"))),
    )

    grounded = make_graph(
        *declarations,
        make_fact("prevents", (NORM, has(outer, nested))),
    )
    assert any(fact.predicate.name == "prevents" for fact in grounded.facts)

    with pytest.raises(ValidationError, match="unknown reference"):
        make_graph(
            *(fact for fact in declarations if fact.args[0] != nested),
            make_fact("prevents", (NORM, has(outer, nested))),
        )


def test_transition_effect_states_must_be_graph_grounded() -> None:
    draft = Atom(value="state:draft")
    active = Atom(value="state:active")
    declarations = (
        make_fact("is", (draft, Atom(value="State"))),
        make_fact("is", (active, Atom(value="State"))),
        make_fact("is", (NORM, Atom(value="Norm"))),
    )

    grounded = make_graph(
        *declarations,
        make_fact("prevents", (NORM, transition(draft, active))),
    )
    assert any(fact.predicate.name == "prevents" for fact in grounded.facts)

    with pytest.raises(ValidationError, match="unknown reference"):
        make_graph(
            make_fact("is", (draft, Atom(value="State"))),
            make_fact("is", (NORM, Atom(value="Norm"))),
            make_fact("prevents", (NORM, transition(draft, active))),
        )


def test_context_is_strict() -> None:
    assert Context("contract") is Context.CONTRACT

    with pytest.raises(ValidationError):
        make_fact("requires", (ACTION, PERMISSION), context="contract:uuid")


def test_predicate_schema_is_declaratively_extensible() -> None:
    schema = PredicateSchema(
        name="field_type",
        arguments=(
            ArgumentSchema(name="field"),
            ArgumentSchema(
                name="type",
                ground_types=(TermKind.ATOM,),
                atom_types=("string",),
            ),
        ),
    )
    predicate = Predicate.from_schema(schema)
    fact = Fact(
        context=Context.CONTRACT,
        predicate=predicate,
        args=(input_field(ACTION, Atom(value="role")), Atom(value="string")),
    )
    graph = make_graph(
        make_fact("is", (ACTION, Atom(value="Action"))),
        fact,
    )

    restored = QdlGraph.model_validate_json(graph.model_dump_json())

    assert restored == graph
    assert restored.facts[0].predicate.name == "field_type"


def test_predicate_verification_classes_are_ontology_defaults() -> None:
    classes = {schema.name: schema.verification_class for schema in PREDICATE_SCHEMAS}
    extension_schema = PredicateSchema(
        name="refers_to",
        arguments=(
            ArgumentSchema(name="field"),
            ArgumentSchema(name="resource"),
        ),
    )

    assert classes["causes"] == "runtime_falsifiable"
    assert classes["exposes"] == "runtime_falsifiable"
    assert classes["requires"] == "runtime_falsifiable"
    assert classes["targets"] == "runtime_falsifiable"
    assert classes["has"] == "evidence_gated"
    assert classes["is"] == "structural"
    assert classes["reaches"] == "structural"
    assert classes["may"] == "structural"
    assert classes["transition"] == "structural"
    assert extension_schema.verification_class == "runtime_falsifiable"


def test_builtin_predicate_cannot_be_redefined() -> None:
    schema = PredicateSchema(
        name="requires",
        arguments=(ArgumentSchema(name="action"),),
    )

    with pytest.raises(ValueError, match="built-in predicate cannot be redefined"):
        Predicate.from_schema(schema)


def test_graph_is_immutable() -> None:
    graph = make_valid_graph()

    with pytest.raises(ValidationError):
        graph.facts = ()


def test_graph_rejects_duplicate_facts() -> None:
    fact = make_fact("is", (ACTION, Atom(value="Action")))

    with pytest.raises(ValidationError, match="duplicate fact"):
        make_graph(fact, fact)


def test_graph_rejects_variables_in_facts() -> None:
    fact = make_fact(
        "is",
        (Variable(name="Action"), Variable(name="Type")),
    )

    with pytest.raises(ValidationError, match="graph fact contains variable"):
        make_graph(fact)


def test_graph_rejects_unknown_references() -> None:
    with pytest.raises(ValidationError, match="unknown reference"):
        make_graph(make_fact("requires", (ACTION, PERMISSION)))


def test_graph_validates_references_inside_structural_terms() -> None:
    graph = make_graph(
        make_fact("is", (ACTION, Atom(value="Action"))),
        make_fact("is", (RESOURCE, Atom(value="Resource"))),
        make_fact("causes", (ACTION, changed(RESOURCE, Atom(value="role")))),
    )

    assert len(graph.facts) == 3


def test_graph_facts_are_canonically_sorted_and_hash_is_stable() -> None:
    first = make_valid_graph()
    second = QdlGraph(facts=tuple(reversed(first.facts)))

    assert first == second
    assert first.facts == second.facts
    assert first.content_hash == second.content_hash
    assert first.content_hash == hash_content(second)


def test_graph_round_trips_through_json() -> None:
    graph = make_valid_graph()

    restored = QdlGraph.model_validate_json(graph.model_dump_json())

    assert restored == graph
    assert restored.content_hash == graph.content_hash


def make_rule(head: str, body: str) -> Rule:
    action = Variable(name="Action")
    requirement = Variable(name="Requirement")
    type_ = Variable(name="Type")
    requirement_type = Variable(name="RequirementType")
    return Rule(
        body=(
            make_fact("is", (action, type_)),
            make_fact("is", (requirement, requirement_type)),
            make_fact(body, (action, requirement)),
        ),
        head=(make_fact(head, (action, requirement)),),
    )


def test_rule_rejects_multi_head_literals() -> None:
    action = Variable(name="Action")
    permission = Variable(name="Permission")
    action_type = Variable(name="ActionType")
    permission_type = Variable(name="PermissionType")

    with pytest.raises(
        ValidationError,
        match="rule head must contain exactly one literal",
    ):
        Rule(
            body=(
                make_fact("is", (action, action_type)),
                make_fact("is", (permission, permission_type)),
            ),
            head=(
                make_fact("part", (action, permission)),
                make_fact("requires", (action, permission)),
            ),
        )


def test_recursive_predicate_whitelist_is_explicit() -> None:
    assert RECURSIVE_PREDICATES == {
        "part_plus",
        "requires_plus",
        "chain_plus",
        "may_plus",
        "affected_plus",
        "reachable",
        "reaches_plus",
    }


def test_rule_accepts_direct_part_plus_recursion() -> None:
    part_plus = make_closure_predicate("part_plus")
    child = Variable(name="Child")
    middle = Variable(name="Middle")
    parent = Variable(name="Parent")
    rule = Rule(
        body=(
            make_fact("part", (child, middle)),
            make_closure_fact(part_plus, (middle, parent)),
        ),
        head=(make_closure_fact(part_plus, (child, parent)),),
    )

    graph = make_graph(rules=(rule,))
    restored = Rule.model_validate_json(rule.model_dump_json())

    assert len(graph.rules) == 1
    assert restored == rule


def test_rule_rejects_direct_recursion_for_arbitrary_predicate() -> None:
    path = make_closure_predicate("path")
    source = Variable(name="Source")
    target = Variable(name="Target")

    with pytest.raises(
        ValidationError,
        match="rule dependency cycle: direct recursion",
    ):
        Rule(
            body=(make_closure_fact(path, (source, target)),),
            head=(make_closure_fact(path, (source, target)),),
        )


def test_graph_accepts_transitive_recursion_between_whitelisted_predicates() -> None:
    part_plus = make_closure_predicate("part_plus")
    reachable = make_closure_predicate("reachable")
    source = Variable(name="Source")
    target = Variable(name="Target")
    first = Rule(
        body=(make_closure_fact(reachable, (source, target)),),
        head=(make_closure_fact(part_plus, (source, target)),),
    )
    second = Rule(
        body=(make_closure_fact(part_plus, (source, target)),),
        head=(make_closure_fact(reachable, (source, target)),),
    )

    graph = make_graph(rules=(first, second))

    assert len(graph.rules) == 2


def test_graph_rejects_transitive_recursion_with_arbitrary_predicate() -> None:
    part_plus = make_closure_predicate("part_plus")
    path = make_closure_predicate("path")
    source = Variable(name="Source")
    target = Variable(name="Target")
    first = Rule(
        body=(make_closure_fact(part_plus, (source, target)),),
        head=(make_closure_fact(path, (source, target)),),
    )
    second = Rule(
        body=(make_closure_fact(path, (source, target)),),
        head=(make_closure_fact(part_plus, (source, target)),),
    )

    with pytest.raises(ValidationError, match="rule dependency cycle"):
        make_graph(rules=(first, second))


def test_graph_rejects_disallowed_cycle_alongside_allowed_cycle() -> None:
    part_plus = make_closure_predicate("part_plus")
    reachable = make_closure_predicate("reachable")
    path = make_closure_predicate("path")
    other = make_closure_predicate("other")
    source = Variable(name="Source")
    target = Variable(name="Target")
    allowed_first = Rule(
        body=(make_closure_fact(reachable, (source, target)),),
        head=(make_closure_fact(part_plus, (source, target)),),
    )
    allowed_second = Rule(
        body=(make_closure_fact(part_plus, (source, target)),),
        head=(make_closure_fact(reachable, (source, target)),),
    )
    disallowed_first = Rule(
        body=(make_closure_fact(path, (source, target)),),
        head=(make_closure_fact(other, (source, target)),),
    )
    disallowed_second = Rule(
        body=(make_closure_fact(other, (source, target)),),
        head=(make_closure_fact(path, (source, target)),),
    )

    with pytest.raises(ValidationError, match="rule dependency cycle"):
        make_graph(
            rules=(allowed_first, allowed_second, disallowed_first, disallowed_second)
        )


def test_recursive_rule_keeps_safety_validation() -> None:
    part_plus = make_closure_predicate("part_plus")
    child = Variable(name="Child")
    middle = Variable(name="Middle")
    parent = Variable(name="Parent")

    with pytest.raises(ValidationError, match="rule head variable Parent"):
        Rule(
            body=(make_closure_fact(part_plus, (child, middle)),),
            head=(make_closure_fact(part_plus, (child, parent)),),
        )

    with pytest.raises(
        ValidationError,
        match="rule literals must share one context",
    ):
        Rule(
            body=(
                make_closure_fact(
                    part_plus,
                    (child, middle),
                    context=Context.PROPOSAL,
                ),
            ),
            head=(
                make_closure_fact(
                    part_plus,
                    (child, parent),
                    context=Context.ACCEPTED,
                ),
            ),
        )

    action = Variable(name="Action")
    resource = Variable(name="Resource")
    field_name = Variable(name="Field")
    with pytest.raises(ValidationError, match="creates a new structural term"):
        Rule(
            body=(
                make_closure_fact(part_plus, (action, resource)),
                make_fact("is", (field_name, Atom(value="Field"))),
            ),
            head=(
                make_closure_fact(
                    part_plus,
                    (action, changed(resource, field_name)),
                ),
            ),
        )


def test_recursive_graph_has_stable_canonical_hash() -> None:
    part_plus = make_closure_predicate("part_plus")
    reachable = make_closure_predicate("reachable")
    source = Variable(name="Source")
    target = Variable(name="Target")
    first = Rule(
        body=(make_closure_fact(reachable, (source, target)),),
        head=(make_closure_fact(part_plus, (source, target)),),
    )
    second = Rule(
        body=(make_closure_fact(part_plus, (source, target)),),
        head=(make_closure_fact(reachable, (source, target)),),
    )

    graph = make_graph(rules=(first, second))
    reordered = make_graph(rules=(second, first))
    restored = QdlGraph.model_validate_json(graph.model_dump_json())

    assert graph == reordered
    assert graph.rules == reordered.rules
    assert graph.content_hash == reordered.content_hash
    assert restored.content_hash == graph.content_hash


def test_rule_accepts_safe_variable_bindings() -> None:
    rule = Rule(
        body=(
            make_fact("is", (Variable(name="Action"), Variable(name="Type"))),
            make_fact(
                "is",
                (Variable(name="Permission"), Variable(name="PermissionType")),
            ),
        ),
        head=(
            make_fact(
                "requires",
                (Variable(name="Action"), Variable(name="Permission")),
            ),
        ),
    )

    restored = Rule.model_validate_json(rule.model_dump_json())
    assert restored == rule


def test_rule_rejects_unbound_head_variable() -> None:
    with pytest.raises(ValidationError, match="rule head variable Missing"):
        Rule(
            body=(make_fact("is", (Variable(name="Action"), Variable(name="Type"))),),
            head=(
                make_fact(
                    "requires",
                    (Variable(name="Action"), Variable(name="Missing")),
                ),
            ),
        )


def test_rule_rejects_cross_context_promotion() -> None:
    with pytest.raises(
        ValidationError,
        match="rule literals must share one context",
    ):
        Rule(
            body=(
                make_fact(
                    "is",
                    (Variable(name="Action"), Variable(name="Type")),
                    context=Context.PROPOSAL,
                ),
            ),
            head=(
                make_fact(
                    "requires",
                    (Variable(name="Action"), Variable(name="Requirement")),
                    context=Context.ACCEPTED,
                ),
            ),
        )


def test_rule_rejects_new_structural_terms_in_head() -> None:
    action = Variable(name="Action")
    resource = Variable(name="Resource")
    field_name = Variable(name="Field")
    effect = changed(resource, field_name)

    with pytest.raises(ValidationError, match="creates a new structural term"):
        Rule(
            body=(
                make_fact("is", (action, Variable(name="ActionType"))),
                make_fact("is", (resource, Variable(name="ResourceType"))),
                make_fact("is", (field_name, Variable(name="FieldType"))),
            ),
            head=(make_fact("causes", (action, effect)),),
        )


def test_rule_can_copy_structural_term_from_body() -> None:
    action = Variable(name="Action")
    resource = Variable(name="Resource")
    field_name = Variable(name="Field")
    effect = changed(resource, field_name)

    rule = Rule(
        body=(
            make_fact("causes", (action, effect)),
            make_fact("is", (Variable(name="Norm"), Variable(name="NormType"))),
        ),
        head=(make_fact("prevents", (Variable(name="Norm"), effect)),),
    )

    restored = Rule.model_validate_json(rule.model_dump_json())
    assert restored == rule


def test_rule_requires_body_and_head() -> None:
    literal = make_fact("is", (Variable(name="Action"), Variable(name="Type")))

    with pytest.raises(ValidationError, match="rule body must not be empty"):
        Rule(body=(), head=(literal,))

    with pytest.raises(ValidationError, match="rule head must not be empty"):
        Rule(body=(literal,), head=())


def test_graph_rejects_rule_dependency_cycle() -> None:
    first = make_rule(head="requires", body="prevents")
    second = make_rule(head="prevents", body="requires")

    with pytest.raises(ValidationError, match="rule dependency cycle"):
        make_graph(rules=(first, second))


def test_graph_accepts_acyclic_rule_chain() -> None:
    rules = (
        make_rule(head="requires", body="is"),
        make_rule(head="prevents", body="requires"),
    )

    graph = make_graph(rules=rules)

    assert len(graph.rules) == 2


def test_stored_predicate_definitions_coerce_to_current_basis() -> None:
    from cloud_dast.qdl.graph import (
        ArgumentSchema,
        Predicate,
        PredicateSchema,
        TermKind,
    )

    legacy = PredicateSchema(
        name="targets",
        arguments=(
            ArgumentSchema(
                name="action",
                ground_types=(TermKind.ATOM,),
                atom_types=("string",),
                reference=True,
            ),
            ArgumentSchema(
                name="resource",
                ground_types=(TermKind.ATOM,),
                atom_types=("string",),
                reference=True,
            ),
        ),
    )
    assert legacy != Predicate.from_name("targets").definition

    restored = Predicate.model_validate_json(
        Predicate(name="targets", definition=legacy).model_dump_json()
    )

    assert restored.definition == Predicate.from_name("targets").definition


@given(
    left=st.frozensets(st.sampled_from(tuple(Context))),
    right=st.frozensets(st.sampled_from(tuple(Context))),
)
def test_context_projection_composes_with_rules(left, right):
    graph = QdlGraph(
        facts=tuple(
            make_fact("is", (term, Atom(value=kind)), context)
            for context in Context
            for term, kind in ((ACTION, "Action"), (PERMISSION, "Permission"))
        ),
        rules=tuple(
            Rule(
                head=(make_fact("requires", (ACTION, PERMISSION), context),),
                body=(make_fact("is", (ACTION, Atom(value="Action")), context),),
            )
            for context in Context
        ),
    )
    selected = graph.select_contexts(left)
    assert selected.select_contexts(right) == graph.select_contexts(left & right)
    assert selected.select_contexts(left) == selected
    assert all(fact.context in left for fact in selected.facts)
    assert all(
        literal.context in left
        for rule in selected.rules
        for literal in (*rule.body, *rule.head)
    )
    assert QdlGraph.model_validate_json(selected.model_dump_json()) == selected


def test_context_projection_rejects_removed_declarations():
    graph = QdlGraph(
        facts=(
            make_fact("is", (ACTION, Atom(value="Action"))),
            make_fact("has", (ACTION, Atom(value="sensitive")), Context.PROPOSAL),
        )
    )
    with pytest.raises(ValueError, match="unknown reference"):
        graph.select_contexts(frozenset({Context.PROPOSAL}))


@pytest.mark.parametrize("values", [(0.0, -0.0), (-0.0, 0.0)])
def test_context_projection_preserves_signed_zero_across_snapshots(values):
    hashes = []
    for value in values:
        retained = (
            make_fact("is", (ACTION, Atom(value="Action"))),
            make_fact("has", (ACTION, Atom(value=value))),
        )
        graph = QdlGraph(
            facts=(
                *retained,
                make_fact("has", (ACTION, Atom(value="proposal")), Context.PROPOSAL),
            )
        )
        projected = graph.select_contexts(frozenset({Context.CONTRACT}))
        assert canonical_json(projected) == canonical_json(QdlGraph(facts=retained))
        hashes.append(projected.content_hash)
    assert hashes[0] != hashes[1]


def test_context_projection_distinguishes_changed_rules_and_old_snapshots():
    selected_contexts = frozenset({Context.ACCEPTED})
    graph = QdlGraph(
        facts=tuple(
            make_fact("is", (term, Atom(value=kind)), context)
            for context in (Context.ACCEPTED, Context.PROPOSAL)
            for term, kind in ((ACTION, "Action"), (PERMISSION, "Permission"))
        )
    )
    before = graph.select_contexts(selected_contexts)
    rule = Rule(
        head=(make_fact("requires", (ACTION, PERMISSION), Context.ACCEPTED),),
        body=(make_fact("is", (ACTION, Atom(value="Action")), Context.ACCEPTED),),
    )
    revised = QdlGraph(facts=graph.facts, rules=(rule,))
    after = revised.select_contexts(selected_contexts)
    assert after.facts == before.facts
    assert after.rules == (rule,)
    assert graph.select_contexts(selected_contexts) == before
    assert before.rules == ()
