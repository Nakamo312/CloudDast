from __future__ import annotations

import pytest

from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    Check,
    Observation,
    Severity,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    allowed,
    changed,
    completed,
    create,
    denied,
    duration,
    external_call,
    field,
    has,
    identity,
    input_field,
    reached,
    remove,
    transition,
)
from cloud_dast.runtime.deficits import gap_for_invariant as classification_deficit
from cloud_dast.verification.taxonomy import (
    DEFAULT_CATALOG,
    ClassCatalog,
    ClassEntry,
    ClassificationFacts,
    load_entries,
)


def _invariant(effect) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="inv-1",
        norm_id="threat-1",
        statement="viewer must not read the certificate",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:inv-1"), effect),
        ),
    )


def _check(
    identities: tuple[str, ...],
    request: tuple[tuple[str, object], ...] = (("resource_id", "cert-1"),),
) -> Check:
    return Check(
        invariant_id="inv-1",
        method_id="get-cert",
        scenario_id="sc-1",
        request=request,
        identities=identities,
    )


def _observation(check: Check) -> Observation:
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="gRPC status: OK",
    )


def _fact(name: str, args: tuple[object, ...]) -> Fact:
    return Fact(
        context=Context.CONTRACT,
        predicate=Predicate.from_name(name),
        args=args,  # type: ignore[arg-type]
    )


def _input_role_graph(
    action_id: str,
    field_name: str,
    role: str,
) -> QdlGraph:
    action = Atom(value=action_id)
    field_term = input_field(action, Atom(value=field_name))
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (field_term, Atom(value="Field"))),
            _fact("has", (field_term, Atom(value=role))),
        )
    )


def test_catalog_entries_are_unique_and_consistent() -> None:
    entries = DEFAULT_CATALOG.entries
    assert len({entry.class_id for entry in entries}) == len(entries)
    active = [entry for entry in entries if entry.status == "active"]
    planned = [entry for entry in entries if entry.status == "planned"]
    assert active and planned
    assert all(not entry.requires_primitive for entry in active)
    assert all(entry.requires_primitive for entry in planned)
    assert all(entry.effect_constructors for entry in entries)
    assert all(entry.primitives for entry in entries)
    assert all(entry.owasp_api and entry.stride and entry.cwe for entry in entries)


def test_catalog_rejects_unknown_semantic_roles() -> None:
    with pytest.raises(ValueError, match="unknown semantic input roles"):
        ClassEntry.model_validate(
            {
                "class_id": "unknown-role",
                "title": "Unknown role",
                "owasp_api": "A01",
                "effect_constructors": ("allowed",),
                "primitives": ("outcome",),
                "norm_source": "test",
                "cwe": ("CWE-285",),
                "stride": ("E",),
                "input_roles": ("mystery_role",),
            }
        )


def test_classification_facts_ignore_unknown_and_engine_roles() -> None:
    action = Atom(value="action:get")
    field = input_field(action, Atom(value="resource_id"))
    graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (field, Atom(value="Field"))),
            _fact("has", (field, Atom(value="object_ref"))),
            _fact("has", (field, Atom(value="mystery_role"))),
            _fact("has", (field, Atom(value="probe_target"))),
            _fact("has", (field, Atom(value="setup_skip"))),
        )
    )

    facts = ClassificationFacts.from_graph(graph)

    assert facts.input_roles_for("action:get", "resource_id") == frozenset(
        {"object_ref"}
    )


def test_catalog_links_classes_to_qdl_effects_and_primitives() -> None:
    entries = {entry.class_id: entry for entry in load_entries()}

    assert entries["bola"].effect_constructors == ("allowed", "identity")
    assert entries["bola"].primitives == ("outcome",)
    assert entries["excessive_exposure"].effect_constructors == ("has",)
    assert entries["excessive_exposure"].primitives == ("response_field",)
    assert entries["mass_assignment"].effect_constructors == ("changed",)
    assert entries["mass_assignment"].primitives == ("differential",)
    assert entries["injection"].effect_constructors == ("reached",)
    assert entries["injection"].primitives == ("marker",)
    assert entries["injection"].sink_types == ("interpreter",)
    assert entries["state_machine_violation"].effect_constructors == ("transition",)
    assert entries["state_machine_violation"].primitives == ("sequence",)


def test_classify_identity_confusion_as_bola() -> None:
    effect = identity(
        Atom(value="principal:attacker"),
        Atom(value="principal:victim"),
    )
    entry = DEFAULT_CATALOG.classify(_invariant(effect))
    assert entry is not None
    assert entry.class_id == "bola"
    assert "CWE-639" in entry.cwe


def test_classify_method_level_norm_as_function_authz() -> None:
    effect = allowed(Atom(value="action:list-certs"))
    entry = DEFAULT_CATALOG.classify(_invariant(effect))
    assert entry is not None
    assert entry.class_id == "function_level_authz"


def test_privileged_permission_gap_classifies_as_function_authz() -> None:
    effect = allowed(Atom(value="action:delete-cert"))
    invariant = _invariant(effect)

    entry = DEFAULT_CATALOG.classify(invariant)

    assert entry is not None
    assert entry.class_id == "function_level_authz"


def test_allowed_object_reference_classifies_as_bola() -> None:
    action_id = "action:grpc:test.Service.GetOrder"
    effect = allowed(Atom(value=action_id))
    facts = ClassificationFacts.from_graph(
        _input_role_graph(action_id, "order_id", "object_ref")
    )

    entry = DEFAULT_CATALOG.classify(_invariant(effect), facts=facts)

    assert entry is not None
    assert entry.class_id == "bola"


def test_classify_dispatches_non_outcome_primitives() -> None:
    certificate = Atom(value="resource:cert")
    private_key = field(certificate, Atom(value="private_key"))
    sensitive_graph = QdlGraph(
        facts=(
            _fact("is", (certificate, Atom(value="Resource"))),
            _fact("is", (private_key, Atom(value="Witness"))),
            _fact(
                "has",
                (
                    private_key,
                    Atom(value="sensitive"),
                ),
            ),
        )
    )
    template_sink_graph = QdlGraph(
        facts=(
            _fact(
                "is",
                (Atom(value="sink:renderer"), Atom(value="template_engine")),
            ),
        )
    )
    cases = (
        (
            has(
                Atom(value="principal:attacker"),
                field(Atom(value="resource:cert"), Atom(value="private_key")),
            ),
            "excessive_exposure",
            ClassificationFacts.from_graph(sensitive_graph),
        ),
        (
            external_call(Atom(value="action:fetch"), Atom(value="marker")),
            "ssrf",
            ClassificationFacts(),
        ),
        (
            duration(Atom(value="action:get"), Atom(value=100)),
            "resource_exhaustion",
            ClassificationFacts(),
        ),
        (
            reached(Atom(value="action:render"), Atom(value="sink:renderer")),
            "ssti",
            ClassificationFacts.from_graph(template_sink_graph),
        ),
    )
    for effect, class_id, facts in cases:
        entry = DEFAULT_CATALOG.classify(_invariant(effect), facts=facts)
        assert entry is not None
        assert entry.class_id == class_id


def test_changed_without_role_fact_is_a_classification_deficit() -> None:
    effect = changed(Atom(value="resource:user"), Atom(value="role"))
    invariant = _invariant(effect)

    entry = DEFAULT_CATALOG.classify(invariant, facts=ClassificationFacts())
    classification = DEFAULT_CATALOG.classify_finding(
        invariant,
        facts=ClassificationFacts(),
    )

    assert entry is None
    assert classification.vulnerability_class == "classification_deficit"
    assert classification.deficit_reasons == ("missing_input_role",)
    assert classification.cwe
    assert classification.owasp
    assert classification.stride


def test_classify_changed_by_input_role() -> None:
    cases = (
        ("mass_assignment", "privileged"),
        ("type_confusion", "type"),
    )
    for class_id, role in cases:
        effect = changed(Atom(value="resource:api_key"), Atom(value="scope"))
        facts = ClassificationFacts.from_graph(
            _input_role_graph(
                "action:grpc:nsfy.shop.v1.KeyService.CreateApiKey",
                "scope",
                role,
            )
        )

        entry = DEFAULT_CATALOG.classify(
            _invariant(effect),
            facts=facts,
            action_id="action:grpc:nsfy.shop.v1.KeyService.CreateApiKey",
        )

        assert entry is not None
        assert entry.class_id == class_id


def test_changed_classification_ignores_method_and_field_names() -> None:
    action_id = "action:grpc:alien.Service.Zorp"
    effect = changed(Atom(value="resource:widget"), Atom(value="zork"))
    facts = ClassificationFacts.from_graph(
        _input_role_graph(action_id, "zork", "privileged")
    )

    entry = DEFAULT_CATALOG.classify(
        _invariant(effect),
        facts=facts,
        action_id=action_id,
    )

    assert entry is not None
    assert entry.class_id == "mass_assignment"


def test_proposal_role_fact_does_not_classify_a_finding() -> None:
    action_id = "action:grpc:alien.Service.Zorp"
    action = Atom(value=action_id)
    field_term = input_field(action, Atom(value="zork"))
    proposal_graph = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))).model_copy(
                update={"context": Context.PROPOSAL}
            ),
            _fact("is", (field_term, Atom(value="Field"))).model_copy(
                update={"context": Context.PROPOSAL}
            ),
            _fact("has", (field_term, Atom(value="privileged"))).model_copy(
                update={"context": Context.PROPOSAL}
            ),
        )
    )
    effect = changed(Atom(value="resource:widget"), Atom(value="zork"))

    entry = DEFAULT_CATALOG.classify(
        _invariant(effect),
        facts=ClassificationFacts.from_graph(proposal_graph),
        action_id=action_id,
    )

    assert entry is None


def test_classify_transition_as_state_machine_violation() -> None:
    effect = transition(Atom(value="paid"), Atom(value="shipped"))

    entry = DEFAULT_CATALOG.classify(_invariant(effect))

    assert entry is not None
    assert entry.class_id == "state_machine_violation"
    assert entry.owasp_api == "API6"
    assert entry.stride == ("T",)


@pytest.mark.parametrize(
    ("sink_type", "expected_class"),
    (
        ("interpreter", "injection"),
        ("filesystem", "path_traversal"),
        ("business_flow", "business_flow_abuse"),
    ),
)
@pytest.mark.parametrize(
    "sink_id",
    ("sink:arbitrary-one", "sink:arbitrary-two"),
)
def test_reached_classifies_by_generic_sink_type(
    sink_type: str,
    expected_class: str,
    sink_id: str,
) -> None:
    effect = reached(Atom(value="action:use-sink"), Atom(value=sink_id))
    facts = ClassificationFacts.from_graph(
        QdlGraph(facts=(_fact("is", (Atom(value=sink_id), Atom(value=sink_type))),))
    )

    entry = DEFAULT_CATALOG.classify(_invariant(effect), facts=facts)

    assert entry is not None
    assert entry.class_id == expected_class


def test_reached_without_sink_type_is_a_classification_deficit() -> None:
    effect = reached(
        Atom(value="action:use-sink"),
        Atom(value="sink:arbitrary-three"),
    )
    invariant = _invariant(effect)

    entry = DEFAULT_CATALOG.classify(invariant, facts=ClassificationFacts())
    classification = DEFAULT_CATALOG.classify_finding(
        invariant,
        facts=ClassificationFacts(),
    )

    assert entry is None
    assert classification.vulnerability_class == "classification_deficit"
    assert classification.deficit_reasons == ("missing_sink_type",)


@pytest.mark.parametrize("actual_type", ("Sink", "unsupported_type"))
@pytest.mark.parametrize("action_id", ("action:ShipOrder", "action:unrelated"))
def test_unsupported_sink_type_exposes_candidate_classification_obligation(
    actual_type: str,
    action_id: str,
) -> None:
    sink = Atom(value="sink:arbitrary")
    invariant = _invariant(reached(Atom(value=action_id), sink))
    facts = ClassificationFacts.from_graph(
        QdlGraph(facts=(_fact("is", (sink, Atom(value=actual_type))),))
    )

    classification = DEFAULT_CATALOG.classify_finding(invariant, facts)
    deficit = classification_deficit(invariant, facts, action_id=action_id)

    assert classification.entry is None
    assert classification.deficit_reasons == ("missing_sink_type",)
    assert deficit is not None
    assert deficit.subgoal.args[0] == sink
    assert dict(deficit.context)["classification_reason"] == "missing_sink_type"
    assert set(dict(deficit.context)["allowed_values"].split(",")) == {
        kind
        for entry in DEFAULT_CATALOG.candidates_for(invariant)
        for kind in entry.sink_types
    }
    assert facts.sink_types_for("sink:arbitrary") == frozenset({actual_type})


@pytest.mark.parametrize(
    ("effect", "facts", "reason"),
    (
        (
            changed(Atom(value="resource:item"), Atom(value="value")),
            ClassificationFacts(
                input_roles=frozenset({("action:use", "value", "object_ref")})
            ),
            "missing_input_role",
        ),
        (
            has(
                Atom(value="principal:reader"),
                field(Atom(value="resource:item"), Atom(value="value")),
            ),
            ClassificationFacts(
                witness_roles=frozenset({("resource:item", "value", "object_ref")})
            ),
            "missing_witness_role",
        ),
    ),
)
def test_existing_role_does_not_mask_catalog_residual(effect, facts, reason) -> None:
    classification = DEFAULT_CATALOG.classify_finding(
        _invariant(effect), facts, action_id="action:use"
    )

    assert classification.entry is None
    assert classification.deficit_reasons == (reason,)


def test_allowed_role_residual_comes_from_exact_catalog_candidates() -> None:
    base = DEFAULT_CATALOG.get("bola")
    assert base is not None
    catalog = ClassCatalog((base,))
    invariant = _invariant(allowed(Atom(value="action:use")))
    facts = ClassificationFacts(
        input_roles=frozenset({("action:use", "value", "privileged")})
    )

    classification = catalog.classify_finding(invariant, facts)

    assert classification.entry is None
    assert classification.deficit_reasons == ("missing_input_role",)
    # The default catalog still has its unconstrained function-level fallback.
    assert DEFAULT_CATALOG.classify_finding(invariant, facts).deficit_reasons == ()


def test_no_fact_residual_is_invented_for_non_fact_catalog_constraints() -> None:
    base = DEFAULT_CATALOG.get("bola")
    assert base is not None
    catalog = ClassCatalog((base.model_copy(update={"input_roles": ()}),))
    invariant = _invariant(allowed(Atom(value="action:use")))

    classification = catalog.classify_finding(invariant)

    assert classification.entry is None
    assert classification.deficit_reasons == ("unsatisfied_catalog_constraints",)


def test_residual_uses_exact_candidates_without_assuming_a_sink_type() -> None:
    base = DEFAULT_CATALOG.get("injection")
    assert base is not None
    entry = base.model_copy(update={"sink_types": ("catalog_specific_type",)})
    catalog = ClassCatalog((entry,))
    invariant = _invariant(reached(Atom(value="action:use"), Atom(value="sink:x")))
    unsupported = ClassificationFacts(
        sink_types=frozenset({("sink:x", "interpreter"), ("sink:x", "Sink")})
    )

    classification = catalog.classify_finding(invariant, unsupported)
    assert classification.entry is None
    assert classification.deficit_reasons == ("missing_sink_type",)
    assert catalog.candidates_for(invariant) == (entry,)

    supported = ClassificationFacts(
        sink_types=unsupported.sink_types | {("sink:x", "catalog_specific_type")}
    )
    classification = catalog.classify_finding(invariant, supported)
    assert classification.entry == entry
    assert classification.deficit_reasons == ()
    assert classification.cwe == entry.cwe
    assert classification.owasp == (entry.owasp_api,)
    assert classification.stride == entry.stride


def test_every_causal_effect_receives_a_class_and_taxonomy() -> None:
    effects = (
        allowed(Atom(value="action:get")),
        changed(Atom(value="resource:user"), Atom(value="role")),
        completed(Atom(value="flow:checkout")),
        create(Atom(value="resource:invoice")),
        denied(Atom(value="action:get")),
        duration(Atom(value="action:get"), Atom(value=100)),
        external_call(Atom(value="action:fetch"), Atom(value="marker")),
        has(
            Atom(value="principal:attacker"),
            field(Atom(value="resource:cert"), Atom(value="private_key")),
        ),
        identity(
            Atom(value="principal:attacker"),
            Atom(value="principal:victim"),
        ),
        reached(Atom(value="action:render"), Atom(value="sink:renderer")),
        remove(Atom(value="resource:invoice")),
        transition(Atom(value="paid"), Atom(value="shipped")),
    )

    for effect in effects:
        classification = DEFAULT_CATALOG.classify_finding(
            _invariant(effect),
            facts=ClassificationFacts(),
        )

        assert classification.vulnerability_class
        assert classification.cwe
        assert classification.owasp
        assert classification.stride


def test_classify_without_norm_fact_returns_none() -> None:
    invariant = InvariantProjection(
        invariant_id="inv-1",
        norm_id="threat-1",
        statement="legacy-only norm",
        severity=Severity.HIGH,
    )
    entry = DEFAULT_CATALOG.classify(invariant)
    assert entry is None


def test_finding_is_labeled_with_class_and_cwe() -> None:
    effect = identity(
        Atom(value="principal:attacker"),
        Atom(value="principal:victim"),
    )
    invariant = _invariant(effect)
    check = _check(("svc-attacker",))

    classification = DEFAULT_CATALOG.classify_finding(
        invariant,
        action_id=f"action:{check.method_id}",
    )

    assert classification.vulnerability_class == "bola"
    assert "CWE-639" in classification.cwe
    assert classification.owasp == ("API1",)
    assert classification.stride == ("E",)


def test_changed_finding_is_labeled_from_qdl_role_fact() -> None:
    effect = changed(Atom(value="resource:api_key"), Atom(value="scope"))
    invariant = _invariant(effect)
    check = Check(
        invariant_id="inv-1",
        method_id="grpc:nsfy.shop.v1.KeyService.CreateApiKey",
        scenario_id="sc-1",
        request=(("scope", "admin"),),
        identities=("svc-attacker",),
    )
    facts = ClassificationFacts.from_graph(
        _input_role_graph(
            "action:grpc:nsfy.shop.v1.KeyService.CreateApiKey",
            "scope",
            "privileged",
        )
    )

    classification = DEFAULT_CATALOG.classify_finding(
        invariant,
        facts=facts,
        action_id=f"action:{check.method_id}",
    )

    assert classification.vulnerability_class == "mass_assignment"
    assert classification.cwe == ("CWE-915",)
    assert classification.owasp == ("API3",)
    assert classification.stride == ("T",)


def test_finding_without_norm_fact_is_a_classification_deficit() -> None:
    invariant = InvariantProjection(
        invariant_id="inv-1",
        norm_id="threat-1",
        statement="legacy-only norm",
        severity=Severity.HIGH,
    )
    check = _check(("svc-attacker",))

    classification = DEFAULT_CATALOG.classify_finding(
        invariant,
        action_id=f"action:{check.method_id}",
    )

    assert classification.vulnerability_class == "classification_deficit"
    assert classification.deficit_reasons == ("missing_norm_fact",)


def test_missing_norm_fact_projects_taxonomy_from_role_fact() -> None:
    invariant = InvariantProjection(
        invariant_id="inv-1",
        norm_id="threat-1",
        statement="legacy-only norm",
        severity=Severity.HIGH,
    )
    check = _check(("svc-attacker",))
    facts = ClassificationFacts.from_graph(
        _input_role_graph("action:get-cert", "resource_id", "object_ref")
    )

    classification = DEFAULT_CATALOG.classify_finding(
        invariant,
        facts=facts,
        action_id=f"action:{check.method_id}",
    )

    assert classification.vulnerability_class == "classification_deficit"
    assert classification.deficit_reasons == ("missing_norm_fact",)
    assert classification.cwe == ("CWE-639",)
    assert classification.owasp == ("A01",)
    assert classification.stride == ("E",)
