from __future__ import annotations

from itertools import product

import pytest

from cloud_dast.model import (
    AccessOutcome,
    ExecutionTrace,
    Observation,
    Severity,
    TraceStep,
    VerdictStatus,
)
from cloud_dast.model.events import CheckCompleted, CoverageUpdated, QdlStepEvaluated
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    canonical_json,
    changed,
    create,
    input_field,
    outcome,
    transition,
)
from cloud_dast.qdl.graph import (
    field as resource_field,
)
from cloud_dast.qdl.state_machine import state_machine_graph
from cloud_dast.runtime.planning import QdlPlanner
from cloud_dast.verification.contract_projection import (
    EXTENSION_PREDICATE_SCHEMAS,
)
from cloud_dast.verification.coverage import (
    CoverageMatrix,
    CoverageMatrixBuilder,
    FieldCoverageCell,
    StateMachineMismatchCoverage,
    TermFactors,
    _forbidden_state_cells,
    build_coverage_matrix,
    evaluate_term_coverage,
    evidence_target_fact,
)
from cloud_dast.verification.invariant_projection import InvariantProjection


def qfact(
    predicate: str,
    *args: Atom | Struct,
    context: Context = Context.CONTRACT,
) -> Fact:
    predicate_object = (
        Predicate.from_schema(
            next(
                schema
                for schema in EXTENSION_PREDICATE_SCHEMAS
                if schema.name == predicate
            )
        )
        if predicate == "refers_to"
        else Predicate.from_name(predicate)
    )
    return Fact(
        context=context,
        predicate=predicate_object,
        args=args,
    )


def test_coverage_matrix_is_field_effect_and_state_projection() -> None:
    field_cell = FieldCoverageCell(
        field_id='{"name":"input_field","args":[...]}',
        field_name="role",
        field_kind="input",
        semantic_role="privileged_attribute",
        primitive="differential",
        status="unresolved",
        deficit="evidence_blind",
    )
    matrix = CoverageMatrix(
        service="svc",
        fields=(field_cell,),
    )

    assert matrix.has_qdl_projection is True
    assert matrix.summary.total == 1
    assert matrix.summary.unresolved == 1
    assert matrix.summary.covered == 0
    assert matrix.deficit_counts["evidence_blind"] == 1


def test_field_roles_and_primitives_are_derived_views() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    role_field = input_field(action, Atom(value="role"))
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", role_field, Atom(value="InputField")),
            qfact("part", role_field, action),
            qfact("has", role_field, Atom(value="privileged_attribute")),
        )
    )

    matrix = build_coverage_matrix(graph)

    assert matrix.service == "service:orders"
    assert len(matrix.fields) == 1
    cell = matrix.fields[0]
    assert cell.field_name == "role"
    assert cell.field_kind == "input"
    assert cell.semantic_role == "privileged_attribute"
    assert cell.primitive == "differential"
    assert cell.status == "unresolved"
    assert cell.deficit == "evidence_blind"
    assert cell.action_ids == ("action:grpc:orders.Update",)
    assert cell.observation_ids == ()


def test_refers_to_derives_object_ref_role_without_capability() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Get")
    resource = Atom(value="resource:order")
    resource_id = input_field(action, Atom(value="resource_id"))
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", resource, Atom(value="ResourceType")),
            qfact("is", resource_id, Atom(value="InputField")),
            qfact("part", resource_id, action),
            qfact("refers_to", resource_id, resource),
        )
    )

    matrix = build_coverage_matrix(graph)

    cell = matrix.fields[0]
    assert cell.semantic_role == "object_ref"
    assert cell.primitive == "unknown"
    assert cell.status == "blind"
    assert cell.deficit == "capability_blind"
    assert cell.rationale == "no supports_primitive derivation exists"


def test_exposure_derives_response_field_capability() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Get")
    resource = Atom(value="resource:order")
    witness = resource_field(resource, Atom(value="email"))
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", resource, Atom(value="ResourceType")),
            qfact("is", witness, Atom(value="Field")),
            qfact("has", witness, Atom(value="sensitive")),
            qfact("exposes", action, witness),
        )
    )

    matrix = build_coverage_matrix(graph)

    cell = matrix.fields[0]
    assert cell.field_kind == "output"
    assert cell.semantic_role == "sensitive"
    assert cell.primitive == "response_field"
    assert cell.status == "unresolved"
    assert cell.deficit == "evidence_blind"


def test_one_field_term_keeps_output_and_resource_aspects_separate() -> None:
    service = Atom(value="service:orders")
    reader = Atom(value="action:grpc:orders.Get")
    writer = Atom(value="action:grpc:orders.Update")
    resource = Atom(value="resource:order")
    witness = resource_field(resource, Atom(value="email"))
    effect = changed(resource, Atom(value="email"))
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", reader, Atom(value="Action")),
            qfact("is", writer, Atom(value="Action")),
            qfact("is", resource, Atom(value="ResourceType")),
            qfact("is", witness, Atom(value="Field")),
            qfact("has", witness, Atom(value="sensitive")),
            qfact("exposes", reader, witness),
            qfact("causes", writer, effect),
        )
    )

    matrix = build_coverage_matrix(graph)

    output_cell = next(
        cell
        for cell in matrix.fields
        if cell.field_kind == "output" and cell.primitive == "response_field"
    )
    assert output_cell.semantic_role == "sensitive"
    assert output_cell.primitive == "response_field"
    assert "action:grpc:orders.Get" in output_cell.action_ids
    resource_cell = next(
        cell
        for cell in matrix.fields
        if cell.field_kind == "resource" and cell.primitive == "marker"
    )
    assert resource_cell.semantic_role == "state_transition"
    assert resource_cell.primitive == "marker"
    assert "action:grpc:orders.Update" in resource_cell.action_ids


def test_field_without_semantic_fact_is_semantic_blind() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Get")
    resource_id = input_field(action, Atom(value="resource_id"))
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", resource_id, Atom(value="InputField")),
            qfact("part", resource_id, action),
        )
    )

    matrix = build_coverage_matrix(graph)

    assert len(matrix.blind_spots) == 1
    cell = matrix.blind_spots[0]
    assert cell.semantic_role == "unclassified"
    assert cell.primitive == "unknown"
    assert cell.status == "blind"
    assert cell.deficit == "semantic_blind"
    assert cell.norm_ids == ()
    assert cell.observation_ids == ()
    assert matrix.deficit_counts["semantic_blind"] == 1


def test_changed_effect_derives_resource_field_and_effect_cells() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    resource = Atom(value="resource:order")
    status_field = Atom(value="status")
    effect = changed(resource, status_field)
    norm = Atom(value="norm:immutable-status")
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", resource, Atom(value="ResourceType")),
            qfact("is", norm, Atom(value="Norm"), context=Context.ACCEPTED),
            qfact("causes", action, effect),
            qfact("prevents", norm, effect, context=Context.ACCEPTED),
        )
    )

    matrix = build_coverage_matrix(graph)

    field_cell = next(cell for cell in matrix.fields if cell.field_kind == "resource")
    assert field_cell.semantic_role == "state_transition"
    assert field_cell.primitive == "marker"
    assert field_cell.norm_ids == ("norm:immutable-status",)
    assert field_cell.deficit == "setup_blind"

    effect_cell = matrix.effects[0]
    assert effect_cell.effect_kind == "changed"
    assert effect_cell.primitive == "marker"
    assert effect_cell.norm_ids == ("norm:immutable-status",)
    assert effect_cell.deficit == "setup_blind"


def test_refers_to_fixture_closes_setup_deficit() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    resource = Atom(value="resource:order")
    status_field = Atom(value="status")
    effect = changed(resource, status_field)
    norm = Atom(value="norm:immutable-status")
    target = input_field(action, Atom(value="order_id"))
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", resource, Atom(value="ResourceType")),
            qfact("is", norm, Atom(value="Norm"), context=Context.ACCEPTED),
            qfact("is", target, Atom(value="InputField")),
            qfact("causes", action, effect),
            qfact("prevents", norm, effect, context=Context.ACCEPTED),
            qfact("refers_to", target, resource),
        )
    )

    matrix = build_coverage_matrix(graph)

    field_cell = next(cell for cell in matrix.fields if cell.field_kind == "resource")
    assert field_cell.deficit == "evidence_blind"
    assert field_cell.status == "unresolved"
    effect_cell = matrix.effects[0]
    assert effect_cell.deficit == "evidence_blind"


def test_create_provider_fixture_closes_setup_deficit() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    setup_action = Atom(value="action:grpc:orders.Create")
    resource = Atom(value="resource:order")
    status_field = Atom(value="status")
    effect = changed(resource, status_field)
    norm = Atom(value="norm:immutable-status")
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", setup_action, Atom(value="Action")),
            qfact("is", resource, Atom(value="ResourceType")),
            qfact("is", norm, Atom(value="Norm"), context=Context.ACCEPTED),
            qfact("causes", action, effect),
            qfact("causes", setup_action, create(resource)),
            qfact("prevents", norm, effect, context=Context.ACCEPTED),
        )
    )

    matrix = build_coverage_matrix(graph)

    effect_cell = next(cell for cell in matrix.effects if cell.effect_kind == "changed")
    assert effect_cell.deficit == "evidence_blind"
    create_cell = next(cell for cell in matrix.effects if cell.effect_kind == "create")
    assert create_cell.primitive == "unknown"
    assert create_cell.deficit == "oracle_blind"
    assert create_cell.status == "blind"


def test_runtime_observation_covers_field_and_effect() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    resource = Atom(value="resource:order")
    status_field = Atom(value="status")
    effect = changed(resource, status_field)
    norm = Atom(value="norm:immutable-status")
    target = input_field(action, Atom(value="order_id"))
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", resource, Atom(value="ResourceType")),
            qfact("is", norm, Atom(value="Norm"), context=Context.ACCEPTED),
            qfact("is", target, Atom(value="InputField")),
            qfact("causes", action, effect),
            qfact("prevents", norm, effect, context=Context.ACCEPTED),
            qfact("refers_to", target, resource),
        )
    )
    invariant = InvariantProjection(
        invariant_id="invariant:immutable-status",
        norm_id="norm:immutable-status",
        statement="Order status must be immutable",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(norm, effect),
        ),
    )
    observation = Observation(
        check_id="check:runtime",
        scenario_id="scenario:runtime",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
    )
    # Execution alone is not an oracle witness. The production runner emits
    # this event only after deterministic, grounded oracle evaluation.
    events = (
        QdlStepEvaluated(
            path_id="path:runtime",
            step_id="step:runtime",
            verdict=VerdictStatus.FAIL,
            phase="goal_reached",
            reason="grounded forbidden effect observed",
            norm_fact=invariant.norm_fact,
            step_index=0,
            action_id="grpc:orders.Update",
            check_id=observation.check_id,
            observation_id=observation.observation_id,
        ),
        CheckCompleted(
            observation=observation,
            correlation_id=observation.check_id,
        ),
        CoverageUpdated(
            check_id=observation.check_id,
            method_id="grpc:orders.Update",
            invariant_id=invariant.invariant_id,
            scenario_id=observation.scenario_id,
            correlation_id=observation.check_id,
        ),
    )

    matrix = build_coverage_matrix(
        graph,
        invariants={invariant.invariant_id: invariant},
        events=events,
    )

    field_cell = next(cell for cell in matrix.fields if cell.field_kind == "resource")
    assert field_cell.status == "covered"
    assert field_cell.deficit is None
    assert field_cell.observation_ids == (observation.observation_id,)
    effect_cell = next(cell for cell in matrix.effects if cell.effect_kind == "changed")
    assert effect_cell.status == "covered"
    assert effect_cell.observation_ids == (observation.observation_id,)


def test_runtime_evidence_creates_effect_cell_without_causes_fact() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Get")
    resource = Atom(value="resource:order")
    witness = resource_field(resource, Atom(value="email"))
    norm = Atom(value="norm:sensitive-exposure")
    has_effect = Struct(
        name="has",
        args=(Atom(value="principal:attacker"), witness),
    )
    invariant = InvariantProjection(
        invariant_id="invariant:sensitive-exposure",
        norm_id="norm:sensitive-exposure",
        statement="email must not leak",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(norm, has_effect),
        ),
    )
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", resource, Atom(value="ResourceType")),
            qfact("is", witness, Atom(value="Field")),
            qfact("exposes", action, witness),
        )
    )
    observation = Observation(
        check_id="check:runtime",
        scenario_id="scenario:runtime",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
    )
    # Execution alone is not an oracle witness. The production runner emits
    # this event only after deterministic, grounded oracle evaluation.
    events = (
        QdlStepEvaluated(
            path_id="path:runtime",
            step_id="step:runtime",
            verdict=VerdictStatus.FAIL,
            phase="goal_reached",
            reason="grounded forbidden effect observed",
            norm_fact=invariant.norm_fact,
            step_index=0,
            action_id="grpc:orders.Get",
            check_id=observation.check_id,
            observation_id=observation.observation_id,
        ),
        CheckCompleted(
            observation=observation,
            correlation_id=observation.check_id,
        ),
        CoverageUpdated(
            check_id=observation.check_id,
            method_id="grpc:orders.Get",
            invariant_id=invariant.invariant_id,
            scenario_id=observation.scenario_id,
            correlation_id=observation.check_id,
        ),
    )

    matrix = build_coverage_matrix(
        graph,
        invariants={invariant.invariant_id: invariant},
        events=events,
    )

    runtime_cell = next(cell for cell in matrix.effects if cell.effect_kind == "has")
    assert runtime_cell.status == "covered"
    assert runtime_cell.deficit is None
    assert runtime_cell.observation_ids == (observation.observation_id,)
    assert runtime_cell.norm_ids == ("norm:sensitive-exposure",)


def test_evidence_target_requires_runtime_observation_fact() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    role_field = input_field(action, Atom(value="role"))
    observation = Atom(value="observation:missing-observes")
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", role_field, Atom(value="InputField")),
            qfact(
                "is", observation, Atom(value="Observation"), context=Context.RUNTIME
            ),
            qfact("part", role_field, action),
            qfact("has", role_field, Atom(value="privileged_attribute")),
            evidence_target_fact(
                observation,
                action,
                role_field,
                "privileged_attribute",
                "differential",
            ),
        )
    )

    matrix = build_coverage_matrix(graph)

    cell = matrix.fields[0]
    assert cell.status == "unresolved"
    assert cell.deficit == "evidence_blind"
    assert cell.observation_ids == ()


def test_evidence_target_fact_binds_runtime_observation() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    role_field = input_field(action, Atom(value="role"))
    observation = Atom(value="observation:obs-1")
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", role_field, Atom(value="InputField")),
            qfact(
                "is", observation, Atom(value="Observation"), context=Context.RUNTIME
            ),
            qfact("part", role_field, action),
            qfact("has", role_field, Atom(value="privileged_attribute")),
            qfact(
                "evidence",
                observation,
                outcome(action, Atom(value="allowed")),
                context=Context.RUNTIME,
            ),
            evidence_target_fact(
                observation,
                action,
                role_field,
                "privileged_attribute",
                "differential",
            ),
        )
    )

    matrix = build_coverage_matrix(graph)

    cell = matrix.fields[0]
    assert cell.status == "covered"
    assert cell.deficit is None
    assert cell.observation_ids == ("observation:obs-1",)


def test_request_field_execution_is_coverage_evidence() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    role_field = input_field(action, Atom(value="role"))
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", role_field, Atom(value="InputField")),
            qfact("part", role_field, action),
            qfact("has", role_field, Atom(value="privileged_attribute")),
        )
    )
    observation = Observation(
        observation_id="observation:request",
        check_id="check:request",
        scenario_id="scenario:request",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id="observation:request",
                    step_id="step:request",
                    method_id="grpc:orders.Update",
                    scenario_id="scenario:request",
                    status=AccessOutcome.ALLOWED,
                    request_fields=("role",),
                ),
            )
        ),
    )

    matrix = build_coverage_matrix(
        graph,
        events=(
            CheckCompleted(
                observation=observation,
                correlation_id=observation.check_id,
            ),
        ),
    )

    cell = matrix.fields[0]
    assert cell.request_executed is True
    assert cell.request_execution_ids == ("observation:request",)
    assert cell.request_deficit is False
    assert cell.oracle_witness_observed is False
    assert cell.observation_ids == ()


def test_declared_field_without_part_still_gets_request_deficit() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    role_field = input_field(action, Atom(value="role"))
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", role_field, Atom(value="InputField")),
        )
    )

    matrix = build_coverage_matrix(graph)

    assert len(matrix.fields) == 1
    cell = matrix.fields[0]
    assert cell.field_name == "role"
    assert cell.action_ids == ("action:grpc:orders.Update",)
    assert cell.request_executed is False
    assert cell.request_deficit is True
    assert matrix.request_deficit_count == 1


def test_request_deficit_is_independent_of_oracle_status() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    role_field = input_field(action, Atom(value="role"))
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", role_field, Atom(value="InputField")),
            qfact("part", role_field, action),
            qfact("has", role_field, Atom(value="privileged_attribute")),
        )
    )
    observation = Observation(
        observation_id="observation:request",
        check_id="check:request",
        scenario_id="scenario:request",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id="observation:request",
                    step_id="step:request",
                    method_id="grpc:orders.Update",
                    scenario_id="scenario:request",
                    status=AccessOutcome.ALLOWED,
                    request_fields=("role",),
                ),
            )
        ),
    )

    matrix = build_coverage_matrix(
        graph,
        events=(
            CheckCompleted(
                observation=observation,
                correlation_id=observation.check_id,
            ),
        ),
    )

    cell = matrix.fields[0]
    assert cell.request_executed is True
    assert cell.request_deficit is False
    assert cell.oracle_witness_observed is False
    assert cell.status == "unresolved"
    assert cell.deficit == "evidence_blind"


def test_oracle_witness_and_request_execution_are_distinct() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    role_field = input_field(action, Atom(value="role"))
    email_field = input_field(action, Atom(value="email"))
    oracle_observation = Atom(value="observation:oracle")
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", role_field, Atom(value="InputField")),
            qfact("is", email_field, Atom(value="InputField")),
            qfact(
                "is",
                oracle_observation,
                Atom(value="Observation"),
                context=Context.RUNTIME,
            ),
            qfact("part", role_field, action),
            qfact("part", email_field, action),
            qfact("has", role_field, Atom(value="privileged_attribute")),
            qfact("has", email_field, Atom(value="sensitive")),
            qfact(
                "evidence",
                oracle_observation,
                outcome(action, Atom(value="allowed")),
                context=Context.RUNTIME,
            ),
            evidence_target_fact(
                oracle_observation,
                action,
                role_field,
                "privileged_attribute",
                "differential",
            ),
        )
    )
    request_observation = Observation(
        observation_id="observation:request",
        check_id="check:request",
        scenario_id="scenario:request",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id="observation:request",
                    step_id="step:request",
                    method_id="grpc:orders.Update",
                    scenario_id="scenario:request",
                    status=AccessOutcome.ALLOWED,
                    request_fields=("email",),
                ),
            )
        ),
    )

    matrix = build_coverage_matrix(
        graph,
        events=(
            CheckCompleted(
                observation=Observation(
                    observation_id="observation:oracle",
                    check_id="check:oracle",
                    scenario_id="scenario:oracle",
                    observed_outcome=AccessOutcome.ALLOWED,
                    response_summary="allowed",
                ),
                correlation_id="check:oracle",
            ),
            CheckCompleted(
                observation=request_observation,
                correlation_id=request_observation.check_id,
            ),
        ),
    )

    role_cell = next(cell for cell in matrix.fields if cell.field_name == "role")
    email_cell = next(cell for cell in matrix.fields if cell.field_name == "email")
    assert role_cell.oracle_witness_observed is True
    assert role_cell.request_executed is False
    assert email_cell.oracle_witness_observed is False
    assert email_cell.request_executed is True


def test_field_without_oracle_witness_is_unresolved_not_blind() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    email_field = input_field(action, Atom(value="email"))
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", email_field, Atom(value="InputField")),
            qfact("part", email_field, action),
            qfact("has", email_field, Atom(value="sensitive")),
        )
    )
    observation = Observation(
        observation_id="observation:request",
        check_id="check:request",
        scenario_id="scenario:request",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id="observation:request",
                    step_id="step:request",
                    method_id="grpc:orders.Update",
                    scenario_id="scenario:request",
                    status=AccessOutcome.ALLOWED,
                    request_fields=("email",),
                ),
            )
        ),
    )

    matrix = build_coverage_matrix(
        graph,
        events=(
            CheckCompleted(
                observation=observation,
                correlation_id=observation.check_id,
            ),
        ),
    )

    cell = matrix.fields[0]
    assert cell.status == "unresolved"
    assert cell.request_executed is True
    assert cell.oracle_witness_observed is False


def test_state_machine_projection_reports_states_not_actions() -> None:
    state_machine = state_machine_graph(
        states=("created", "approved", "shipped"),
        actions=("approve", "ship"),
        initial_states=("created",),
        transitions=(("approve", "created", "approved"),),
        observed_transitions=(("ship", "created", "shipped"),),
    )

    matrix = build_coverage_matrix(state_machine)

    coverage = matrix.state_machine
    assert coverage is not None
    assert coverage.mismatches == (
        StateMachineMismatchCoverage(
            action_id="ship",
            from_state="created",
            to_state="shipped",
        ),
    )
    assert not hasattr(coverage, "actions")
    created = next(item for item in coverage.states if item.state_id == "created")
    assert created.status == "covered"
    assert created.deficit is None
    approved = next(item for item in coverage.states if item.state_id == "approved")
    assert approved.status == "unresolved"
    assert approved.deficit == "evidence_blind"


def test_unreachable_state_is_setup_blind() -> None:
    graph = state_machine_graph(
        states=("draft", "published", "archived"),
        actions=("publish",),
        initial_states=("draft",),
        transitions=(("publish", "draft", "published"),),
    )

    matrix = build_coverage_matrix(graph)

    coverage = matrix.state_machine
    assert coverage is not None
    archived = next(item for item in coverage.states if item.state_id == "archived")
    assert archived.reachable is False
    assert archived.status == "blind"
    assert archived.deficit == "setup_blind"


def test_forbidden_state_deficits_are_typed() -> None:
    graph = state_machine_graph(
        states=("draft", "published"),
        actions=("publish",),
        norms=("no_published",),
        initial_states=("draft",),
        transitions=(("publish", "draft", "published"),),
        forbidden_states=(("no_published", "published"),),
        observed_transitions=(("publish", "draft", "published"),),
    )

    matrix = build_coverage_matrix(graph)

    coverage = matrix.state_machine
    assert coverage is not None
    forbidden = coverage.forbidden_states[0]
    assert forbidden.norm_id == "no_published"
    assert forbidden.state_id == "published"
    assert forbidden.reachable is True
    assert forbidden.witness_initial_state == "draft"
    assert forbidden.witness_actions == ("publish",)
    assert forbidden.status == "unresolved"
    assert forbidden.deficit == "evidence_blind"

    forbidden_without_initial = build_coverage_matrix(
        state_machine_graph(
            states=("draft", "published"),
            actions=("publish",),
            norms=("no_published",),
            transitions=(("publish", "draft", "published"),),
            forbidden_states=(("no_published", "published"),),
        )
    )
    no_initial = forbidden_without_initial.state_machine
    assert no_initial is not None
    assert no_initial.forbidden_states[0].deficit == "setup_blind"


def _planned_graph() -> QdlGraph:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    role_field = input_field(action, Atom(value="role"))
    transition_norm = Atom(value="norm:no-unapproved")
    transition_effect = transition(
        Atom(value="draft"),
        Atom(value="published"),
    )
    contract_facts = (
        qfact("is", service, Atom(value="Service")),
        qfact("is", role_field, Atom(value="InputField")),
        qfact("part", role_field, action),
        qfact("has", role_field, Atom(value="privileged_attribute")),
        qfact("is", transition_norm, Atom(value="Norm"), context=Context.ACCEPTED),
        qfact(
            "prevents",
            transition_norm,
            transition_effect,
            context=Context.ACCEPTED,
        ),
    )
    state_machine = state_machine_graph(
        states=("draft", "published"),
        actions=("action:grpc:orders.Update",),
        norms=("no_published",),
        initial_states=("draft",),
        transitions=(("action:grpc:orders.Update", "draft", "published"),),
        forbidden_states=(("no_published", "published"),),
    )
    return QdlGraph(facts=(*contract_facts, *state_machine.facts))


def test_build_plan_attaches_planned_paths_to_qdl_coverage() -> None:
    graph = _planned_graph()
    plan = QdlPlanner().plan(graph)

    matrix = CoverageMatrixBuilder().build_plan(plan, graph)

    assert matrix.source == "qdl"
    assert matrix.plan_hash == plan.graph_hash == graph.content_hash
    field_cell = matrix.fields[0]
    assert field_cell.status == "unresolved"
    assert field_cell.deficit == "evidence_blind"
    assert field_cell.plan_path_ids
    state_machine = matrix.state_machine
    assert state_machine is not None
    sm_transition = state_machine.transitions[0]
    assert sm_transition.norm_ids == ("norm:no-unapproved",)
    assert sm_transition.plan_path_ids == field_cell.plan_path_ids


def test_build_plan_rejects_graph_hash_mismatch() -> None:
    graph = _planned_graph()
    plan = QdlPlanner().plan(graph)

    with pytest.raises(ValueError, match="plan does not match the graph"):
        CoverageMatrixBuilder().build_plan(plan, QdlGraph(facts=()))


def test_build_rejects_bare_qdl_plan_without_graph() -> None:
    plan = QdlPlanner().plan(_planned_graph())

    with pytest.raises(TypeError, match="coverage source must be a QdlGraph"):
        build_coverage_matrix(plan)


# --- S24R: term coverage algebra -------------------------------------------


def test_coverage_is_the_product_of_every_factor() -> None:
    """coverage(term) = semantic × setup × channel × primitive × runtime."""

    leaf_values = (False, True)
    for semantic, setup, channel, primitive, runtime in product(leaf_values, repeat=5):
        factors = TermFactors(
            semantic=semantic,
            setup=setup,
            oracle_channel=channel,
            oracle_primitive=primitive,
            runtime=runtime,
        )
        assert factors.oracle == (channel and primitive)
        assert factors.covered == (
            semantic and setup and channel and primitive and runtime
        )


@pytest.mark.parametrize(
    ("leaf", "status", "deficit", "factor"),
    (
        ("semantic", "blind", "semantic_blind", "semantic"),
        ("setup", "blind", "setup_blind", "setup"),
        ("oracle_channel", "blind", "capability_blind", "oracle"),
        ("oracle_primitive", "blind", "oracle_blind", "oracle"),
        ("runtime", "unresolved", "evidence_blind", "runtime"),
    ),
)
def test_deficit_is_typed_by_the_missing_leaf(
    leaf: str,
    status: str,
    deficit: str,
    factor: str,
) -> None:
    values = {
        "semantic": True,
        "setup": True,
        "oracle_channel": True,
        "oracle_primitive": True,
        "runtime": True,
    }
    values[leaf] = False
    evaluation = evaluate_term_coverage(TermFactors(**values))

    assert evaluation.status == status
    assert evaluation.deficit == deficit
    assert evaluation.missing_factor == factor


@pytest.mark.parametrize(
    ("missing_leaves", "deficit", "factor"),
    (
        (("semantic", "setup", "runtime"), "semantic_blind", "semantic"),
        (("setup", "oracle_channel", "runtime"), "setup_blind", "setup"),
        (("oracle_channel", "oracle_primitive"), "capability_blind", "oracle"),
        (("oracle_primitive", "runtime"), "oracle_blind", "oracle"),
    ),
)
def test_first_missing_leaf_wins_the_canonical_order(
    missing_leaves: tuple[str, ...],
    deficit: str,
    factor: str,
) -> None:
    """The deficit follows semantic ≺ setup ≺ channel ≺ primitive ≺ runtime."""

    values = {
        "semantic": True,
        "setup": True,
        "oracle_channel": True,
        "oracle_primitive": True,
        "runtime": True,
    }
    for leaf in missing_leaves:
        values[leaf] = False
    evaluation = evaluate_term_coverage(TermFactors(**values))

    assert evaluation.deficit == deficit
    assert evaluation.missing_factor == factor


def test_counter_evidence_units_carry_no_deficit() -> None:
    evaluation = evaluate_term_coverage(
        TermFactors(
            semantic=True,
            setup=True,
            oracle_channel=True,
            oracle_primitive=True,
            runtime=True,
            required=False,
        )
    )

    assert evaluation.status == "unresolved"
    assert evaluation.deficit is None
    assert evaluation.missing_factor is None


def test_coverage_matrix_projects_generic_terms() -> None:
    graph = _planned_graph()
    matrix = build_coverage_matrix(graph)

    terms = matrix.terms
    kinds = {cell.term_kind for cell in terms}
    assert kinds == {"field", "state", "transition", "forbidden_state"}

    role_field = input_field(
        Atom(value="action:grpc:orders.Update"),
        Atom(value="role"),
    )
    assert any(
        cell.term_id == canonical_json(role_field)
        for cell in terms
        if cell.term_kind == "field"
    )
    assert any(
        cell.term_id == canonical_json(Atom(value="draft"))
        for cell in terms
        if cell.term_kind == "state"
    )
    assert any(
        cell.term_id
        == canonical_json(transition(Atom(value="draft"), Atom(value="published")))
        for cell in terms
        if cell.term_kind == "transition"
    )
    assert any(
        cell.term_id == canonical_json(Atom(value="published"))
        for cell in terms
        if cell.term_kind == "forbidden_state"
    )

    assert all(cell.factors is not None for cell in terms)
    assert all(
        cell.missing_factor == "runtime"
        for cell in terms
        if cell.deficit == "evidence_blind"
    )
    assert matrix.missing_factor_counts == {
        "semantic": 0,
        "setup": 0,
        "oracle": 0,
        "runtime": 5,
    }


def test_field_cells_carry_their_factor_state() -> None:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Get")
    resource = Atom(value="resource:order")
    resource_id = input_field(action, Atom(value="resource_id"))
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", resource, Atom(value="ResourceType")),
            qfact("is", resource_id, Atom(value="InputField")),
            qfact("part", resource_id, action),
            qfact("refers_to", resource_id, resource),
        )
    )

    matrix = build_coverage_matrix(graph)

    cell = matrix.fields[0]
    assert cell.factors is not None
    assert cell.factors.semantic is True
    assert cell.factors.setup is True
    assert cell.factors.oracle_channel is False
    assert cell.factors.oracle_primitive is False
    assert cell.factors.runtime is False
    assert cell.missing_factor == "oracle"
    assert cell.deficit == "capability_blind"


def test_runtime_evidence_does_not_mask_semantic_deficit() -> None:
    """A witnessed term without a derivable role is semantic-blind (S24R)."""

    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    mystery_field = input_field(action, Atom(value="mystery"))
    observation = Atom(value="observation:obs-1")
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", mystery_field, Atom(value="InputField")),
            qfact(
                "is", observation, Atom(value="Observation"), context=Context.RUNTIME
            ),
            qfact("part", mystery_field, action),
            qfact(
                "evidence",
                observation,
                outcome(action, Atom(value="allowed")),
                context=Context.RUNTIME,
            ),
            evidence_target_fact(
                observation,
                action,
                mystery_field,
                "unclassified",
                "differential",
            ),
        )
    )

    matrix = build_coverage_matrix(graph)

    cell = matrix.fields[0]
    assert cell.observation_ids == ("observation:obs-1",)
    assert cell.status == "blind"
    assert cell.deficit == "semantic_blind"
    assert cell.missing_factor == "semantic"
    assert cell.factors is not None
    assert cell.factors.semantic is False
    assert cell.factors.runtime is True


def test_observed_effect_without_oracle_primitive_is_oracle_blind() -> None:
    """Runtime provenance cannot substitute a deterministic oracle primitive."""

    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Create")
    resource = Atom(value="resource:order")
    observation = Atom(value="observation:obs-1")
    effect = create(resource)
    graph = QdlGraph(
        facts=(
            qfact("is", service, Atom(value="Service")),
            qfact("is", action, Atom(value="Action")),
            qfact("is", resource, Atom(value="ResourceType")),
            qfact(
                "is", observation, Atom(value="Observation"), context=Context.RUNTIME
            ),
            qfact("causes", action, effect),
            qfact(
                "evidence",
                observation,
                effect,
                context=Context.RUNTIME,
            ),
        )
    )

    matrix = build_coverage_matrix(graph)

    cell = matrix.effects[0]
    assert cell.effect_kind == "create"
    assert cell.primitive == "unknown"
    assert cell.observation_ids == ("observation:obs-1",)
    assert cell.status == "blind"
    assert cell.deficit == "oracle_blind"
    assert cell.missing_factor == "oracle"
    assert cell.factors is not None
    assert cell.factors.oracle_primitive is False
    assert cell.factors.runtime is True


def test_forbidden_state_absence_proof_depends_on_solver_completeness() -> None:
    forbidden = {("norm:no-archived", "archived")}
    initial_states = {"draft"}
    reachable_states = ("draft", "published")

    proven = _forbidden_state_cells(
        forbidden,
        initial_states,
        reachable_states,
        {},
        solution_complete=True,
    )
    assert proven[0].status == "covered"
    assert proven[0].deficit is None
    assert proven[0].missing_factor is None
    assert (
        proven[0].rationale
        == "state is unreachable in the complete solution; the ban is proven"
    )

    bounded = _forbidden_state_cells(
        forbidden,
        initial_states,
        reachable_states,
        {},
        solution_complete=False,
    )
    assert bounded[0].status == "blind"
    assert bounded[0].deficit == "oracle_blind"
    assert bounded[0].missing_factor == "oracle"
    assert bounded[0].factors is not None
    assert bounded[0].factors.oracle_primitive is False


def test_proven_unreachable_forbidden_state_is_covered() -> None:
    graph = state_machine_graph(
        states=("draft", "published", "archived"),
        actions=("publish",),
        norms=("no_archived",),
        initial_states=("draft",),
        transitions=(("publish", "draft", "published"),),
        forbidden_states=(("no_archived", "archived"),),
    )

    matrix = build_coverage_matrix(graph)

    coverage = matrix.state_machine
    assert coverage is not None
    forbidden = coverage.forbidden_states[0]
    assert forbidden.reachable is False
    assert forbidden.status == "covered"
    assert forbidden.deficit is None


def test_observed_unspecified_transition_is_counter_evidence() -> None:
    graph = state_machine_graph(
        states=("created", "shipped"),
        actions=("ship",),
        initial_states=("created",),
        observed_transitions=(("ship", "created", "shipped"),),
    )

    matrix = build_coverage_matrix(graph)

    coverage = matrix.state_machine
    assert coverage is not None
    transition = coverage.transitions[0]
    assert transition.in_specification is False
    assert transition.observed is True
    assert transition.status == "unresolved"
    assert transition.deficit is None
    assert transition.missing_factor is None
    assert transition.factors is not None
    assert transition.factors.required is False

    term = next(cell for cell in matrix.terms if cell.term_kind == "transition")
    assert term.deficit is None
    assert term.missing_factor is None
