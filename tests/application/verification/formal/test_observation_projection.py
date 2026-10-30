from __future__ import annotations

import pytest

from cloud_dast.infrastructure.runtime import MemoryEvidenceChannel
from cloud_dast.model import (
    AccessOutcome,
    ExecutionTrace,
    GrpcStatus,
    HttpStatus,
    Observation,
    ResponseData,
    TraceStep,
)
from cloud_dast.ports import EvidenceEvent
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.qdl.state_machine import (
    StateMachineEngine,
    state_machine_graph,
)
from cloud_dast.verification.projection import (
    ObservationProjector,
)


def make_observation() -> Observation:
    return Observation(
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.UNKNOWN,
        response_summary="gRPC status: INVALID_ARGUMENT",
        transport_status=GrpcStatus(code="INVALID_ARGUMENT"),
        duration_ms=12.5,
    )


def make_state_observation(
    observation_id: str,
    state_before: str,
    state_after: str,
) -> Observation:
    return Observation(
        observation_id=observation_id,
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary=state_after,
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id=observation_id,
                    step_id="step-1",
                    method_id="orders.Close",
                    scenario_id="scenario-1",
                    status=AccessOutcome.ALLOWED,
                    resource_state_before=(("state", state_before),),
                    resource_state_after=(("state", state_after),),
                ),
            )
        ),
    )


def _named(graph, name: str) -> list[Fact]:
    return [fact for fact in graph.facts if fact.predicate.name == name]


def test_projector_emits_runtime_aggregates() -> None:
    graph = ObservationProjector().project(make_observation(), "grpc:service.Get")

    assert graph.content_hash
    assert any(
        fact.args[1].value == "gRPC status: INVALID_ARGUMENT"
        for fact in _named(graph, "observed_response_status")
    )
    assert any(
        fact.args[1].value == "unknown" for fact in _named(graph, "observed_outcome")
    )
    assert any(
        fact.args[1].value == 12.5 and fact.args[1].literal_type == "float"
        for fact in _named(graph, "observed_duration")
    )


def test_projector_emits_http_json_aggregates_without_protobuf() -> None:
    observation = Observation(
        check_id="check-http",
        scenario_id="scenario-http",
        observed_outcome=AccessOutcome.DENIED,
        response_summary="HTTP 403 Forbidden",
        transport_status=HttpStatus(code=403),
        output=ResponseData(fields=(("order.id", 42),)),
        response_tree=(
            ("http.status_code", 403),
            ("order.id", 42),
        ),
    )

    graph = ObservationProjector().project(observation, "http:orders.get")

    summaries = {
        fact.args[1].value for fact in _named(graph, "observed_response_status")
    }
    assert summaries == {"HTTP 403 Forbidden", "http:403"}
    assert any(
        fact.args[1].value == "denied" for fact in _named(graph, "observed_outcome")
    )
    field_names = {fact.args[1].value for fact in _named(graph, "observed_field")}
    assert field_names == {"http.status_code", "order.id"}


def test_projector_is_deterministic() -> None:
    projector = ObservationProjector()
    observation = make_observation()
    first = projector.project(observation, "grpc:service.Get")
    second = projector.project(observation, "grpc:service.Get")

    assert first == second
    assert first.content_hash == second.content_hash


def test_projector_does_not_invent_security_semantics() -> None:
    graph = ObservationProjector().project(make_observation(), "grpc:service.Get")

    assert all(fact.context.value == "runtime" for fact in graph.facts)
    assert not any(fact.predicate.name == "prevents" for fact in graph.facts)
    assert not any(fact.predicate.name == "causes" for fact in graph.facts)


def test_projector_emits_output_field_names_without_values() -> None:
    observation = make_observation().model_copy(
        update={
            "output": ResponseData(
                fields=(
                    ("id", "secret-value"),
                    ("items", ("one", "two")),
                )
            ),
        }
    )

    graph = ObservationProjector().project(observation, "orders.Get")

    field_names = {fact.args[1].value for fact in _named(graph, "observed_field")}
    assert field_names == {"id", "items"}
    assert "secret-value" not in graph.model_dump_json()


def test_projector_emits_error_reason_aggregate() -> None:
    observation = make_observation().model_copy(
        update={"error_reason": "export denied: secret is missing"}
    )

    graph = ObservationProjector().project(observation, "orders.Export")

    assert any(
        fact.args[1].value == "export denied: secret is missing"
        for fact in _named(graph, "observed_error")
    )


def test_projector_emits_field_names_without_duplicates() -> None:
    observation = make_observation().model_copy(
        update={
            "output": ResponseData(
                fields=(("id", "secret-value"),),
                field_names=("id", "nested.leaf"),
            ),
        }
    )

    graph = ObservationProjector().project(observation, "orders.Get")

    field_names = [fact.args[1].value for fact in _named(graph, "observed_field")]
    assert field_names == ["id", "nested.leaf"]
    assert "secret-value" not in graph.model_dump_json()


def test_projector_emits_response_tree_paths_without_values() -> None:
    observation = make_observation().model_copy(
        update={
            "response_tree": (
                ("debug.trace_id", "trace-1"),
                ("items.0.name", "widget"),
                ("__truncated__", True),
            ),
        }
    )

    graph = ObservationProjector().project(observation, "orders.Get")

    field_names = {fact.args[1].value for fact in _named(graph, "observed_field")}
    assert field_names == {"debug.trace_id", "items.0.name"}
    assert "trace-1" not in graph.model_dump_json()
    assert "widget" not in graph.model_dump_json()


def test_projector_uses_trace_response_when_output_is_absent() -> None:
    observation = Observation(
        observation_id="obs-trace",
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id="obs-trace",
                    step_id="step-1",
                    method_id="orders.Get",
                    scenario_id="scenario-1",
                    status=AccessOutcome.ALLOWED,
                    response=ResponseData(fields=(("id", "secret-value"),)),
                ),
            )
        ),
    )

    graph = ObservationProjector().project(observation, "orders.Get")

    field_names = {fact.args[1].value for fact in _named(graph, "observed_field")}
    assert "id" in field_names
    assert "secret-value" not in graph.model_dump_json()


def test_projector_emits_trace_evidence_channels_or_not_available() -> None:
    observation = Observation(
        observation_id="obs-trace",
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id="obs-trace",
                    step_id="step-1",
                    method_id="orders.Create",
                    scenario_id="scenario-1",
                    status=AccessOutcome.ALLOWED,
                    request_fields=("user_id",),
                    response=ResponseData(fields=(("id", "secret"),)),
                    resource_state_before=(("state", "open"),),
                    resource_state_after=(("state", "closed"),),
                    permissions_checked=("iam.folders.get",),
                    gates_passed=("quota",),
                    sinks_reached=("http:internal",),
                ),
            )
        ),
    )

    graph = ObservationProjector().project(observation, "orders.Create")

    field_names = {fact.args[1].value for fact in _named(graph, "observed_field")}
    assert {
        "request.user_id",
        "id",
        "state_before.state",
        "state_after.state",
        "permission.iam.folders.get",
        "gate.quota",
    } <= field_names
    reached_sinks = {fact.args[1].value for fact in _named(graph, "observed_reached")}
    assert reached_sinks == {"http:internal"}
    unmapped_reasons = {
        fact.args[2].value for fact in _named(graph, "observed_unmapped")
    }
    assert unmapped_reasons == set()


def test_projector_marks_missing_trace_channels_not_available() -> None:
    observation = Observation(
        observation_id="obs-empty",
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="ok",
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id="obs-empty",
                    step_id="step-1",
                    method_id="orders.Get",
                    scenario_id="scenario-1",
                    status=AccessOutcome.ALLOWED,
                ),
            )
        ),
    )

    graph = ObservationProjector().project(observation, "orders.Get")

    unmapped_reasons = {
        fact.args[2].value for fact in _named(graph, "observed_unmapped")
    }
    assert {
        "request_fields_not_available",
        "response_not_available",
        "resource_state_before_not_available",
        "resource_state_after_not_available",
        "permissions_checked_not_available",
        "gates_passed_not_available",
        "sinks_reached_not_available",
    } <= unmapped_reasons


def test_projector_skips_non_string_output_field_names() -> None:
    observation = make_observation().model_copy(
        update={
            "output": ResponseData.model_construct(
                fields=((42, "secret-value"), ("name", "value"))
            ),
        }
    )

    graph = ObservationProjector().project(observation, "orders.Get")

    field_names = {fact.args[1].value for fact in _named(graph, "observed_field")}
    assert field_names == {"name"}


def test_projector_emits_probe_marker_aggregate() -> None:
    observation = make_observation().model_copy(
        update={"probe_marker": "marker:canary-123"}
    )

    graph = ObservationProjector().project(observation, "orders.Create")

    assert any(
        fact.args[1].value == "marker:canary-123"
        for fact in _named(graph, "observed_marker")
    )


def test_projector_emits_matching_oob_callback_aggregate() -> None:
    observation = make_observation().model_copy(
        update={"probe_marker": "marker:canary-123"}
    )
    events = (
        EvidenceEvent(channel="oob", correlation_id="other-candidate"),
        EvidenceEvent(
            channel="oob",
            correlation_id="marker:canary-123",
            source="10.0.0.8",
            attributes=(("method", "GET"), ("path", "/marker:canary-123")),
        ),
    )

    graph = ObservationProjector().project(
        observation,
        "orders.Create",
        oob_events=events,
    )

    callbacks = [fact.args[1].value for fact in _named(graph, "observed_external_call")]
    assert callbacks == ["marker:canary-123"]


def test_projector_polls_only_matching_persisted_oob_callback() -> None:
    observation = make_observation().model_copy(
        update={"probe_marker": "marker:canary-123"}
    )
    events = MemoryEvidenceChannel()
    events.record(EvidenceEvent(channel="oob", correlation_id="other-candidate"))
    events.record(
        EvidenceEvent(
            channel="oob",
            correlation_id="marker:canary-123",
            source="10.0.0.8",
            attributes=(("method", "GET"), ("path", "/marker:canary-123")),
        )
    )

    graph = ObservationProjector(oob_events=events).project(
        observation,
        "orders.Create",
    )

    callbacks = [fact.args[1].value for fact in _named(graph, "observed_external_call")]
    assert callbacks == ["marker:canary-123"]


def test_invalid_observation_fails_before_reading_captured_callbacks() -> None:
    reads = []

    class UnavailableChannel:
        def wait_for(self, marker, timeout, *, channel):
            reads.append((marker, timeout, channel))
            raise RuntimeError("captured evidence unavailable")

    projector = ObservationProjector(oob_events=UnavailableChannel())
    observation = make_observation().model_copy(update={"probe_marker": "candidate"})

    with pytest.raises(ValueError):
        projector.project(
            observation.model_copy(update={"duration_ms": float("inf")}),
            "orders.Create",
        )
    assert reads == []

    with pytest.raises(RuntimeError, match="captured evidence unavailable"):
        projector.project(observation, "orders.Create")
    assert reads == [("candidate", 0.0, "oob")]


def test_projector_emits_transport_status_aggregate() -> None:
    graph = ObservationProjector().project(make_observation(), "grpc:service.Get")

    status_values = {
        fact.args[1].value for fact in _named(graph, "observed_response_status")
    }
    assert status_values == {"gRPC status: INVALID_ARGUMENT", "grpc:INVALID_ARGUMENT"}


def test_projector_does_not_duplicate_matching_status_aggregate() -> None:
    observation = make_observation().model_copy(
        update={"response_summary": "grpc:INVALID_ARGUMENT"}
    )

    graph = ObservationProjector().project(observation, "grpc:service.Get")

    status_values = _named(graph, "observed_response_status")
    assert len(status_values) == 1
    assert status_values[0].args[1].value == "grpc:INVALID_ARGUMENT"


def test_projector_emits_auth_failure_aggregate() -> None:
    observation = make_observation().model_copy(update={"auth_failed": True})

    graph = ObservationProjector().project(observation, "orders.Get")

    assert any(
        fact.args[1].value == "auth_failure" for fact in _named(graph, "observed_error")
    )


def test_projector_does_not_read_state_response_field_as_control_state() -> None:
    observation = make_observation().model_copy(
        update={"output": ResponseData(fields=(("state", "archived"),))}
    )

    graph = ObservationProjector().project(observation, "orders.Close")

    assert not any(fact.predicate.name == "transition" for fact in graph.facts)
    assert any(
        fact.args[1].value == "state" for fact in _named(graph, "observed_field")
    )
    assert any(
        fact.args[2].value == "state_semantics_missing"
        for fact in _named(graph, "observed_unmapped")
    )


def test_projector_reads_status_field_as_state() -> None:
    observation = make_observation().model_copy(
        update={
            "output": ResponseData(fields=(("status", "active"),)),
        }
    )

    graph = ObservationProjector().project(observation, "orders.Activate")

    assert not any(fact.predicate.name == "transition" for fact in graph.facts)
    assert any(
        fact.args[1].value == "status" for fact in _named(graph, "observed_field")
    )
    assert any(
        fact.args[2].value == "state_semantics_missing"
        for fact in _named(graph, "observed_unmapped")
    )


def test_projector_emits_full_transition_from_trace_states() -> None:
    observation = Observation(
        observation_id="obs-1",
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="closed",
        output=ResponseData(fields=(("state", "closed"),)),
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id="obs-1",
                    step_id="step-1",
                    method_id="orders.Close",
                    scenario_id="scenario-1",
                    status=AccessOutcome.ALLOWED,
                    resource_state_before=(("state", "open"),),
                    resource_state_after=(("state", "closed"),),
                ),
            )
        ),
    )

    graph = ObservationProjector().project(observation, "orders.Close")

    assert any(
        fact.predicate.name == "transition"
        and [argument.value for argument in fact.args]
        == ["action:orders.Close", "open", "closed"]
        for fact in graph.facts
    )
    assert not any(
        fact.predicate.name == "is"
        and [argument.value for argument in fact.args] == ["unknown", "State"]
        for fact in graph.facts
    )


def test_projector_emits_transition_aggregate_from_trace_states() -> None:
    observation = make_state_observation("obs-evidence", "open", "closed")

    graph = ObservationProjector().project(observation, "orders.Close")

    assert any(
        [argument.value for argument in fact.args]
        == ["action:orders.Close", "open", "closed"]
        for fact in _named(graph, "observed_transition")
    )


def test_projector_requires_both_trace_state_channels() -> None:
    observation = make_state_observation("obs-partial", "open", "closed")
    step = observation.trace.steps[0].model_copy(update={"resource_state_before": ()})
    trace = observation.trace.model_copy(update={"steps": (step,)})
    observation = observation.model_copy(update={"trace": trace})

    graph = ObservationProjector().project(observation, "orders.Close")

    assert not any(fact.predicate.name == "transition" for fact in graph.facts)
    assert any(
        fact.args[2].value == "state_semantics_missing"
        for fact in _named(graph, "observed_unmapped")
    )


def test_projector_reads_after_state_from_trace_without_output_field() -> None:
    observation = Observation(
        observation_id="obs-2",
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="closed",
        output=ResponseData(fields=(("error", "none"),)),
        trace=ExecutionTrace(
            steps=(
                TraceStep(
                    observation_id="obs-2",
                    step_id="step-1",
                    method_id="orders.Close",
                    scenario_id="scenario-1",
                    status=AccessOutcome.ALLOWED,
                    resource_state_before=(("status", "open"),),
                    resource_state_after=(("status", "closed"),),
                ),
            )
        ),
    )

    graph = ObservationProjector().project(observation, "orders.Close")

    assert any(
        fact.predicate.name == "transition"
        and [argument.value for argument in fact.args]
        == ["action:orders.Close", "open", "closed"]
        for fact in graph.facts
    )


def test_projector_reads_after_state_from_response_tree() -> None:
    observation = make_observation().model_copy(
        update={
            "response_tree": (("state", "closed"),),
        }
    )

    graph = ObservationProjector().project(observation, "orders.Close")

    assert not any(fact.predicate.name == "transition" for fact in graph.facts)
    assert any(
        fact.args[2].value == "state_semantics_missing"
        for fact in _named(graph, "observed_unmapped")
    )


def test_projector_skips_non_string_state_values() -> None:
    observation = make_observation().model_copy(
        update={
            "output": ResponseData(fields=(("state", 404),)),
        }
    )

    graph = ObservationProjector().project(observation, "orders.Close")

    assert not any(fact.predicate.name == "transition" for fact in graph.facts)
    assert any(
        fact.args[2].value == "state_semantics_missing"
        for fact in _named(graph, "observed_unmapped")
    )


def test_projected_transitions_reach_state_machine_mismatch_engine() -> None:
    specification = state_machine_graph(
        states=("open", "closed"),
        actions=("action:orders.Close",),
        initial_states=("open",),
        transitions=(("action:orders.Close", "open", "closed"),),
    )
    observation = make_state_observation("obs-mismatch", "open", "archived")
    runtime = ObservationProjector().project(observation, "orders.Close")

    mismatches = StateMachineEngine().mismatches(merge_graphs(specification, runtime))

    assert len(mismatches) == 1
    assert mismatches[0].action == "action:orders.Close"
    assert mismatches[0].from_state == "open"
    assert mismatches[0].to_state == "archived"


def test_projected_transition_aggregates_ground_forbidden_state_violation() -> None:
    specification = state_machine_graph(
        states=("open", "archived"),
        actions=("action:orders.Close",),
        norms=("no_archive",),
        initial_states=("open",),
        forbidden_states=(("no_archive", "archived"),),
    )
    observation = make_state_observation("obs-grounded", "open", "archived")
    runtime = ObservationProjector().project(observation, "orders.Close")

    solution = StateMachineEngine().solve(merge_graphs(specification, runtime))

    assert len(solution.grounded_violations) == 1
    violation = solution.grounded_violations[0]
    assert violation.norm == "no_archive"
    assert violation.state == "archived"
    assert violation.grounded is True
    # Per-observation witnesses stay in the append-only event log; the graph
    # only carries idempotent observed_* aggregates.
    assert violation.evidence_refs == ()
    assert violation.path.initial_state == "open"
    assert violation.path.final_state == "archived"
    assert violation.path.actions == ("action:orders.Close",)
    assert violation.path.depth == 1


def test_projector_keeps_observation_ids_out_of_fact_arguments() -> None:
    observation = make_state_observation("obs-no-ids", "open", "closed")

    graph = ObservationProjector().project(observation, "orders.Close")

    assert not any(
        isinstance(term, Atom)
        and isinstance(term.value, str)
        and "obs-no-ids" in term.value
        for fact in graph.facts
        for term in fact.args
    )
    assert not any(
        fact.predicate.name == "is" and fact.args[1].value == "Observation"
        for fact in graph.facts
    )


def test_projector_is_idempotent_for_the_same_observation() -> None:
    observation = make_state_observation("obs-repeat", "open", "closed")

    first = ObservationProjector().project(observation, "orders.Close")
    second = ObservationProjector().project(observation, "orders.Close")
    merged = merge_graphs(first, second)

    assert first == second
    assert merged.facts == first.facts


def test_projector_deduplicates_same_meaning_across_observation_ids() -> None:
    first = make_state_observation("obs-one", "open", "closed")
    second = make_state_observation("obs-two", "open", "closed")

    graph_one = ObservationProjector().project(first, "orders.Close")
    graph_two = ObservationProjector().project(second, "orders.Close")
    merged = merge_graphs(graph_one, graph_two)

    assert graph_one.facts == graph_two.facts
    assert merged.facts == graph_one.facts
    assert len(_named(merged, "observed_outcome")) == 1
    assert len(_named(merged, "observed_transition")) == 1
    assert len(_named(merged, "transition")) == 1


def test_projector_aggregates_outcome_transition_and_reached() -> None:
    projector = ObservationProjector()
    observations = [
        Observation(
            observation_id=f"obs-{index}",
            check_id=f"check-{index}",
            scenario_id="scenario-1",
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="ok",
            trace=ExecutionTrace(
                steps=(
                    TraceStep(
                        observation_id=f"obs-{index}",
                        step_id=f"step-{index}",
                        method_id="orders.Close",
                        scenario_id="scenario-1",
                        status=AccessOutcome.ALLOWED,
                        resource_state_before=(("state", "open"),),
                        resource_state_after=(("state", "closed"),),
                        sinks_reached=("db.orders", "audit.log"),
                    ),
                )
            ),
        )
        for index in range(5)
    ]

    merged = merge_graphs(
        *(
            projector.project(observation, "orders.Close")
            for observation in observations
        )
    )

    assert {
        (fact.args[0].value, fact.args[1].value)
        for fact in _named(merged, "observed_outcome")
    } == {("action:orders.Close", "allowed")}
    assert {
        tuple(argument.value for argument in fact.args)
        for fact in _named(merged, "observed_transition")
    } == {("action:orders.Close", "open", "closed")}
    assert {
        (fact.args[0].value, fact.args[1].value)
        for fact in _named(merged, "observed_reached")
    } == {
        ("action:orders.Close", "db.orders"),
        ("action:orders.Close", "audit.log"),
    }


def test_projector_collapses_repeated_observations_to_unique_meanings() -> None:
    """Benchmark-shaped compression: many observations, few distinct meanings.

    Five observations per check across 194 checks used to project one
    evidence fact per observation channel; the merged graph now keeps only
    the distinct meanings per action.
    """

    projector = ObservationProjector()
    graphs = []
    for index in range(194 * 5):
        observation = Observation(
            observation_id=f"obs-{index}",
            check_id=f"check-{index // 5}",
            scenario_id="scenario-1",
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="ok",
            duration_ms=42.0,
            output=ResponseData(
                fields=(("id", 1), ("state", "closed"), ("owner", "user"))
            ),
            trace=ExecutionTrace(
                steps=(
                    TraceStep(
                        observation_id=f"obs-{index}",
                        step_id=f"step-{index}",
                        method_id=f"orders.Method{index % 39}",
                        scenario_id="scenario-1",
                        status=AccessOutcome.ALLOWED,
                        request_fields=("user_id", "order_id"),
                        resource_state_before=(("state", "open"),),
                        resource_state_after=(("state", "closed"),),
                        permissions_checked=("authz:read",),
                        gates_passed=("quota",),
                        sinks_reached=("db.orders",),
                    ),
                )
            ),
        )
        graphs.append(projector.project(observation, f"orders.Method{index % 39}"))

    merged = merge_graphs(*graphs)

    assert len(graphs) == 970
    # The same shape previously projected >15k per-observation evidence facts;
    # the merged runtime graph now keeps only distinct per-action meanings.
    assert sum(len(graph.facts) for graph in graphs) > 15_000
    assert len(merged.facts) < 700
    assert all(
        fact.context is Context.RUNTIME
        for fact in merged.facts
        if fact.predicate.name.startswith("observed_")
    )


def test_observed_aggregate_refutation_uses_supersedes() -> None:
    """Refuting an aggregate appends ``supersedes``; history is never retracted."""

    graph = ObservationProjector().project(make_observation(), "grpc:service.Get")
    outcome_facts = _named(graph, "observed_outcome")
    assert len(outcome_facts) == 1

    action = outcome_facts[0].args[0]
    old_value = outcome_facts[0].args[1]
    new_value = Atom(value="denied")
    refuted = merge_graphs(
        graph,
        QdlGraph(
            facts=(
                Fact(
                    context=Context.RUNTIME,
                    predicate=Predicate.from_name("is"),
                    args=(action, Atom(value="Action")),
                ),
                Fact(
                    context=Context.RUNTIME,
                    predicate=Predicate.from_name("is"),
                    args=(new_value, Atom(value="Node")),
                ),
                Fact(
                    context=Context.RUNTIME,
                    predicate=Predicate.from_name("is"),
                    args=(old_value, Atom(value="Node")),
                ),
                Fact(
                    context=Context.RUNTIME,
                    predicate=Predicate.from_name("observed_outcome"),
                    args=(action, new_value),
                ),
                Fact(
                    context=Context.RUNTIME,
                    predicate=Predicate.from_name("supersedes"),
                    args=(new_value, old_value),
                ),
            )
        ),
    )

    assert any(
        fact.predicate.name == "observed_outcome" and fact.args[1] == new_value
        for fact in refuted.facts
    )
    assert any(
        fact.predicate.name == "supersedes" and fact.args == (new_value, old_value)
        for fact in refuted.facts
    )
    # The superseded aggregate remains in the append-only graph.
    assert any(
        fact.predicate.name == "observed_outcome" and fact.args[1] == old_value
        for fact in refuted.facts
    )
