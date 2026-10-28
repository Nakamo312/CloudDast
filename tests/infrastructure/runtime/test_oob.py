from __future__ import annotations

import json
from dataclasses import asdict
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import pytest

from cloud_dast.api import (
    ExecutionResult,
    ObservationProvenance,
)
from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.infrastructure.runtime import (
    InteractshClient,
    JsonlEvidenceChannel,
    MemoryEvidenceChannel,
    OobCollaborator,
)
from cloud_dast.infrastructure.runtime import oob as oob_runtime
from cloud_dast.model import (
    AccessOutcome,
    Check,
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    Observation,
    Severity,
    VerdictStatus,
)
from cloud_dast.model.events import DomainEvent, FindingRaised
from cloud_dast.ports import EvidenceEvent
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, external_call
from cloud_dast.runtime.execution.checks import run_check
from cloud_dast.verification.finding_evaluator import FindingEvaluator
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.oracles import OobOracle
from cloud_dast.verification.oracles.primitive_router import (
    PrimitiveOracleRouter,
)
from cloud_dast.verification.projection import (
    ObservationProjector,
)
from cloud_dast_fuzzing import GoalPayloadGenerator


class _FakeServer:
    def __init__(self, address, handler):
        self.server_address = ("127.0.0.1", 45678)
        self.handler_class = handler
        self.instances.append(self)

    def serve_forever(self) -> None:
        return None

    def shutdown(self) -> None:
        return None

    def server_close(self) -> None:
        return None


def _install_fake_oob_server(monkeypatch) -> list[_FakeServer]:
    servers: list[_FakeServer] = []
    _FakeServer.instances = servers
    monkeypatch.setattr(oob_runtime, "HTTPServer", _FakeServer)
    return servers


class _FakeInteractshClient:
    class Session:
        correlation_id = "1234567890abcdefghij"

    def __init__(self, interactions=()) -> None:
        self.callback_host = "oob.example"
        self.interactions = tuple(interactions)
        self.session = self.Session()
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True
        return self.session

    def poll(self, session):
        assert session is self.session
        return self.interactions

    def stop(self, session):
        assert session is self.session
        self.stopped = True


def _payload_from_url(url: str) -> str:
    return urlsplit(url).hostname.split(".", 1)[0]


class _StaticGenerator:
    def generate(self, plan, method, invariant, scenario, *, feedback=None):
        del plan, invariant, feedback
        return (
            Check(
                invariant_id="invariant-1",
                method_id=method.method_id,
                scenario_id=scenario.scenario_id,
                request=tuple((field.name, "") for field in method.fields),
                identities=("attacker",),
            ),
        )


class _EventLog:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []
        self._cursors: dict[str, int] = {}

    def append(self, event: DomainEvent) -> None:
        self.events.append(event)

    def publish(self, event: DomainEvent) -> None:
        self.events.append(event)

    def read(self):
        return iter(self.events)

    def read_new(self, consumer_id: str) -> tuple[DomainEvent, ...]:
        cursor = self._cursors.setdefault(consumer_id, 0)
        events = tuple(self.events[cursor:])
        self._cursors[consumer_id] = len(self.events)
        return events


def _record_callback(servers: list[_FakeServer], marker: str) -> None:
    handler = servers[0].handler_class.__new__(servers[0].handler_class)
    handler.command = "GET"
    handler.path = f"/{marker}"
    handler.client_address = ("127.0.0.1", 45678)
    handler.headers = {}
    handler.send_response = lambda status: None
    handler.end_headers = lambda: None
    handler._record()


def _oob_observation(marker: str) -> Observation:
    return Observation(
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="OK",
        probe_marker=marker,
    )


def _oob_invariant() -> InvariantProjection:
    effect = external_call(
        Atom(value="action:orders.SetWebhook"),
        Atom(value="norm-marker"),
    )
    return InvariantProjection(
        invariant_id="invariant-1",
        norm_id="norm-1",
        statement="prevent outbound calls",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm-1"), effect),
        ),
    )


def _oob_method() -> MethodSpec:
    return MethodSpec(
        method_id="orders.SetWebhook",
        service="orders",
        name="SetWebhook",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="callback_url", type="url", required=True),),
    )


def _oob_plan(scenario) -> VerificationPlan:
    return VerificationPlan(
        plan_id="plan-1",
        invariant_id="invariant-1",
        method_id="orders.SetWebhook",
        scenario_id=scenario.scenario_id,
        probe_fields=("callback_url",),
    )


def test_memory_oob_store_waits_for_marker() -> None:
    store = MemoryEvidenceChannel()
    store.set_ready(True)
    store.record(
        EvidenceEvent(channel="oob", correlation_id="marker-1", source="127.0.0.1")
    )

    assert store.wait_for("marker-1", 0.0) is not None
    assert store.wait_for("marker-2", 0.0) is None
    assert store.ready() is True


def test_memory_oob_store_reports_blocked_reason() -> None:
    store = MemoryEvidenceChannel()

    store.block("listener port is unavailable")

    assert store.ready() is False
    assert store.blocked_reason() == "listener port is unavailable"

    store.set_ready(True)

    assert store.ready() is True
    assert store.blocked_reason() is None


def test_memory_oob_store_keeps_bounded_index_for_10k_events() -> None:
    events = [
        EvidenceEvent(channel="oob", correlation_id=f"marker-{index}")
        for index in range(10_000)
    ]
    store = MemoryEvidenceChannel(capacity=128)

    for event in events:
        store.record(event)

    assert store.events == tuple(events[-128:])
    assert store.wait_for("marker-9999", 0.0) == events[-1]
    assert store.wait_for("marker-0", 0.0) is None


def test_memory_evidence_channel_rejects_invalid_event_metadata() -> None:
    store = MemoryEvidenceChannel()

    with pytest.raises(ValueError, match="unknown evidence channel"):
        store.record(
            EvidenceEvent(correlation_id="marker-1", channel="invalid-channel"),
        )

    with pytest.raises(ValueError, match="observed_at must be a finite non-negative"):
        store.record(
            EvidenceEvent(
                correlation_id="marker-1",
                channel="oob",
                observed_at=-1.0,
            ),
        )

    with pytest.raises(ValueError, match="duplicate evidence attribute"):
        store.record(
            EvidenceEvent(
                correlation_id="marker-1",
                channel="oob",
                attributes=(("method", "GET"), ("method", "POST")),
            ),
        )


def test_jsonl_evidence_channel_rejects_forged_record(tmp_path) -> None:
    path = tmp_path / "evidence-events.jsonl"
    payload = {
        "event_id": "forged",
        "correlation_id": "marker-1",
        "channel": "invalid-channel",
        "event_type": "http",
        "source": "10.0.0.8",
        "observed_at": 1.0,
        "attributes": [],
    }
    path.write_text(json.dumps(payload) + "\n")

    with pytest.raises(ValueError, match="invalid evidence event JSON"):
        JsonlEvidenceChannel(path)


def test_local_oob_collaborator_closes_evidence_chain(monkeypatch) -> None:
    servers = _install_fake_oob_server(monkeypatch)
    store = MemoryEvidenceChannel()
    collaborator = OobCollaborator(store, host="127.0.0.1", port=0)
    marker = "oob-candidate-marker"

    url = collaborator.url_for(marker)
    assert url == f"http://127.0.0.1:45678/{marker}"

    _record_callback(servers, marker)

    event = store.wait_for(marker, 1.0)
    assert event is not None
    assert event.event_id
    assert event.correlation_id == marker
    assert event.channel == "oob"
    assert event.event_type == "http"
    assert ("method", "GET") in event.attributes
    assert ("path", f"/{marker}") in event.attributes
    assert event.source == "127.0.0.1"
    assert event.observed_at > 0.0

    collaborator.stop()
    assert store.blocked_reason() == "out-of-band listener stopped"


def test_in_memory_oob_chain_yields_verdict_and_runtime_fact(monkeypatch) -> None:
    servers = _install_fake_oob_server(monkeypatch)
    store = MemoryEvidenceChannel()
    collaborator = OobCollaborator(store, host="127.0.0.1", port=0)
    marker = "candidate-marker"
    collaborator.url_for(marker)
    _record_callback(servers, marker)

    observation = _oob_observation(marker)
    invariant = _oob_invariant()

    verdict = OobOracle(store, wait_seconds=0.0).evaluate_policy(
        invariant,
        (observation,),
    )
    graph = ObservationProjector(oob_events=store).project(
        observation,
        "orders.SetWebhook",
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.grounded is True
    assert observation.observation_id in verdict.evidence_refs
    assert store.wait_for(marker, 0.0).event_id in verdict.evidence_refs
    assert any(
        fact.predicate.name == "observed_external_call" and fact.args[1].value == marker
        for fact in graph.facts
    )


def test_in_memory_oob_chain_raises_finding(
    monkeypatch,
    scenario_position,
) -> None:
    servers = _install_fake_oob_server(monkeypatch)
    store = MemoryEvidenceChannel()
    collaborator = OobCollaborator(store, host="127.0.0.1", port=0)
    method = _oob_method()
    plan = _oob_plan(scenario_position)
    invariant = _oob_invariant()
    generator = GoalPayloadGenerator(_StaticGenerator(), oob_urls=collaborator)

    first = generator.generate(plan, method, invariant, scenario_position)[0]
    second = generator.generate(plan, method, invariant, scenario_position)[0]
    assert first.probe_marker is not None
    assert second.probe_marker is not None
    assert first.probe_marker != second.probe_marker
    assert first.probe_marker != "norm-marker"
    check = first
    assert dict(check.request)["callback_url"] == collaborator.url_for(
        check.probe_marker
    )

    _record_callback(servers, check.probe_marker)
    events = _EventLog()

    def target(executed: Check) -> Observation:
        return Observation(
            check_id=executed.check_id,
            scenario_id=executed.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="OK",
        )

    observation = run_check(check, target, events)
    assert observation.probe_marker == check.probe_marker

    verdict = PrimitiveOracleRouter(
        oob_oracle=OobOracle(store, wait_seconds=0.0)
    ).evaluate_policy(
        invariant, (observation,), method=method, scenario=scenario_position
    )
    graph = ObservationProjector(oob_events=store).project(
        observation,
        method.method_id,
    )
    execution = ExecutionResult(
        observations=(observation,),
        checks=(check,),
        traces={observation.observation_id: (observation,)},
        provenance={
            (observation.observation_id, invariant.invariant_id): ObservationProvenance(
                None, "path", "step", invariant.invariant_id
            )
        },
        policy_verdicts={(observation.observation_id, invariant.invariant_id): verdict},
    )
    evaluation = FindingEvaluator(events, events).evaluate(
        execution,
        {invariant.invariant_id: invariant},
    )

    assert verdict.status is VerdictStatus.FAIL
    assert verdict.grounded is True
    assert len(evaluation.findings) == 1
    finding = evaluation.findings[0]
    assert observation.observation_id in finding.evidence_refs
    assert store.wait_for(check.probe_marker, 0.0).event_id in finding.evidence_refs
    assert any(
        fact.predicate.name == "observed_external_call"
        and fact.args[1].value == check.probe_marker
        for fact in graph.facts
    )
    assert any(isinstance(event, FindingRaised) for event in events.events)

    collaborator.stop()


def test_oob_oracle_does_not_fall_back_to_the_norm_marker() -> None:
    store = MemoryEvidenceChannel()
    store.set_ready(True)
    store.record(
        EvidenceEvent(channel="oob", correlation_id="norm-marker", source="127.0.0.1")
    )
    observation = _oob_observation("candidate-marker")

    verdict = OobOracle(store, wait_seconds=0.0).evaluate_policy(
        _oob_invariant(),
        (observation,),
    )

    assert verdict.status is VerdictStatus.UNSCOREABLE
    assert verdict.grounded is False
    assert verdict.evidence_refs == ()


def test_oob_store_accepts_dns_and_rejects_oversized_metadata() -> None:
    store = MemoryEvidenceChannel()

    store.record(
        EvidenceEvent(
            channel="oob",
            correlation_id="dns-marker",
            event_type="dns",
            source="10.0.0.8",
            attributes=(("method", "DNS"),),
        )
    )

    assert store.wait_for("dns-marker", 0.0) is not None
    with pytest.raises(ValueError, match="event_type is too long"):
        store.record(
            EvidenceEvent(
                channel="oob",
                correlation_id="bad-event-type",
                event_type="x" * 65,
            ),
        )
    with pytest.raises(ValueError, match="source is too long"):
        store.record(
            EvidenceEvent(
                channel="oob",
                correlation_id="bad-source",
                source="x" * 257,
            ),
        )


def test_jsonl_oob_store_persists_and_polls_across_instances(tmp_path) -> None:
    path = tmp_path / "oob-events.jsonl"
    writer = JsonlEvidenceChannel(path)
    event = EvidenceEvent(
        channel="oob",
        correlation_id="candidate-marker",
        source="10.0.0.8",
        event_type="http",
        observed_at=123.5,
        attributes=(("method", "POST"), ("path", "/candidate-marker")),
    )
    clock = [0.0]

    def record_while_polling(_: float) -> None:
        writer.record(event)
        clock[0] += 1

    reader = JsonlEvidenceChannel(
        path,
        clock=lambda: clock[0],
        poll_interval=0.0,
        sleep=record_while_polling,
    )

    assert reader.wait_for("candidate-marker", 1.0) == event
    assert reader.wait_for("other-marker", 0.0) is None
    assert reader.events == (event,)

    with pytest.raises(ValueError, match="duplicate evidence event_id"):
        writer.record(event)


def test_jsonl_oob_timeout_reevaluates_late_durable_callback(tmp_path) -> None:
    path = tmp_path / "oob-events.jsonl"
    marker = "late-callback-marker"
    store = JsonlEvidenceChannel(path)
    observation = _oob_observation(marker)
    oracle = OobOracle(store, wait_seconds=0.0)

    timed_out = oracle.evaluate_policy(_oob_invariant(), (observation,))
    event = EvidenceEvent(channel="oob", correlation_id=marker, source="10.0.0.8")
    JsonlEvidenceChannel(path).record(event)
    late = oracle.evaluate_policy(_oob_invariant(), (observation,))

    assert timed_out.status is VerdictStatus.UNSCOREABLE
    assert timed_out.grounded is False
    assert late.status is VerdictStatus.FAIL
    assert late.grounded is True
    assert event.event_id in late.evidence_refs


def test_memory_oob_timeout_sweeps_late_callback() -> None:
    store = MemoryEvidenceChannel()
    store.set_ready(True)
    marker = "late-callback-marker"
    observation = _oob_observation(marker)
    oracle = OobOracle(store, wait_seconds=0.0)

    timed_out = oracle.evaluate_policy(_oob_invariant(), (observation,))
    assert oracle.reevaluate_pending(timeout=0.0) == {}

    event = EvidenceEvent(channel="oob", correlation_id=marker, source="10.0.0.8")
    store.record(event)
    verdicts = oracle.reevaluate_pending(timeout=0.0)

    assert timed_out.status is VerdictStatus.UNSCOREABLE
    assert tuple(verdicts) == (observation.observation_id,)
    late = verdicts[observation.observation_id]
    assert late.status is VerdictStatus.FAIL
    assert late.grounded is True
    assert observation.observation_id in late.evidence_refs
    assert event.event_id in late.evidence_refs
    assert oracle.reevaluate_pending(timeout=0.0) == {}


def test_memory_oob_timeout_reevaluates_by_marker() -> None:
    store = MemoryEvidenceChannel()
    store.set_ready(True)
    marker = "marker-late-callback"
    observation = _oob_observation(marker)
    oracle = OobOracle(store, wait_seconds=0.0)

    timed_out = oracle.evaluate_policy(_oob_invariant(), (observation,))
    event = EvidenceEvent(channel="oob", correlation_id=marker, source="10.0.0.8")
    store.record(event)
    late = oracle.reevaluate(marker)

    assert timed_out.status is VerdictStatus.UNSCOREABLE
    assert late is not None
    assert late.status is VerdictStatus.FAIL
    assert late.grounded is True
    assert observation.observation_id in late.evidence_refs
    assert event.event_id in late.evidence_refs
    assert oracle.reevaluate(marker) is None


def test_oob_router_sweeps_pending_late_callback(scenario_position) -> None:
    store = MemoryEvidenceChannel()
    store.set_ready(True)
    marker = "router-late-callback"
    observation = _oob_observation(marker)
    router = PrimitiveOracleRouter(oob_oracle=OobOracle(store, wait_seconds=0.0))

    timed_out = router.evaluate_policy(
        _oob_invariant(),
        (observation,),
        method=_oob_method(),
        scenario=scenario_position,
    )
    event = EvidenceEvent(channel="oob", correlation_id=marker, source="10.0.0.8")
    store.record(event)
    verdicts = router.reevaluate_oob_pending(timeout=0.0)

    assert timed_out.status is VerdictStatus.UNSCOREABLE
    assert verdicts[observation.observation_id].status is VerdictStatus.FAIL
    assert verdicts[observation.observation_id].grounded is True
    assert event.event_id in verdicts[observation.observation_id].evidence_refs


def test_jsonl_oob_store_recovers_torn_tail_before_append(tmp_path) -> None:
    path = tmp_path / "oob-events.jsonl"
    path.write_bytes(b'{"event_id":"torn"')
    event = EvidenceEvent(
        channel="oob", correlation_id="candidate-marker", source="10.0.0.8"
    )

    JsonlEvidenceChannel(path).record(event)

    assert JsonlEvidenceChannel(path).wait_for("candidate-marker", 0.0) == event


def test_jsonl_oob_store_keeps_bounded_index_for_10k_events(tmp_path) -> None:
    path = tmp_path / "oob-events.jsonl"
    events = [
        EvidenceEvent(channel="oob", correlation_id=f"marker-{index}")
        for index in range(10_000)
    ]
    with path.open("wb") as stream:
        for event in events:
            stream.write(
                json.dumps(asdict(event), separators=(",", ":")).encode("utf-8") + b"\n"
            )

    store = JsonlEvidenceChannel(path, capacity=128)

    assert store.events == tuple(events[-128:])
    assert store.wait_for("marker-9999", 0.0) == events[-1]
    assert store.wait_for("marker-0", 0.0) == events[0]
    assert sum(1 for _ in path.open("rb")) == len(events)


def test_oob_collaborator_uses_interactsh_without_local_listener(
    monkeypatch,
) -> None:
    servers = _install_fake_oob_server(monkeypatch)
    store = MemoryEvidenceChannel()
    client = _FakeInteractshClient()
    collaborator = OobCollaborator(
        store,
        client=client,
        poll_interval=60.0,
    )

    url = collaborator.url_for("candidate-marker")
    payload = _payload_from_url(url)

    assert url == f"https://{payload}.oob.example"
    assert len(payload) == 33
    assert client.started is True
    assert store.ready() is True
    assert servers == []

    client.interactions = (
        {
            "protocol": "dns",
            "unique-id": payload,
            "full-id": f"{payload}.oob.example",
            "remote-address": "10.0.0.8",
            "timestamp": "2026-10-20T12:00:00Z",
        },
        {
            "protocol": "dns",
            "unique-id": "unknownpaylooooooooooooooooooooooooooo",
            "full-id": "unknownpaylooooooooooooooooooooooooooo.oob.example",
            "remote-address": "10.0.0.9",
            "timestamp": "2026-10-20T12:00:01Z",
        },
    )
    collaborator.poll_once()

    event = store.wait_for("candidate-marker", 0.0)
    assert event is not None
    assert event.channel == "oob"
    assert event.event_type == "dns"
    assert ("method", "DNS") in event.attributes
    assert ("path", f"{payload}.oob.example") in event.attributes
    assert event.source == "10.0.0.8"
    assert event.observed_at > 0.0
    assert store.events == (event,)

    collaborator.stop()
    assert client.stopped is True
    assert store.blocked_reason() == "out-of-band channel stopped"


def test_interactsh_stop_drains_late_callback_before_deregistration() -> None:
    store = MemoryEvidenceChannel()
    client = _FakeInteractshClient()
    collaborator = OobCollaborator(
        store,
        client=client,
        poll_interval=60.0,
    )

    url = collaborator.url_for("late-callback-marker")
    payload = _payload_from_url(url)
    client.interactions = (
        {
            "protocol": "dns",
            "unique-id": payload,
            "full-id": f"{payload}.oob.example",
            "remote-address": "10.0.0.8",
            "timestamp": "2026-10-20T12:00:00Z",
        },
    )

    collaborator.stop()

    event = store.wait_for("late-callback-marker", 0.0)
    assert event is not None
    assert event.channel == "oob"
    assert event.event_type == "dns"
    assert event.source == "10.0.0.8"
    assert client.stopped is True
    assert store.blocked_reason() == "out-of-band channel stopped"


def test_interactsh_expected_marker_set_is_bounded() -> None:
    store = MemoryEvidenceChannel()
    client = _FakeInteractshClient()
    collaborator = OobCollaborator(
        store,
        client=client,
        poll_interval=60.0,
        expected_capacity=2,
    )
    urls = (
        collaborator.url_for("marker-1"),
        collaborator.url_for("marker-2"),
        collaborator.url_for("marker-3"),
    )
    payloads = tuple(_payload_from_url(url) for url in urls)

    assert collaborator.url_for("marker-3") == urls[2]
    client.interactions = tuple(
        {
            "protocol": "dns",
            "unique-id": payload,
            "full-id": f"{payload}.oob.example",
            "remote-address": "10.0.0.8",
            "timestamp": "2026-10-20T12:00:00Z",
        }
        for payload in payloads
    )
    collaborator.poll_once()

    assert tuple(event.correlation_id for event in store.events) == (
        "marker-2",
        "marker-3",
    )

    collaborator.stop()


def test_interactsh_registration_failure_blocks_url_generation() -> None:
    store = MemoryEvidenceChannel()

    class FailingClient(_FakeInteractshClient):
        def start(self):
            raise RuntimeError("unauthorized")

    collaborator = OobCollaborator(
        store,
        client=FailingClient(),
        poll_interval=60.0,
    )

    with pytest.raises(RuntimeError, match="Interactsh registration failed"):
        collaborator.url_for("candidate-marker")

    assert store.ready() is False
    assert store.blocked_reason() == "Interactsh registration failed"


def test_interactsh_configuration_requires_https_and_token(monkeypatch) -> None:
    monkeypatch.delenv("CLOUD_DAST_OOB_SERVER_URL", raising=False)
    monkeypatch.delenv("CLOUD_DAST_OOB_TOKEN", raising=False)
    monkeypatch.delenv("CLOUD_DAST_OOB_TOKEN_FILE", raising=False)
    store = MemoryEvidenceChannel()

    with pytest.raises(RuntimeError, match="invalid Interactsh OOB configuration"):
        OobCollaborator(store, server_url="http://collaborator.test")
    with pytest.raises(RuntimeError, match="invalid Interactsh OOB configuration"):
        OobCollaborator(store, server_url="https://collaborator.test", token="")
    with pytest.raises(RuntimeError, match="invalid Interactsh OOB configuration"):
        OobCollaborator(store, server_url="https://127.0.0.1", token="server-token")

    assert store.ready() is False
    assert store.blocked_reason() == "invalid Interactsh OOB configuration"


def test_interactsh_poll_interval_must_be_numeric(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_OOB_POLL_INTERVAL", "not-a-number")
    store = MemoryEvidenceChannel()

    with pytest.raises(RuntimeError, match="POLL_INTERVAL must be a number"):
        OobCollaborator(
            store,
            server_url="https://collaborator.test",
            token="server-token",
        )

    assert store.blocked_reason() == "CLOUD_DAST_OOB_POLL_INTERVAL must be a number"


def test_interactsh_client_forbids_redirects() -> None:
    handler = oob_runtime._NoRedirectHandler()

    with pytest.raises(HTTPError, match="redirects are forbidden"):
        handler.redirect_request(
            object(),
            None,
            302,
            "Found",
            {},
            "https://attacker.test/register",
        )


def test_local_oob_fallback_accepts_only_expected_markers(monkeypatch) -> None:
    servers = _install_fake_oob_server(monkeypatch)
    store = MemoryEvidenceChannel()
    collaborator = OobCollaborator(store, host="127.0.0.1", port=0)
    collaborator.url_for("expected-marker")

    _record_callback(servers, "unexpected-marker")
    assert store.events == ()

    _record_callback(servers, "expected-marker")
    event = store.wait_for("expected-marker", 0.0)
    assert event is not None
    assert event.channel == "oob"
    assert event.event_type == "http"

    collaborator.stop()


def test_local_oob_fallback_rejects_non_loopback_host() -> None:
    store = MemoryEvidenceChannel()

    with pytest.raises(RuntimeError, match="loopback"):
        OobCollaborator(store, host="0.0.0.0", port=0)

    assert store.ready() is False
    assert store.blocked_reason() == "local OOB fallback listener must bind to loopback"


class _FakeHttpResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.headers = {"Content-Length": str(len(body))}

    def read(self, size: int = -1) -> bytes:
        return self.body if size < 0 else self.body[:size]

    def close(self) -> None:
        return None


class _FakeUrlopen:
    def __init__(self, poll_payload: dict | None = None) -> None:
        self.requests: list[tuple[object, float]] = []
        self.register_body: dict | None = None
        self.poll_payload = poll_payload

    def __call__(self, request, timeout: float):
        self.requests.append((request, timeout))
        parsed = urlsplit(request.full_url)
        if request.method == "POST" and parsed.path.endswith("/register"):
            self.register_body = json.loads(request.data)
            return _FakeHttpResponse(b'{"message":"registration successful"}')
        if request.method == "GET" and parsed.path.endswith("/poll"):
            payload = self.poll_payload or {
                "data": [],
                "extra": [
                    json.dumps(
                        {
                            "protocol": "http",
                            "unique-id": "callback-id",
                            "full-id": "callback-id.oob.example",
                            "raw-request": "GET /callback HTTP/1.1\r\nHost: x\r\n",
                            "remote-address": "10.0.0.8:12345",
                            "timestamp": "2026-10-20T12:00:00Z",
                        }
                    )
                ],
                "aes_key": "",
            }
            return _FakeHttpResponse(json.dumps(payload).encode())
        if request.method == "POST" and parsed.path.endswith("/deregister"):
            return _FakeHttpResponse(b'{"message":"deregistration successful"}')
        raise AssertionError(f"unexpected request: {request.method} {parsed.path}")


def test_interactsh_client_uses_registration_and_polling_rest_protocol() -> None:
    transport = _FakeUrlopen()
    client = InteractshClient(
        "https://collaborator.test/",
        "server-token",
        urlopen_=transport,
    )

    session = client.start()
    interaction = client.poll(session)[0]
    client.stop(session)

    assert transport.register_body is not None
    assert set(transport.register_body) == {
        "public-key",
        "secret-key",
        "correlation-id",
    }
    assert len(transport.register_body["correlation-id"]) == 20
    register_request = transport.requests[0][0]
    assert register_request.headers["Authorization"] == "server-token"
    assert register_request.get_header("Content-type") == "application/json"
    poll_request = transport.requests[1][0]
    poll_query = parse_qs(urlsplit(poll_request.full_url).query)
    assert poll_query["id"] == [session.correlation_id]
    assert poll_query["secret"] == [session.secret_key]
    assert interaction["protocol"] == "http"


def test_interactsh_client_decrypts_encrypted_poll_data() -> None:
    import base64

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    transport = _FakeUrlopen()
    client = InteractshClient(
        "https://collaborator.test",
        "server-token",
        urlopen_=transport,
    )
    session = client.start()
    assert transport.register_body is not None
    public_key = serialization.load_pem_public_key(
        base64.b64decode(transport.register_body["public-key"])
    )
    aes_key = b"0123456789abcdef0123456789abcdef"
    iv = b"1234567890abcdef"
    plaintext = json.dumps(
        {
            "protocol": "dns",
            "unique-id": "callback-id",
            "full-id": "callback-id.oob.example",
            "remote-address": "10.0.0.8",
            "timestamp": "2026-10-20T12:00:00Z",
        }
    ).encode()
    encryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).encryptor()
    ciphertext = iv + encryptor.update(plaintext) + encryptor.finalize()
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    transport.poll_payload = {
        "data": [base64.b64encode(ciphertext).decode("ascii")],
        "extra": [],
        "aes_key": base64.b64encode(encrypted_key).decode("ascii"),
    }

    interaction = client.poll(session)[0]

    assert interaction["protocol"] == "dns"
    assert interaction["remote-address"] == "10.0.0.8"


def test_interactsh_client_bounds_poll_flood() -> None:
    transport = _FakeUrlopen(
        {
            "data": [],
            "extra": ["{}", "{}"],
            "aes_key": "",
        }
    )
    client = InteractshClient(
        "https://collaborator.test",
        "server-token",
        max_interactions=1,
        urlopen_=transport,
    )
    session = client.start()

    with pytest.raises(ValueError, match="too many interactions"):
        client.poll(session)

    transport.poll_payload = {
        "data": [],
        "extra": [],
        "aes_key": "",
    }
    oversized = _FakeHttpResponse(b"x" * 65)
    original_read = oversized.read

    def read(_: int = -1) -> bytes:
        return original_read(65)

    oversized.read = read
    oversized.headers = {"Content-Length": "65"}
    small_client = InteractshClient(
        "https://collaborator.test",
        "server-token",
        max_response_bytes=64,
        urlopen_=lambda request, timeout: oversized,
    )
    with pytest.raises(ValueError, match="byte cap"):
        small_client.poll(session)
