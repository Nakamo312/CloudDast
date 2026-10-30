"""The OOB port and runtime finalizer share one physical RunScope owner."""

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

import cloud_dast.composition.run_provider as providers
from cloud_dast.composition.container import make_cloud_dast_container
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.infrastructure.events import JsonlEventStore
from cloud_dast.infrastructure.runtime import OobCollaborator
from cloud_dast.model import AccessOutcome, Observation, Severity, VerdictStatus
from cloud_dast.ports import EvidenceChannel, OobEvaluator, OobUrlFactory
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, duration
from cloud_dast.runtime import oob
from cloud_dast.runtime.campaign import LiveWorkflow
from cloud_dast.verification.oracles import latency, primitive_router, witness


def test_real_run_provider_binds_one_oob_owner_per_run(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")

    def target(check):
        return Observation(
            check_id=check.check_id,
            scenario_id=check.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="OK",
        )

    container = make_cloud_dast_container(
        lambda: nullcontext(), target, JsonlEventStore(tmp_path / "events.jsonl")
    )
    with container as app:
        with app() as run:
            coordinator = run.get(oob.Coordinator)
            assert run.get(OobEvaluator) is coordinator
            router = run.get(primitive_router.Oracle)
            assert router._witness is run.get(witness.Oracle)
            assert router._witness._oob is coordinator
            workflow = run.get(LiveWorkflow)
            assert workflow._finalizer._oob is coordinator
            channel = run.get(EvidenceChannel)
            assert coordinator._events is channel
        with app() as run:
            assert run.get(oob.Coordinator) is not coordinator


def test_router_uses_run_calibration_without_leaking_to_next_run(
    tmp_path, monkeypatch, method_spec, scenario_position
):
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")
    monkeypatch.delenv("CLOUD_DAST_LATENCY_BASELINES", raising=False)
    action = Atom(value=f"action:{method_spec.method_id}")
    invariant = InvariantProjection(
        invariant_id="latency",
        norm_id="norm:latency",
        statement="bounded latency",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:latency"), duration(action, Atom(value=100))),
        ),
    )
    observation = Observation(
        check_id="check",
        scenario_id=scenario_position.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="OK",
        duration_ms=200,
    )
    container = make_cloud_dast_container(
        lambda: nullcontext(),
        lambda check: None,
        JsonlEventStore(tmp_path / "events.jsonl"),
    )
    with container as app:
        for calibrated in (True, False):
            with app() as run:
                router = run.get(primitive_router.Oracle)
                if calibrated:
                    run.get(latency.Oracle).update_baseline(
                        method_spec.method_id, (100, 100, 100)
                    )
                verdict = router.evaluate_policy(
                    invariant,
                    (observation,),
                    method=method_spec,
                    scenario=scenario_position,
                )
                if calibrated:
                    assert verdict.status is VerdictStatus.FAIL
                    assert verdict.deterministic and verdict.grounded
                    assert verdict.evidence_refs == (observation.observation_id,)
                else:
                    assert verdict.status is VerdictStatus.UNSCOREABLE
                    assert "no runtime latency baseline" in verdict.rationale


@pytest.mark.parametrize("abort", [False, True])
def test_collaborator_closes_at_run_exit(tmp_path, monkeypatch, abort):
    calls = []

    class Collaborator:
        def __init__(self, events):
            self.events = events
            calls.append(("created", self))

        def stop(self):
            calls.append(("stopped", self))

    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")
    monkeypatch.setattr(providers, "OobCollaborator", Collaborator)
    container = make_cloud_dast_container(
        lambda: nullcontext(),
        lambda check: None,
        JsonlEventStore(tmp_path / "events.jsonl"),
    )
    with container as app:
        with app():
            pass
        assert calls == []  # An unused resource is never constructed.
        exit_check = (
            pytest.raises(RuntimeError, match="aborted") if abort else nullcontext()
        )
        with exit_check:
            with app() as run:
                first = run.get(OobUrlFactory)
                assert run.get(OobUrlFactory) is first
                assert first.events is run.get(EvidenceChannel)
                assert calls == [("created", first)]
                if abort:
                    raise RuntimeError("aborted")
        assert calls == [("created", first), ("stopped", first)]
        with app() as run:
            second = run.get(OobUrlFactory)
            assert second is not first
        assert calls == [
            ("created", first),
            ("stopped", first),
            ("created", second),
            ("stopped", second),
        ]


@pytest.mark.parametrize("abort", [False, True])
def test_run_exit_stops_polling_and_deregisters_session(tmp_path, monkeypatch, abort):
    calls = []

    class Transport:
        callback_host = "oob.invalid"

        def start(self):
            calls.append("start")
            return SimpleNamespace(correlation_id="1234567890abcdefghij")

        def poll(self, session):
            calls.append("poll")
            return ()

        def stop(self, session):
            calls.append("stop")

    transport = Transport()
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")
    monkeypatch.setattr(
        providers,
        "OobCollaborator",
        lambda events: OobCollaborator(events, client=transport, poll_interval=60),
    )
    container = make_cloud_dast_container(
        lambda: nullcontext(),
        lambda check: None,
        JsonlEventStore(tmp_path / "events.jsonl"),
    )
    with container as app:
        exit_check = (
            pytest.raises(RuntimeError, match="aborted") if abort else nullcontext()
        )
        with exit_check:
            with app() as run:
                collaborator = run.get(OobUrlFactory)
                channel = run.get(EvidenceChannel)
                collaborator.url_for("probe-marker")
                poller = collaborator._poll_thread
                assert poller.is_alive()
                assert channel.ready()
                assert calls == ["start"]
                if abort:
                    raise RuntimeError("aborted")
        assert not poller.is_alive()
        assert not channel.ready()
        assert calls == ["start", "poll", "stop"]
