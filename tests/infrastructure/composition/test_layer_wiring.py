"""DI regression tests for the B2 layer-model fixes."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from typing import Any

from cloud_dast.composition.container import make_cloud_dast_container
from cloud_dast.infrastructure.runtime import ThreadedGroundingRunner
from cloud_dast.model import (
    AccessOutcome,
    Check,
    HttpStatus,
    Observation,
)
from cloud_dast.ports import (
    FormalRepository,
    Guardrail,
    InvocationRepository,
)
from cloud_dast.runtime.grounding import AutoGroundingService


class _EmptyResult:
    def data(self) -> list[dict[str, Any]]:
        return []

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(())


class _RecordingSession:
    def __init__(self) -> None:
        self.queries: list[tuple[str, dict[str, Any]]] = []

    def run(self, query: str, **params: Any) -> _EmptyResult:
        self.queries.append((query, dict(params)))
        return _EmptyResult()


class _EmptyEventStore:
    def append(self, event: object) -> None:
        return None

    def read(self) -> Iterator[object]:
        return iter(())

    def read_new(self, consumer_id: str) -> tuple[object, ...]:
        return ()


def _target(check: Check) -> Observation:
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.DENIED,
        response_summary="denied",
        transport_status=HttpStatus(code=403),
    )


def _check() -> Check:
    return Check(
        invariant_id="invariant",
        method_id="grpc-priv:example.Service.Get",
        scenario_id="scenario",
        request=(("secret_id", "secret"),),
        identities=("attacker",),
    )


def _session_factory(
    session: _RecordingSession,
) -> Callable[[], AbstractContextManager[_RecordingSession]]:
    @contextmanager
    def factory() -> Iterator[_RecordingSession]:
        yield session

    return factory


def _forbidden_session_factory() -> None:
    raise AssertionError("auto_grounding must reuse the container session factory")


def test_container_provides_guardrail_port(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")
    monkeypatch.delenv("CLOUD_DAST_ALLOWED_SERVICES", raising=False)
    session = _RecordingSession()
    container = make_cloud_dast_container(
        _session_factory(session),
        _target,
        _EmptyEventStore(),
    )

    with container as app, app() as run:
        guardrail = run.get(Guardrail)

        assert guardrail.allows(_check()) is False
    assert session.queries == []


def test_container_provides_invocation_repository_from_context_factory(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")
    session = _RecordingSession()
    container = make_cloud_dast_container(
        _session_factory(session),
        _target,
        _EmptyEventStore(),
    )

    with container as app, app() as run:
        invocations = run.get(InvocationRepository)

        assert invocations.get_invocation("grpc:example.Service.Get") is None
    assert any("Endpoint" in query for query, _ in session.queries)


def test_auto_grounding_uses_file_stand_source_by_default(
    monkeypatch,
    tmp_path,
) -> None:
    stand_path = tmp_path / "stand.json"
    stand_path.write_text(
        """
        {
          "bindings": [
            {"subject": "victim", "role": "lockbox.viewer", "scope": "secret-1"}
          ],
          "resources": [
            {"resource": "secret-1", "resource_type": "lockbox.secret"}
          ],
          "containments": [
            {"child": "secret-1", "parent": "folder-1"}
          ]
        }
        """,
        encoding="utf-8",
    )
    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "file")
    monkeypatch.setenv("CLOUD_DAST_STAND_FILE", str(stand_path))
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(
        '{"service": "lockbox", "endpoints": [], "methods": []}',
        encoding="utf-8",
    )
    monkeypatch.setenv("CLOUD_DAST_CONTRACT_FILE", str(contract_path))
    monkeypatch.setattr(
        "cloud_dast.infrastructure.neo4j.common.repository.make_session_factory",
        _forbidden_session_factory,
    )
    session = _RecordingSession()
    container = make_cloud_dast_container(
        _session_factory(session),
        _target,
        _EmptyEventStore(),
    )

    with container as app, app() as run:
        grounding = run.get(AutoGroundingService)

        grounding.start_grounded("lockbox", ThreadedGroundingRunner())
        repository = run.get(FormalRepository)
        stand = repository.load("stand:lockbox")

    facts = {
        (fact.predicate.name, *(argument.value for argument in fact.args))
        for fact in stand.facts
    }
    assert (
        "binding",
        "principal:victim",
        "role:lockbox.viewer",
        "resource:secret-1",
    ) in facts
    assert not any("LivePrincipal" in query for query, _ in session.queries)


def test_execution_checks_belong_to_one_run_scope(monkeypatch) -> None:
    from cloud_dast.runtime.execution.scenarios import Checker
    from tests.support.guardrails import AllowAllGuardrail

    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")
    executed = []

    def target(check):
        executed.append(check.check_id)
        return _target(check)

    container = make_cloud_dast_container(
        _session_factory(_RecordingSession()),
        target,
        _EmptyEventStore(),
        guardrail=AllowAllGuardrail(),
    )
    with container as app:
        with app() as run:
            checker = run.get(Checker)
            check = _check()
            observation = checker.execute_check(check)
            assert observation is not None
            assert observation.check_id == check.check_id
            assert run.get(Checker).checks == (check,)
        with app() as run:
            fresh = run.get(Checker)
            assert fresh.checks == ()
            assert checker.checks == (check,)
            fresh.execute_check(_check())
            assert len(fresh.checks) == 1
            assert checker.checks == (check,)
    assert len(executed) == 2


def test_planner_snapshot_cache_belongs_to_one_run(monkeypatch) -> None:
    from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph
    from cloud_dast.runtime.binding import ScenarioBinder
    from cloud_dast.runtime.planning import QdlPlanner

    monkeypatch.setenv("CLOUD_DAST_STAND_SOURCE", "neo4j")
    empty = QdlGraph()
    declared = QdlGraph(
        facts=(
            Fact(
                context=Context.CONTRACT,
                predicate=Predicate.from_name("is"),
                args=(Atom(value="action:read"), Atom(value="Action")),
            ),
        )
    )
    container = make_cloud_dast_container(
        _session_factory(_RecordingSession()), _target, _EmptyEventStore()
    )
    with container as app:
        with app() as run:
            planner = run.get(QdlPlanner)
            run.get(ScenarioBinder)
            planner.plan(empty)
            planner.plan(declared)
            assert run.get(QdlPlanner).grounded_batches == 1
        with app() as run:
            fresh = run.get(QdlPlanner)
            run.get(ScenarioBinder)
            assert fresh.grounded_batches == 0
            assert fresh.plan(declared) == QdlPlanner().plan(declared)
            assert fresh.grounded_batches == 0
            assert planner.grounded_batches == 1
