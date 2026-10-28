from __future__ import annotations

from types import SimpleNamespace

from cloud_dast.model import VerdictStatus
from cloud_dast.runtime import finding_shrinking
from cloud_dast.runtime.finding_shrinking import FindingShrinkCoordinator


class _Budget:
    def can_spend(self) -> bool:
        return True


class _Shrinker:
    def __init__(self, candidate: object) -> None:
        self._candidate = candidate
        self._returned = False
        self.recorded: list[tuple[object, bool]] = []
        self.result = SimpleNamespace(check=candidate)

    def next(self) -> object | None:
        if self._returned:
            return None
        self._returned = True
        return self._candidate

    def discard(self, candidate: object) -> None:
        self.recorded.append((candidate, False))

    def record(self, candidate: object, *, reproduced: bool) -> None:
        self.recorded.append((candidate, reproduced))


def test_coordinator_updates_minimal_check_and_persists_example(monkeypatch) -> None:
    seed = SimpleNamespace(name="seed")
    candidate = SimpleNamespace(name="minimal")
    origin = SimpleNamespace(observation_id="observation:origin")
    replacement = SimpleNamespace(observation_id="observation:replacement")
    invariant = SimpleNamespace(invariant_id="invariant:test")
    step = SimpleNamespace(
        step_id="step:test",
        plan=SimpleNamespace(),
        method=SimpleNamespace(method_id="method:test"),
        invariant=invariant,
    )
    key = (origin.observation_id, invariant.invariant_id)
    state = SimpleNamespace(
        minimal_checks={key: seed},
        provenance={key: SimpleNamespace(step_id=step.step_id, path_id="path:test")},
        differential_evidence=None,
    )
    attempt = SimpleNamespace(
        path=SimpleNamespace(steps=(step,)),
        observations=(origin,),
    )
    shrinker = _Shrinker(candidate)
    executed: list[object] = []
    persisted: list[object] = []

    monkeypatch.setattr(
        finding_shrinking,
        "save_finding_example",
        lambda _store, check: persisted.append(check),
    )

    def factory(**kwargs):
        assert kwargs["seed"] is seed
        return shrinker

    def execute(check, _budget, **_kwargs):
        executed.append(check)
        return replacement

    def classify(*_args, **_kwargs):
        return SimpleNamespace(
            policy_verdict=SimpleNamespace(deterministic=True, grounded=True),
            verdict=VerdictStatus.FAIL,
        )

    coordinator = FindingShrinkCoordinator(
        factory=factory,
        example_database=object(),
        execute_check=execute,
        classify_observation=classify,
    )

    coordinator.shrink_attempt_findings(
        SimpleNamespace(),
        attempt,
        state,
        budget=_Budget(),
        scope=None,
    )

    assert executed == [candidate]
    assert shrinker.recorded == [(candidate, True)]
    assert state.minimal_checks[key] is candidate
    assert persisted == [candidate]
