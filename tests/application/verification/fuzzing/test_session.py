from __future__ import annotations

import pytest
from hypothesis.database import InMemoryExampleDatabase

from cloud_dast.candidates import TemplateGenerator
from cloud_dast.contracts.finding_examples import save_finding_example
from cloud_dast.contracts.plan import InvariantProjection, VerificationPlan
from cloud_dast.model import (
    AccessOutcome,
    BindingRef,
    Check,
    EndpointLayer,
    FieldSpec,
    HttpStatus,
    MethodSpec,
    Observation,
    PrincipalRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
    VerdictStatus,
)
from cloud_dast.ports import ModelRequest
from cloud_dast_fuzzing import FuzzSession, GeneratorBandit
from cloud_dast_fuzzing.session import _signature
from cloud_dast_llm.generator import LlmGenerator


class StaticGenerator:
    def __init__(self, values: tuple[str, ...]) -> None:
        self._values = values
        self.calls = 0

    def generate(
        self, plan, method, invariant, scenario, *, feedback=None
    ) -> tuple[Check, ...]:
        del feedback
        self.calls += 1
        return tuple(
            Check(
                invariant_id=invariant.invariant_id,
                method_id=method.method_id,
                scenario_id=scenario.scenario_id,
                request=((field.name, value),),
                identities=("attacker",),
                generator="fuzzing",
            )
            for field in method.fields
            for value in self._values
        )


class FeedbackGenerator:
    uses_feedback = True

    def __init__(self) -> None:
        self.calls = 0
        self.feedback = []

    def generate(
        self,
        plan,
        method,
        invariant,
        scenario,
        *,
        feedback=None,
    ) -> tuple[Check, ...]:
        self.calls += 1
        self.feedback.append(feedback)
        values = (
            ("first", "first-alternative") if self.calls == 1 else ("informed-next",)
        )
        return (
            Check(
                invariant_id=invariant.invariant_id,
                method_id=method.method_id,
                scenario_id=scenario.scenario_id,
                request=(
                    (
                        method.fields[0].name,
                        value,
                    ),
                ),
                identities=("attacker",),
                generator="grammar",
            )
            for value in values
        )


class FailingModelClient:
    def complete(
        self,
        request: ModelRequest,
        *,
        response_type=None,
    ):
        raise TimeoutError("model timed out")


class AllowAll:
    def allows(self, check) -> bool:
        return True


class DenyFirst:
    def __init__(self) -> None:
        self.calls = 0

    def allows(self, check) -> bool:
        self.calls += 1
        return self.calls > 1


class RecordingBandit:
    """Bandit double that records every graded arm reward."""

    def __init__(self) -> None:
        self.updates: list[tuple[str, float]] = []

    def choose(
        self,
        strategies,
        *,
        goal_key="generic",
        action_id=None,
    ):
        return strategies[0]

    def update(
        self,
        strategy,
        reward,
        *,
        goal_key="generic",
        action_id=None,
        verdict=None,
    ) -> None:
        self.updates.append((strategy, float(reward)))


def method() -> MethodSpec:
    return MethodSpec(
        method_id="get-secret",
        service="lockbox",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="secret_id", type="string", required=True),),
    )


def scenario() -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="scenario",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="resource",
            endpoint_layer=EndpointLayer.PRIVATE,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(),
    )


def invariant() -> InvariantProjection:
    return InvariantProjection(
        invariant_id="inv",
        norm_id="norm",
        statement="norm",
        severity=Severity.HIGH,
    )


def plan() -> VerificationPlan:
    return VerificationPlan(
        plan_id="plan",
        invariant_id="inv",
        method_id="get-secret",
        scenario_id="scenario",
    )


def session(values: tuple[str, ...] = ("a", "b", "c"), **kwargs) -> FuzzSession:
    return FuzzSession(
        plan=plan(),
        method=method(),
        invariant=invariant(),
        scenario=scenario(),
        generators={"fuzzing": StaticGenerator(values)},
        policy=GeneratorBandit(seed=0),
        guardrail=AllowAll(),
        **kwargs,
    )


def observation(check: Check, *, summary: str = "resource not found") -> Observation:
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ERROR,
        response_summary=summary,
        transport_status=HttpStatus(code=404),
    )


def test_fuzz_session_stops_on_budget() -> None:
    fuzz = session(max_checks=2)
    first = fuzz.next()
    second = fuzz.next()
    third = fuzz.next()

    assert first is not None
    assert second is not None
    assert third is None
    assert fuzz.stop_reason == "budget"
    assert fuzz.state.emitted == 2


def test_preview_does_not_consume_fuzz_budget() -> None:
    fuzz = session(values=("a", "b"))
    previewed = fuzz.preview()

    assert previewed is not None
    assert fuzz.state.emitted == 0
    assert not fuzz.stopped
    assert fuzz.next() == previewed
    assert fuzz.state.emitted == 1


def test_preview_queues_multiple_candidates_without_consuming_budget() -> None:
    fuzz = session(values=("a", "b", "c"), max_checks=3)
    first_preview = fuzz.preview()
    second_preview = fuzz.preview()

    assert first_preview is not None
    assert second_preview is not None
    assert first_preview != second_preview
    assert fuzz.state.emitted == 0
    assert fuzz.next() == first_preview
    assert fuzz.next() == second_preview
    assert fuzz.state.emitted == 2


def test_fuzz_session_replays_stored_finding_before_generation() -> None:
    stored = Check(
        invariant_id="inv",
        method_id="get-secret",
        scenario_id="scenario",
        request=(("secret_id", "minimal"),),
        identities=("attacker",),
    )
    database = InMemoryExampleDatabase()
    save_finding_example(database, stored)
    bandit = RecordingBandit()
    fuzz = FuzzSession(
        plan=plan(),
        method=method(),
        invariant=invariant(),
        scenario=scenario(),
        generators={"fuzzing": StaticGenerator(("generated",))},
        policy=bandit,
        guardrail=AllowAll(),
        example_database=database,
    )

    replayed = fuzz.next()

    assert replayed is not None
    assert dict(replayed.request)["secret_id"] == "minimal"
    assert replayed.check_id != stored.check_id
    assert fuzz.state.emitted == 1

    fuzz.record(
        replayed,
        VerdictStatus.PASS,
        observation=observation(replayed),
    )

    assert fuzz.state.emitted == 1
    assert fuzz.state.passes == 1
    assert bandit.updates == []
    assert not fuzz.stopped

    generated = fuzz.next()
    assert generated is not None
    assert dict(generated.request)["secret_id"] == "generated"


def test_replayed_finding_failure_keeps_the_session_alive() -> None:
    stored = Check(
        invariant_id="inv",
        method_id="get-secret",
        scenario_id="scenario",
        request=(("secret_id", "minimal"),),
        identities=("attacker",),
    )
    database = InMemoryExampleDatabase()
    save_finding_example(database, stored)
    fuzz = session(
        values=("generated",),
        example_database=database,
        max_checks=2,
    )

    replayed = fuzz.next()
    assert replayed is not None
    fuzz.record(
        replayed,
        VerdictStatus.FAIL,
        observation=observation(replayed),
    )

    assert fuzz.state.emitted == 1
    assert fuzz.state.failures == 1
    assert not fuzz.stopped
    assert fuzz.next() is not None


def test_fuzz_session_generates_one_batch_per_strategy() -> None:
    generator = StaticGenerator(("a", "b", "c"))
    fuzz = FuzzSession(
        plan=plan(),
        method=method(),
        invariant=invariant(),
        scenario=scenario(),
        generators={"fuzzing": generator},
        policy=GeneratorBandit(seed=0),
        guardrail=AllowAll(),
    )

    assert all(fuzz.next() is not None for _ in range(3))

    assert generator.calls == 1


def test_feedback_aware_generator_receives_bounded_observation_history() -> None:
    generator = FeedbackGenerator()
    fuzz = FuzzSession(
        plan=plan(),
        method=method(),
        invariant=invariant(),
        scenario=scenario(),
        generators={"grammar": generator},
        policy=GeneratorBandit(seed=0),
        guardrail=AllowAll(),
    )
    first = fuzz.next()
    assert first is not None
    first_observation = observation(first)

    fuzz.record(
        first,
        VerdictStatus.UNSCOREABLE,
        grounded=False,
        proximity=1 / 3,
        observation=first_observation,
    )
    second = fuzz.next()

    assert second is not None
    assert dict(second.request)["secret_id"] == "informed-next"
    assert generator.feedback[0] is None
    assert len(generator.feedback) == 2
    feedback = generator.feedback[1]
    assert len(feedback.entries) == 1
    entry = feedback.entries[0]
    assert entry.check == first
    assert entry.observation == first_observation
    assert entry.verdict is VerdictStatus.UNSCOREABLE
    assert entry.grounded is False
    assert entry.proximity == pytest.approx(1 / 3)


def test_feedback_history_is_bounded() -> None:
    generator = FeedbackGenerator()
    fuzz = FuzzSession(
        plan=plan(),
        method=method(),
        invariant=invariant(),
        scenario=scenario(),
        generators={"grammar": generator},
        policy=GeneratorBandit(seed=0),
        guardrail=AllowAll(),
        max_feedback_history=1,
    )
    first = fuzz.next()
    assert first is not None
    first_observation = observation(first, summary="first response")
    fuzz.record(
        first,
        VerdictStatus.UNSCOREABLE,
        grounded=False,
        observation=first_observation,
    )
    second = fuzz.next()
    assert second is not None
    second_observation = observation(second, summary="second response")
    fuzz.record(
        second,
        VerdictStatus.UNSCOREABLE,
        grounded=False,
        observation=second_observation,
    )
    fuzz.next()

    assert len(fuzz.feedback.entries) == 1
    assert fuzz.feedback.entries[0].observation == second_observation


def test_legacy_generator_keeps_one_batch_after_observation() -> None:
    generator = StaticGenerator(("a", "b", "c"))
    fuzz = FuzzSession(
        plan=plan(),
        method=method(),
        invariant=invariant(),
        scenario=scenario(),
        generators={"fuzzing": generator},
        policy=GeneratorBandit(seed=0),
        guardrail=AllowAll(),
    )
    first = fuzz.next()
    assert first is not None

    fuzz.record(first, VerdictStatus.PASS, observation=observation(first))
    assert fuzz.next() is not None
    assert fuzz.next() is not None

    assert generator.calls == 1


def test_fuzz_session_continues_after_llm_model_timeout() -> None:
    fuzz = FuzzSession(
        plan=plan(),
        method=method(),
        invariant=invariant(),
        scenario=scenario(),
        generators={
            "llm": LlmGenerator(FailingModelClient(), TemplateGenerator()),
            "template": StaticGenerator(("next-candidate",)),
        },
        policy=GeneratorBandit(seed=0),
        guardrail=AllowAll(),
    )

    fallback = fuzz.next()
    next_candidate = fuzz.next()

    assert fallback is not None
    assert fallback.generator == "template"
    assert next_candidate is not None
    assert next_candidate.generator == "fuzzing"
    assert next_candidate.request != fallback.request
    assert fuzz.state.emitted == 2


def test_fuzz_session_continues_after_a_failure() -> None:
    fuzz = session()
    check = fuzz.next()

    fuzz.record(check, VerdictStatus.FAIL)

    assert fuzz.state.failures == 1
    assert fuzz.state.reward == 3.0
    assert not fuzz.stopped
    assert fuzz.next() is not None


def test_fuzz_session_stops_on_entropy() -> None:
    fuzz = session(values=("same",), max_repeats=2)

    assert fuzz.next() is not None
    assert fuzz.next() is None
    assert fuzz.stop_reason == "entropy"
    assert fuzz.state.repeated == 2


def test_fuzz_session_skips_guardrail_denied_candidates() -> None:
    fuzz = FuzzSession(
        plan=plan(),
        method=method(),
        invariant=invariant(),
        scenario=scenario(),
        generators={"fuzzing": StaticGenerator(("a", "b"))},
        policy=GeneratorBandit(seed=0),
        guardrail=DenyFirst(),
    )

    first = fuzz.next()
    second = fuzz.next()

    assert first is not None
    assert second is not None
    assert first.request != second.request


def test_fuzz_session_rejects_unrelated_record() -> None:
    fuzz = session()
    check = fuzz.next()
    assert check is not None
    unrelated = check.model_copy(update={"request": (("secret_id", "other"),)})

    with pytest.raises(ValueError, match="candidate returned by next"):
        fuzz.record(unrelated, VerdictStatus.FAIL)


def test_fuzz_session_rejects_unpaired_observation() -> None:
    fuzz = session()
    check = fuzz.next()
    assert check is not None
    unrelated = observation(check.model_copy(update={"check_id": "other"}))

    with pytest.raises(ValueError, match="observation does not belong"):
        fuzz.record(check, VerdictStatus.PASS, observation=unrelated)


def test_fuzz_session_accepts_output_forwarded_record() -> None:
    fuzz = session(values=(None, "b"))
    check = fuzz.next()
    assert check is not None
    forwarded = check.model_copy(update={"request": (("secret_id", "forwarded"),)})

    fuzz.record(forwarded, VerdictStatus.PASS)

    assert fuzz.state.passes == 1
    assert not fuzz.stopped


def test_fuzz_session_accepts_forwarded_missing_field() -> None:
    fuzz = session(values=("a", "b"))
    check = fuzz.next()
    assert check is not None
    forwarded = check.model_copy(
        update={
            "request": (
                ("secret_id", "a"),
                ("folder_id", "folder-forwarded"),
            )
        }
    )

    fuzz.record(forwarded, VerdictStatus.PASS)

    assert fuzz.state.passes == 1
    assert not fuzz.stopped


def test_record_accepts_solver_prefiltered_executed_check() -> None:
    fuzz = session()
    candidate = fuzz.next()
    assert candidate is not None
    solved = candidate.model_copy(
        update={
            "request": (("secret_id", "solver-value"),),
            "generator": "symbolic",
        }
    )

    fuzz.record(
        solved,
        VerdictStatus.FAIL,
        solver_prefiltered=True,
        observation=observation(solved),
    )

    assert fuzz.state.failures == 1
    assert fuzz.state.reward == 3.0
    assert fuzz.feedback.entries[0].check == solved


def test_fuzz_session_does_not_reward_ungrounded_failure() -> None:
    fuzz = session()
    check = fuzz.next()
    assert check is not None

    fuzz.record(check, VerdictStatus.FAIL, grounded=False)

    assert fuzz.state.failures == 0
    assert fuzz.state.unscoreable == 1
    assert fuzz.state.reward == 0.0
    assert not fuzz.stopped


def test_ungrounded_failure_proximity_earns_no_reward_or_bandit_credit() -> None:
    bandit = RecordingBandit()
    fuzz = FuzzSession(
        plan=plan(),
        method=method(),
        invariant=invariant(),
        scenario=scenario(),
        generators={"fuzzing": StaticGenerator(("a",))},
        policy=bandit,
        guardrail=AllowAll(),
    )
    check = fuzz.next()

    fuzz.record(check, VerdictStatus.FAIL, grounded=False, proximity=0.9)

    assert fuzz.state.failures == 0
    assert fuzz.state.unscoreable == 1
    assert fuzz.state.reward == 0.0
    assert fuzz.state.best_proximity == 0.0
    assert bandit.updates == [("fuzzing", 0.0)]
    assert not fuzz.stopped


def test_fuzz_session_rejects_invalid_limits() -> None:
    with pytest.raises(ValueError, match="max_checks"):
        session(max_checks=0)
    with pytest.raises(ValueError, match="max_repeats"):
        session(max_repeats=0)
    with pytest.raises(ValueError, match="max_feedback_history"):
        session(max_feedback_history=0)
    with pytest.raises(ValueError, match="max_enrichments"):
        session(max_enrichments=0)
    with pytest.raises(ValueError, match="max_saturated_candidates"):
        session(max_saturated_candidates=0)


def test_unscoreable_proximity_earns_partial_reward() -> None:
    fuzz = session()
    check = fuzz.next()

    fuzz.record(check, VerdictStatus.UNSCOREABLE, grounded=False, proximity=2 / 3)

    assert fuzz.state.unscoreable == 1
    assert fuzz.state.reward == pytest.approx(2 / 3)
    assert fuzz.state.best_proximity == pytest.approx(2 / 3)
    assert not fuzz.stopped


def test_pass_keeps_verdict_emphasis_and_records_proximity() -> None:
    fuzz = session()
    check = fuzz.next()

    fuzz.record(check, VerdictStatus.PASS, proximity=2 / 3)

    assert fuzz.state.passes == 1
    assert fuzz.state.reward == 1.0
    assert fuzz.state.best_proximity == pytest.approx(2 / 3)


def test_fail_forces_full_proximity() -> None:
    fuzz = session()
    check = fuzz.next()

    fuzz.record(check, VerdictStatus.FAIL, proximity=2 / 3)

    assert fuzz.state.failures == 1
    assert fuzz.state.reward == 3.0
    assert fuzz.state.best_proximity == 1.0
    assert not fuzz.stopped


def test_sessions_share_bandit_across_goal_namespaces() -> None:
    from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, changed, denied

    def formal_invariant(effect) -> InvariantProjection:
        return InvariantProjection(
            invariant_id="inv",
            norm_id="norm",
            statement="formal",
            severity=Severity.HIGH,
            norm_fact=Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(Atom(value="norm:1"), effect),
            ),
        )

    shared = GeneratorBandit(seed=3)
    denial = FuzzSession(
        plan=plan(),
        method=method(),
        invariant=formal_invariant(denied(Atom(value="action:get"))),
        scenario=scenario(),
        generators={"fuzzing": StaticGenerator(("a",))},
        policy=shared,
        guardrail=AllowAll(),
    )
    tamper = FuzzSession(
        plan=plan(),
        method=method(),
        invariant=formal_invariant(changed(Atom(value="resource:x"), Atom(value="f"))),
        scenario=scenario(),
        generators={"fuzzing": StaticGenerator(("a",))},
        policy=shared,
        guardrail=AllowAll(),
    )

    denial_check = denial.next()
    tamper_check = tamper.next()
    assert denial_check is not None
    assert tamper_check is not None
    denial.record(denial_check, VerdictStatus.FAIL, proximity=1.0)
    tamper.record(
        tamper_check, VerdictStatus.UNSCOREABLE, grounded=False, proximity=0.0
    )

    assert denial.state.reward == 3.0
    assert tamper.state.reward == 0.0


def _signature_check(identities: tuple[str, ...] = ("attacker",)) -> Check:
    return Check(
        invariant_id="inv",
        method_id="get-secret",
        scenario_id="scenario",
        request=(("secret_id", "secret-victim"),),
        identities=identities,
    )


def test_signature_discriminates_check_identities() -> None:
    base = scenario()

    victim = _signature_check(("victim",))
    attacker = _signature_check(("attacker",))

    assert _signature(victim, base) != _signature(attacker, base)
    assert _signature(victim, base) == _signature(victim, base)


def test_signature_discriminates_stand_principals() -> None:
    base = scenario()
    victim = base.model_copy(
        update={
            "stand": StandState(
                principals=(PrincipalRef(principal_id="victim", principal_type="user"),)
            )
        }
    )
    attacker = base.model_copy(
        update={
            "stand": StandState(
                principals=(
                    PrincipalRef(principal_id="attacker", principal_type="user"),
                )
            )
        }
    )
    check = _signature_check()

    assert _signature(check, victim) != _signature(check, attacker)
    assert _signature(check, victim) == _signature(check, victim)


def test_signature_discriminates_stand_bindings() -> None:
    base = scenario()
    viewer = base.model_copy(
        update={
            "stand": StandState(
                bindings=(BindingRef(principal_id="attacker", role="viewer"),)
            )
        }
    )
    editor = base.model_copy(
        update={
            "stand": StandState(
                bindings=(BindingRef(principal_id="attacker", role="editor"),)
            )
        }
    )
    check = _signature_check()

    assert _signature(check, viewer) != _signature(check, editor)
    assert _signature(check, viewer) == _signature(check, viewer)
