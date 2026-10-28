"""Entropy-point seed enrichment and its audit boundary."""

from __future__ import annotations

from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.model import (
    AccessOutcome,
    Check,
    EndpointLayer,
    FieldSpec,
    HttpStatus,
    MethodSpec,
    Observation,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
    VerdictStatus,
)
from cloud_dast.ports import ModelRequest, ModelResponse
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast.verification.promotion import (
    PromotionPolicy,
)
from cloud_dast_fuzzing import FuzzSession
from cloud_dast_fuzzing.corpus import PayloadCorpusStore
from cloud_dast_fuzzing.corpus.enrichment import SeedEnrichmentConsultant
from cloud_dast_fuzzing.strategies.selector import GeneratorBandit
from cloud_dast_llm.consultation import ConsultationDispatcher


class AllowAll:
    def allows(self, check: Check) -> bool:
        return True


class SaturationGenerator:
    def __init__(self) -> None:
        self.calls = 0

    def generate(
        self,
        plan,
        method,
        invariant,
        scenario,
        *,
        feedback=None,
    ) -> tuple[Check, ...]:
        del feedback
        self.calls += 1
        if self.calls == 1:
            return tuple(
                Check(
                    invariant_id=invariant.invariant_id,
                    method_id=method.method_id,
                    scenario_id=scenario.scenario_id,
                    request=((method.fields[0].name, value),),
                    identities=("attacker",),
                    generator="grammar",
                    probe_marker=(
                        f"marker-{value}" if value != "new-terminal" else None
                    ),
                )
                for value in ("same", "same-2")
            )
        value = "new-terminal"
        return (
            Check(
                invariant_id=invariant.invariant_id,
                method_id=method.method_id,
                scenario_id=scenario.scenario_id,
                request=((method.fields[0].name, value),),
                identities=("attacker",),
                generator="grammar",
            ),
        )


class SeedEnrichmentModelClient:
    def __init__(self) -> None:
        self.requests: list[ModelRequest] = []

    def complete(
        self,
        request: ModelRequest,
        *,
        response_type=None,
    ) -> ModelResponse:
        self.requests.append(request)
        return ModelResponse(
            structured={
                "context": "proposal",
                "productions": [],
                "slot_alternatives": [
                    {
                        "production_id": "sql-ansi",
                        "slot_name": "terminator",
                        "alternatives": ["\n"],
                    }
                ],
                "uncertainties": [],
            },
            model_id="seed-model",
            input_tokens=100,
            cached_input_tokens=10,
            output_tokens=20,
        )


def _method() -> MethodSpec:
    return MethodSpec(
        method_id="get-secret",
        service="service",
        name="GetSecret",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="secret_id", type="string"),),
    )


def _scenario() -> ScenarioPosition:
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


def _plan() -> VerificationPlan:
    return VerificationPlan(
        plan_id="plan",
        invariant_id="inv",
        method_id="get-secret",
        scenario_id="scenario",
        sink_types=(("secret_id", "interpreter"),),
        grammar_dialects=(("secret_id", "ansi"),),
    )


def _invariant() -> InvariantProjection:
    return InvariantProjection(
        invariant_id="inv",
        norm_id="norm",
        statement="norm",
        severity=Severity.HIGH,
    )


def _observation(
    check: Check,
    value: str,
    *,
    marker: str | None = None,
) -> Observation:
    response_tree = (
        (("error", f"prefix {marker}"),) if marker is not None else (("result", value),)
    )
    return Observation(
        check_id=check.check_id,
        scenario_id=check.scenario_id,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="response",
        transport_status=HttpStatus(code=200),
        response_tree=response_tree,
        duration_ms=10.0,
        probe_marker=marker,
    )


def test_entropy_enrichment_grows_corpus_and_resumes_campaign() -> None:
    client = SeedEnrichmentModelClient()
    store = PayloadCorpusStore()
    consultant = SeedEnrichmentConsultant(
        ConsultationDispatcher(client),
        store=store,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    generator = SaturationGenerator()
    fuzz = FuzzSession(
        plan=_plan(),
        method=_method(),
        invariant=_invariant(),
        scenario=_scenario(),
        generators={"grammar": generator},
        policy=GeneratorBandit(seed=0),
        guardrail=AllowAll(),
        max_checks=3,
        max_repeats=2,
        seed_enrichment=consultant,
    )

    first = fuzz.next()
    assert first is not None
    fuzz.record(
        first,
        VerdictStatus.PASS,
        observation=_observation(first, "one", marker=first.probe_marker),
    )
    second = fuzz.next()
    assert second is not None
    fuzz.record(
        second,
        VerdictStatus.PASS,
        observation=_observation(second, "two", marker=second.probe_marker),
    )

    resumed = fuzz.next()

    assert resumed is not None
    assert dict(resumed.request)["secret_id"] == "new-terminal"
    assert not fuzz.stopped
    assert fuzz.stop_reason is None
    assert fuzz.state.entropy_events == 1
    assert fuzz.state.enrichments == 1
    assert store.corpus.corpus_version == "3"
    production = next(
        item for item in store.corpus.productions if item.production_id == "sql-ansi"
    )
    slot = next(item for item in production.slots if item.name == "terminator")
    assert "\n" in slot.alternatives

    assert len(client.requests) == 1
    context = client.requests[0].context
    history = context["saturated_history"]
    assert len(history["candidates"]) == 2
    assert history["sink_types"] == [{"field": "secret_id", "sink_type": "interpreter"}]
    assert history["schema"][0]["name"] == "secret_id"
    assert history["diff_pairs"][0]["changed_response_paths"] == ("error",)
    assert any(signal["kind"] == "marker_echo" for signal in history["witness_signals"])
    assert context["graph"]

    audit = store.audit_trail[0]
    assert audit.status == "promoted"
    assert audit.model_version == "seed-model"
    assert audit.prompt_hash
    assert audit.history_digest
    assert audit.proposal_digest
    assert audit.promoted_slot_alternatives == ("sql-ansi.terminator",)
    assert audit.delta is not None


def test_failed_enrichment_leaves_entropy_stop_and_audits_the_attempt() -> None:
    store = PayloadCorpusStore()
    consultant = SeedEnrichmentConsultant(
        ConsultationDispatcher(SeedEnrichmentModelClient()),
        store=store,
        promotion_policy=PromotionPolicy(enabled=False),
    )
    fuzz = FuzzSession(
        plan=_plan(),
        method=_method(),
        invariant=_invariant(),
        scenario=_scenario(),
        generators={"grammar": SaturationGenerator()},
        policy=GeneratorBandit(seed=0),
        guardrail=AllowAll(),
        max_checks=3,
        max_repeats=1,
        seed_enrichment=consultant,
    )
    first = fuzz.next()
    assert first is not None
    fuzz.record(first, VerdictStatus.PASS, observation=_observation(first, "one"))
    second = fuzz.next()
    assert second is not None
    fuzz.record(second, VerdictStatus.PASS, observation=_observation(second, "two"))

    assert fuzz.next() is None

    assert fuzz.stop_reason == "entropy"
    assert fuzz.state.enrichments == 1
    assert store.corpus.corpus_version == "2"
    audit = store.audit_trail[0]
    assert audit.status == "parked"
    assert audit.reason == "payload corpus promotion is disabled"
