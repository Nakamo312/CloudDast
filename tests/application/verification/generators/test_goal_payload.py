from __future__ import annotations

import pytest

from cloud_dast.contracts.plan import InvariantProjection, VerificationPlan
from cloud_dast.infrastructure.runtime import MemoryEvidenceChannel
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
from cloud_dast.ports import EvidenceEvent
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    allowed,
    external_call,
    reached,
)
from cloud_dast.runtime import oob
from cloud_dast.runtime.candidates.feedback import (
    ExecutionFeedback,
    ExecutionFeedbackEntry,
)
from cloud_dast.runtime.execution.checks import run_check
from cloud_dast.verification.oracles import oob as verification_oob
from cloud_dast_fuzzing import GoalPayloadGenerator
from cloud_dast_fuzzing.corpus import PayloadCorpusStore


class _StaticGenerator:
    def generate(
        self,
        plan,
        method,
        invariant,
        scenario,
        *,
        feedback=None,
    ) -> tuple[Check, ...]:
        del plan, invariant, feedback
        return (
            Check(
                invariant_id="inv",
                method_id=method.method_id,
                scenario_id=scenario.scenario_id,
                request=tuple((field.name, "") for field in method.fields),
                identities=("attacker",),
            ),
        )


class _StaticUrls:
    def url_for(self, marker: str) -> str:
        return f"https://collaborator.test/{marker}"


class _PlaceholderGenerator:
    def __init__(
        self,
        request: tuple[tuple[str, object], ...],
        *,
        generator: str = "llm",
    ) -> None:
        self._request = request
        self._generator = generator

    def generate(
        self,
        plan,
        method,
        invariant,
        scenario,
        *,
        feedback=None,
    ) -> tuple[Check, ...]:
        del plan, invariant, feedback
        return (
            Check(
                invariant_id="inv",
                method_id=method.method_id,
                scenario_id=scenario.scenario_id,
                request=self._request,
                identities=("attacker",),
                generator=self._generator,
            ),
        )


class _FeedbackGenerator:
    uses_feedback = True

    def __init__(self) -> None:
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
        del plan, invariant
        self.feedback.append(feedback)
        return (
            Check(
                invariant_id="inv",
                method_id=method.method_id,
                scenario_id=scenario.scenario_id,
                request=tuple((field.name, "") for field in method.fields),
                identities=("attacker",),
            ),
        )


def _method() -> MethodSpec:
    return MethodSpec(
        method_id="render",
        service="template-service",
        name="Render",
        layer=EndpointLayer.PRIVATE,
        fields=(
            FieldSpec(name="resource_id", type="string", required=True),
            FieldSpec(name="template", type="string"),
            FieldSpec(name="callback_url", type="url"),
            FieldSpec(name="labels", type="string", repeated=True),
        ),
    )


def _invariant(effect) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="inv",
        norm_id="threat",
        statement="QDL norm",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm:inv"), effect),
        ),
    )


def _binding(scenario_position):
    method = _method()
    plan = VerificationPlan(
        plan_id="plan",
        invariant_id="inv",
        method_id=method.method_id,
        scenario_id=scenario_position.scenario_id,
    )
    return method, plan, scenario_position


def test_goal_payload_generator_injects_qdl_marker(scenario_position) -> None:
    method, plan, scenario = _binding(scenario_position)
    plan = plan.model_copy(update={"probe_fields": ("template",)})
    effect = reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))

    check = GoalPayloadGenerator(
        _StaticGenerator(), payload_corpus=PayloadCorpusStore()
    ).generate(plan, method, _invariant(effect), scenario)[0]

    assert check.probe_marker is not None
    assert check.probe_marker.startswith("dast_marker_42_")
    assert dict(check.request)["template"] == check.probe_marker


def test_goal_payload_generator_keeps_unknown_sink_marker_undecorated(
    scenario_position,
) -> None:
    """An unknown sink format must not be mutated as a quoted canary.

    Without a ``reaches``/``is(Sink, ...)``/``format``/``dialect`` fact the
    engine has no grounded grammar.  The bare marker stays the structural
    probe; quoting it would guess a quoted-literal sink class the QDL graph
    never declared.
    """
    method, plan, scenario = _binding(scenario_position)
    plan = plan.model_copy(update={"probe_fields": ("template",)})
    effect = reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))

    check = GoalPayloadGenerator(_StaticGenerator()).generate(
        plan, method, _invariant(effect), scenario
    )[0]

    value = dict(check.request)["template"]
    assert value == check.probe_marker
    assert not value.startswith("'")
    assert not value.endswith("'")
    assert check.probe_marker is not None and check.probe_marker in value


def test_goal_payload_generator_preserves_model_derived_marker_grammar(
    scenario_position,
) -> None:
    """A grammar strategy positions the canary; the engine only fills it."""

    method, plan, scenario = _binding(scenario_position)
    plan = plan.model_copy(update={"probe_fields": ("template",)})
    effect = reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))

    check = GoalPayloadGenerator(
        _PlaceholderGenerator(
            (("template", "carrier/{probe_marker}"),),
        )
    ).generate(plan, method, _invariant(effect), scenario)[0]

    assert check.probe_marker is not None
    assert dict(check.request)["template"] == f"carrier/{check.probe_marker}"


@pytest.mark.parametrize(
    (
        "sink_types",
        "grammar_dialects",
        "expected_prefix",
        "expected_suffix",
    ),
    [
        ((("template", "interpreter"),), (("template", "ansi"),), "'", "'--"),
        ((("template", "filesystem"),), (("template", "posix"),), ".pdf/../", ""),
        ((("template", "command"),), (("template", "posix"),), "; printf ", ""),
    ],
)
def test_goal_payload_generator_compiles_sink_specific_marker_grammar(
    scenario_position,
    sink_types: tuple[tuple[str, str], ...],
    grammar_dialects: tuple[tuple[str, str], ...],
    expected_prefix: str,
    expected_suffix: str,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    plan = plan.model_copy(
        update={
            "probe_fields": ("template",),
            "sink_types": sink_types,
            "grammar_dialects": grammar_dialects,
        }
    )
    effect = reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))

    check = GoalPayloadGenerator(
        _StaticGenerator(), payload_corpus=PayloadCorpusStore()
    ).generate(plan, method, _invariant(effect), scenario)[0]

    assert check.probe_marker is not None
    assert dict(check.request)["template"] == (
        f"{expected_prefix}{check.probe_marker}{expected_suffix}"
    )


def test_goal_payload_generator_forwards_execution_feedback(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    generator = _FeedbackGenerator()
    check = Check(
        invariant_id="inv",
        method_id=method.method_id,
        scenario_id=scenario.scenario_id,
        request=(("resource_id", "candidate"),),
        identities=("attacker",),
    )
    feedback = ExecutionFeedback(
        entries=(
            ExecutionFeedbackEntry(
                check=check,
                observation=Observation(
                    check_id=check.check_id,
                    scenario_id=scenario.scenario_id,
                    observed_outcome=AccessOutcome.ERROR,
                    response_summary="resource not found",
                ),
                verdict=VerdictStatus.UNSCOREABLE,
                grounded=False,
            ),
        )
    )

    GoalPayloadGenerator(generator).generate(
        plan,
        method,
        _invariant(allowed(Atom(value=method.method_id))),
        scenario,
        feedback=feedback,
    )

    assert generator.feedback == [feedback]


def test_goal_payload_wrapper_reports_inner_feedback_capability() -> None:
    assert GoalPayloadGenerator(_FeedbackGenerator()).uses_feedback is True
    assert GoalPayloadGenerator(_StaticGenerator()).uses_feedback is False


def test_goal_payload_generator_drops_grammar_candidate_without_placeholder(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    effect = reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))

    checks = GoalPayloadGenerator(
        _PlaceholderGenerator(
            (("name", "carrier-without-runtime-token"),),
            generator="grammar",
        )
    ).generate(plan, method, _invariant(effect), scenario)

    assert checks == ()


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("scope", "resource:api_key{probe_marker}"),
        ("url", "https://example.com/callback/{oob_url}"),
    ],
)
def test_goal_payload_generator_drops_non_marker_placeholder_candidate(
    scenario_position,
    field_name: str,
    value: str,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    method = method.model_copy(
        update={
            "fields": (
                FieldSpec(name="resource_id", type="string", required=True),
                FieldSpec(name="scope", type="string"),
                FieldSpec(name="url", type="url"),
            )
        }
    )
    effect = allowed(Atom(value=method.method_id))

    checks = GoalPayloadGenerator(
        _PlaceholderGenerator(((field_name, value),))
    ).generate(plan, method, _invariant(effect), scenario)

    assert checks == ()


def test_goal_payload_generator_drops_placeholder_candidate_without_norm_fact(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    invariant = InvariantProjection(
        invariant_id="inv",
        norm_id="threat",
        statement="legacy-only norm",
        severity=Severity.HIGH,
    )

    checks = GoalPayloadGenerator(
        _PlaceholderGenerator((("scope", "resource:api_key{probe_marker}"),))
    ).generate(plan, method, invariant, scenario)

    assert checks == ()


def test_goal_payload_generator_rejects_placeholder_outside_probe_fields(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    plan = plan.model_copy(update={"probe_fields": ("template",)})
    effect = reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))

    checks = GoalPayloadGenerator(
        _PlaceholderGenerator(
            (("name", "carrier/{probe_marker}"),),
            generator="grammar",
        )
    ).generate(plan, method, _invariant(effect), scenario)

    assert checks == ()


def test_goal_payload_generator_injects_oob_url(scenario_position) -> None:
    method, plan, scenario = _binding(scenario_position)
    effect = external_call(Atom(value=method.method_id), Atom(value="marker-123"))

    check = GoalPayloadGenerator(
        _StaticGenerator(),
        oob_urls=_StaticUrls(),
    ).generate(plan, method, _invariant(effect), scenario)[0]

    assert check.probe_marker is not None
    assert check.probe_marker.startswith("marker_123_")
    assert dict(check.request)["callback_url"] == (
        f"https://collaborator.test/{check.probe_marker}"
    )


def test_goal_payload_generator_preserves_model_derived_oob_url_grammar(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    effect = external_call(Atom(value=method.method_id), Atom(value="marker-123"))

    check = GoalPayloadGenerator(
        _PlaceholderGenerator((("callback_url", "{oob_url}"),)),
        oob_urls=_StaticUrls(),
    ).generate(plan, method, _invariant(effect), scenario)[0]

    assert check.probe_marker is not None
    assert dict(check.request)["callback_url"] == (
        f"https://collaborator.test/{check.probe_marker}"
    )


def test_goal_payload_oob_fallback_uses_schema_type_not_field_names(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    method = method.model_copy(
        update={
            "fields": (
                FieldSpec(name="resource_id", type="string", required=True),
                FieldSpec(name="callback_url", type="string"),
                FieldSpec(name="destination", type="url"),
            )
        }
    )
    effect = external_call(Atom(value=method.method_id), Atom(value="marker-123"))

    check = GoalPayloadGenerator(_StaticGenerator(), oob_urls=_StaticUrls()).generate(
        plan, method, _invariant(effect), scenario
    )[0]

    assert check.probe_marker is not None
    assert dict(check.request)["destination"] == (
        f"https://collaborator.test/{check.probe_marker}"
    )
    assert dict(check.request)["callback_url"] == ""


def test_goal_payload_oob_uses_explicitly_grounded_string_carrier(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    method = method.model_copy(
        update={
            "fields": (FieldSpec(name="callback_url", type="string", required=True),),
        }
    )
    plan = plan.model_copy(update={"probe_fields": ("callback_url",)})
    effect = external_call(Atom(value=method.method_id), Atom(value="marker-123"))

    check = GoalPayloadGenerator(_StaticGenerator(), oob_urls=_StaticUrls()).generate(
        plan,
        method,
        _invariant(effect),
        scenario,
    )[0]

    assert check.probe_marker is not None
    assert dict(check.request)["callback_url"] == (
        f"https://collaborator.test/{check.probe_marker}"
    )


def test_goal_payload_preserves_oob_grammar_in_grounded_string_carrier(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    method = method.model_copy(
        update={
            "fields": (FieldSpec(name="callback_url", type="string", required=True),),
        }
    )
    plan = plan.model_copy(update={"probe_fields": ("callback_url",)})
    effect = external_call(Atom(value=method.method_id), Atom(value="marker-123"))

    check = GoalPayloadGenerator(
        _PlaceholderGenerator(
            (("callback_url", "{oob_url}"),),
            generator="grammar",
        ),
        oob_urls=_StaticUrls(),
    ).generate(plan, method, _invariant(effect), scenario)[0]

    assert check.probe_marker is not None
    assert dict(check.request)["callback_url"] == (
        f"https://collaborator.test/{check.probe_marker}"
    )


def test_goal_payload_oob_marker_reaches_observation_and_oracle(
    scenario_position,
) -> None:
    """An OOB candidate must stay attributable through execution and oracle."""

    method, plan, scenario = _binding(scenario_position)
    method = method.model_copy(
        update={
            "fields": (FieldSpec(name="callback_url", type="string", required=True),),
        }
    )
    plan = plan.model_copy(update={"probe_fields": ("callback_url",)})
    effect = external_call(Atom(value=method.method_id), Atom(value="marker-123"))
    invariant = _invariant(effect)
    check = GoalPayloadGenerator(_StaticGenerator(), oob_urls=_StaticUrls()).generate(
        plan,
        method,
        invariant,
        scenario,
    )[0]
    assert check.probe_marker is not None

    def target(executed: Check) -> Observation:
        return Observation(
            check_id=executed.check_id,
            scenario_id=executed.scenario_id,
            observed_outcome=AccessOutcome.ALLOWED,
            response_summary="OK",
        )

    observation = run_check(check, target)
    unmarked = run_check(
        check.model_copy(update={"check_id": "unmarked", "probe_marker": None}),
        target,
    )
    assert observation.probe_marker == check.probe_marker
    assert unmarked.probe_marker is None

    store = MemoryEvidenceChannel()
    store.set_ready(True)
    oracle = oob.Coordinator(store, verification_oob.Oracle(), wait_seconds=0.0)
    without_marker = oracle.evaluate_policy(invariant, (unmarked,))
    assert without_marker.status is VerdictStatus.UNSCOREABLE
    assert without_marker.grounded is False

    store.record(
        EvidenceEvent(
            channel="oob", correlation_id=check.probe_marker, source="127.0.0.1"
        )
    )
    with_callback = oracle.evaluate_policy(invariant, (observation,))
    assert with_callback.status is VerdictStatus.FAIL
    assert with_callback.grounded is True
    assert observation.observation_id in with_callback.evidence_refs


def test_goal_payload_generator_makes_probe_markers_unique(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    effect = external_call(Atom(value=method.method_id), Atom(value="marker-123"))
    generator = GoalPayloadGenerator(
        _StaticGenerator(),
        oob_urls=_StaticUrls(),
    )
    invariant = _invariant(effect)

    first = generator.generate(plan, method, invariant, scenario)[0]
    second = generator.generate(plan, method, invariant, scenario)[0]

    assert first.probe_marker is not None
    assert second.probe_marker is not None
    assert first.probe_marker != second.probe_marker


def test_goal_payload_generator_keeps_uninjectable_probe_leg_undecorated(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    method = method.model_copy(update={"fields": (method.fields[0],)})
    effect = reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))

    checks = GoalPayloadGenerator(_StaticGenerator()).generate(
        plan,
        method,
        _invariant(effect),
        scenario,
    )

    assert len(checks) == 1
    assert checks[0].probe_marker is None


def test_goal_payload_generator_without_norm_fact_is_inert(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    invariant = InvariantProjection(
        invariant_id="inv",
        norm_id="threat",
        statement="legacy-only norm",
        severity=Severity.HIGH,
    )

    checks = GoalPayloadGenerator(_StaticGenerator()).generate(
        plan, method, invariant, scenario
    )

    assert checks[0].request == tuple((field.name, "") for field in method.fields)


def test_goal_payload_generator_separates_object_ref_from_probe_carrier(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    method = method.model_copy(update={"resource_types": frozenset({"lockbox.secret"})})
    plan = plan.model_copy(
        update={
            "probe_fields": ("template",),
            "resource_params": ("resource_id",),
            "resource_types": (("resource_id", "lockbox.secret"),),
        }
    )
    effect = reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))

    check = GoalPayloadGenerator(_StaticGenerator()).generate(
        plan,
        method,
        _invariant(effect),
        scenario,
    )[0]

    # The object reference keeps its live fixture value; the marker moves to
    # the free-text carrier instead of producing a resource-not-found echo.
    assert dict(check.request)["resource_id"] == "secret-victim"
    assert dict(check.request)["template"] == check.probe_marker


def test_goal_payload_object_ref_gets_fixture_and_text_carries_marker(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    method = method.model_copy(
        update={
            "resource_types": frozenset({"lockbox.secret"}),
            "fields": (
                FieldSpec(name="opaque_handle", type="string", required=True),
                FieldSpec(name="note", type="string"),
            ),
        }
    )
    plan = plan.model_copy(
        update={
            "probe_fields": ("note",),
            "resource_params": ("opaque_handle",),
            "resource_types": (("opaque_handle", "lockbox.secret"),),
        }
    )
    effect = reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))

    check = GoalPayloadGenerator(_StaticGenerator()).generate(
        plan,
        method,
        _invariant(effect),
        scenario,
    )[0]

    values = dict(check.request)
    assert values["opaque_handle"] == "secret-victim"
    assert values["note"] == check.probe_marker


def test_goal_payload_rejects_placeholder_in_object_ref(scenario_position) -> None:
    method, plan, scenario = _binding(scenario_position)
    method = method.model_copy(
        update={
            "fields": (
                FieldSpec(name="opaque_handle", type="string", required=True),
                FieldSpec(name="note", type="string"),
            )
        }
    )
    plan = plan.model_copy(
        update={
            "probe_fields": ("opaque_handle",),
            "resource_params": ("opaque_handle",),
        }
    )
    effect = reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))

    checks = GoalPayloadGenerator(
        _PlaceholderGenerator((("opaque_handle", "{probe_marker}"),))
    ).generate(plan, method, _invariant(effect), scenario)

    assert checks == ()


def test_goal_payload_marker_does_not_fallback_to_schema(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    method = method.model_copy(
        update={
            "fields": (
                FieldSpec(name="opaque_identifier", type="string", required=True),
                FieldSpec(name="opaque_carrier", type="string"),
            )
        }
    )
    effect = reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))

    checks = GoalPayloadGenerator(_StaticGenerator()).generate(
        plan, method, _invariant(effect), scenario
    )

    assert len(checks) == 1
    assert checks[0].probe_marker is None
    assert dict(checks[0].request)["opaque_carrier"] == ""
    assert dict(checks[0].request)["opaque_identifier"] == ""


def test_goal_payload_oob_fallback_never_uses_arbitrary_text_or_id_fields(
    scenario_position,
) -> None:
    method, plan, scenario = _binding(scenario_position)
    method = method.model_copy(
        update={
            "fields": (
                FieldSpec(name="resource_id", type="string", required=True),
                FieldSpec(name="arbitrary_text", type="string"),
            )
        }
    )
    effect = external_call(Atom(value=method.method_id), Atom(value="marker-123"))

    checks = GoalPayloadGenerator(_StaticGenerator(), oob_urls=_StaticUrls()).generate(
        plan, method, _invariant(effect), scenario
    )

    assert len(checks) == 1
    assert checks[0].probe_marker is None
    assert dict(checks[0].request) == {
        "resource_id": "",
        "arbitrary_text": "",
    }


def test_goal_payload_generator_does_not_wrap_oob_canary_url(
    scenario_position,
) -> None:
    """A full OOB URL stays unquoted; a bare marker never fills a URL field."""
    method, plan, scenario = _binding(scenario_position)
    effect = external_call(Atom(value=method.method_id), Atom(value="marker-123"))

    with_factory = GoalPayloadGenerator(
        _StaticGenerator(),
        oob_urls=_StaticUrls(),
    ).generate(plan, method, _invariant(effect), scenario)
    without_factory = GoalPayloadGenerator(_StaticGenerator()).generate(
        plan, method, _invariant(effect), scenario
    )

    assert with_factory and without_factory
    with_url, without_url = with_factory[0], without_factory[0]

    assert with_url.probe_marker is not None
    assert dict(with_url.request)["callback_url"] == (
        f"https://collaborator.test/{with_url.probe_marker}"
    )
    assert without_url.probe_marker is None
    assert dict(without_url.request)["callback_url"] == ""


def test_goal_payload_generator_applies_plan_seed_hints(scenario_position) -> None:
    method, plan, scenario = _binding(scenario_position)
    method = method.model_copy(
        update={
            "fields": (
                FieldSpec(name="resource_id", type="string", required=True),
                FieldSpec(name="template", type="string"),
                FieldSpec(name="payload_spec", type="message"),
                FieldSpec(name="payload_spec.key", type="string"),
            )
        }
    )
    plan = plan.model_copy(
        update={
            "seed_hints": (
                ("resource_id", "setup_value"),
                ("payload_spec", "setup_skip"),
            )
        }
    )

    effect = reached(Atom(value=method.method_id), Atom(value="dast-marker-42"))
    check = GoalPayloadGenerator(_StaticGenerator()).generate(
        plan, method, _invariant(effect), scenario
    )[0]

    values = dict(check.request)
    assert values["resource_id"] == "dast-fixture-resource_id"
    assert "payload_spec" not in values
    assert "payload_spec.key" not in values
