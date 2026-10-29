from __future__ import annotations

import pytest

from cloud_dast.contracts.plan import InvariantProjection, VerificationPlan
from cloud_dast.model import (
    Check,
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    ResourceRef,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, reached
from cloud_dast_fuzzing import (
    GoalPayloadGenerator,
)
from cloud_dast_fuzzing.corpus import PayloadCorpusCompiler
from cloud_dast_fuzzing.strategies.goal_payload import (
    PROBE_MARKER_PLACEHOLDER,
)
from cloud_dast_fuzzing.strategies.grammar import GrammarGenerator

TRAVERSAL_TOKENS = (
    "../",
    "..\\",
    "..%2f",
    "..%5c",
    "%2e%2e%2f",
    "%2e%2e%5c",
    "%252e%252e%252f",
)


def _grammar(seed_generator):
    return GrammarGenerator(
        seed_generator,
        payload_compiler=PayloadCorpusCompiler(),
    )


class StaticSeedGenerator:
    def generate(
        self,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
        *,
        feedback=None,
    ) -> tuple[Check, ...]:
        del feedback
        return (
            Check(
                invariant_id=plan.invariant_id,
                method_id=plan.method_id,
                scenario_id=scenario.scenario_id,
                request=(
                    ("zork", "seed-value"),
                    ("container_id", "live-container"),
                    ("mode", "fast"),
                    ("tags", ("seed-tag",)),
                    ("left", "choice"),
                ),
                identities=("attacker",),
            ),
        )


def _method() -> MethodSpec:
    return MethodSpec(
        method_id="example.Write",
        service="example",
        name="Write",
        layer=EndpointLayer.PUBLIC,
        resource_types=frozenset({"container"}),
        fields=(
            FieldSpec(name="zork", type="string"),
            FieldSpec(name="container_id", type="string"),
            FieldSpec(name="mode", type="string", enum_values=("fast", "slow")),
            FieldSpec(name="tags", type="string", repeated=True),
            FieldSpec(name="left", type="string", oneof="choice"),
            FieldSpec(name="right", type="string", oneof="choice"),
        ),
    )


def _scenario() -> ScenarioPosition:
    return ScenarioPosition(
        scenario_id="scenario",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.SAME_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PUBLIC,
            resource_state="existing",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(
            resources=(
                ResourceRef(
                    service="example",
                    resource_type="container",
                    resource_id="live-container",
                ),
            ),
        ),
    )


def _invariant(method: MethodSpec) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="invariant",
        norm_id="norm",
        statement="filesystem sink must not be reached",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(
                Atom(value="norm"),
                reached(Atom(value=method.method_id), Atom(value="dast-marker")),
            ),
        ),
    )


def _binding(
    *,
    sink_types: tuple[tuple[str, str], ...],
    resource_params: tuple[str, ...] = ("container_id",),
) -> tuple[MethodSpec, VerificationPlan, InvariantProjection, ScenarioPosition]:
    method = _method()
    invariant = _invariant(method)
    plan = VerificationPlan(
        plan_id="plan",
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id="scenario",
        probe_fields=("zork",),
        resource_params=resource_params,
        sink_types=sink_types,
    )
    return method, plan, invariant, _scenario()


def test_grammar_generator_adds_deterministic_filesystem_paths() -> None:
    method, plan, invariant, scenario = _binding(
        sink_types=(("zork", "filesystem"),),
    )

    checks = _grammar(StaticSeedGenerator()).generate(
        plan,
        method,
        invariant,
        scenario,
    )
    repeated = _grammar(StaticSeedGenerator()).generate(
        plan,
        method,
        invariant,
        scenario,
    )
    values = tuple(dict(check.request)["zork"] for check in checks)

    assert checks == repeated
    assert values
    assert all(value.count(PROBE_MARKER_PLACEHOLDER) == 1 for value in values)
    assert all("/" in value or "\\" in value for value in values)
    assert any(any(token in value for token in TRAVERSAL_TOKENS) for value in values)


def test_filesystem_paths_use_bounded_versioned_corpus_grammar() -> None:
    method, plan, invariant, scenario = _binding(
        sink_types=(("zork", "filesystem"),),
    )

    checks = _grammar(StaticSeedGenerator()).generate(
        plan,
        method,
        invariant,
        scenario,
    )

    assert checks
    for check in checks:
        value = dict(check.request)["zork"].replace(PROBE_MARKER_PLACEHOLDER, "")
        separator = next(index for index, char in enumerate(value) if char in "/\\")
        assert value[:separator].endswith(".pdf")
        assert any(token in value for token in TRAVERSAL_TOKENS)


def test_filesystem_candidates_remain_schema_valid_and_preserve_object_refs() -> None:
    method, plan, invariant, scenario = _binding(
        sink_types=(("zork", "filesystem"),),
    )

    checks = GoalPayloadGenerator(_grammar(StaticSeedGenerator())).generate(
        plan,
        method,
        invariant,
        scenario,
    )

    assert checks
    for check in checks:
        request = dict(check.request)
        assert set(request) == {
            "zork",
            "container_id",
            "mode",
            "tags",
            "left",
        }
        assert "left" in request
        assert "right" not in request
        assert request["container_id"] == "live-container"
        assert request["mode"] in {"fast", "slow"}
        assert isinstance(request["tags"], tuple)
        assert request["zork"].count(check.probe_marker) == 1


def test_filesystem_operator_respects_field_schema() -> None:
    method, plan, invariant, scenario = _binding(
        sink_types=(("mode", "filesystem"),),
    )

    checks = _grammar(StaticSeedGenerator()).generate(
        plan,
        method,
        invariant,
        scenario,
    )

    assert checks
    assert all(dict(check.request)["mode"] in {"fast", "slow"} for check in checks)


@pytest.mark.parametrize(
    "sink_types",
    [
        (),
        (("zork", "command"),),
    ],
)
def test_traversal_candidates_require_filesystem_sink_type(
    sink_types: tuple[tuple[str, str], ...],
) -> None:
    method, plan, invariant, scenario = _binding(sink_types=sink_types)

    checks = _grammar(StaticSeedGenerator()).generate(
        plan,
        method,
        invariant,
        scenario,
    )
    values = tuple(dict(check.request)["zork"] for check in checks)

    assert values
    assert all("../" not in value for value in values)
