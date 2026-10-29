from __future__ import annotations

import json
import pickle
import pickletools
import xml.etree.ElementTree as ET
from xml.parsers import expat

from cloud_dast.contracts.plan import InvariantProjection, VerificationPlan
from cloud_dast.model import (
    Check,
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    external_call,
    reached,
)
from cloud_dast_fuzzing import (
    GoalPayloadGenerator,
    TextualGenerator,
)
from cloud_dast_fuzzing.strategies.goal_payload import (
    PROBE_MARKER_PLACEHOLDER,
)


class StaticSeedGenerator:
    def __init__(self, request: tuple[tuple[str, object], ...]) -> None:
        self._request = request

    def generate(
        self,
        plan: VerificationPlan,
        method: MethodSpec,
        invariant: InvariantProjection,
        scenario: ScenarioPosition,
        *,
        feedback=None,
    ) -> tuple[Check, ...]:
        del invariant, feedback
        return (
            Check(
                invariant_id=plan.invariant_id,
                method_id=method.method_id,
                scenario_id=scenario.scenario_id,
                request=self._request,  # type: ignore[arg-type]
                identities=("attacker",),
                generator="template",
            ),
        )


class StaticOobUrls:
    def url_for(self, marker: str) -> str:
        return f"https://{marker}.oob.test"


def _method(*, repeated: bool = False) -> MethodSpec:
    fields = (
        FieldSpec(name="payload", type="string", required=True),
        FieldSpec(name="resource_id", type="string"),
        FieldSpec(name="mode", type="string", enum_values=("fast", "slow")),
    )
    if repeated:
        fields = (
            FieldSpec(name="tags", type="string", repeated=True),
            *fields,
        )
    return MethodSpec(
        method_id="example.Service.Write",
        service="example",
        name="Write",
        layer=EndpointLayer.PUBLIC,
        fields=fields,
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
        stand=StandState(),
    )


def _marker_invariant(method: MethodSpec) -> InvariantProjection:
    return _invariant(
        reached(Atom(value=f"action:{method.method_id}"), Atom(value="dast-marker"))
    )


def _oob_invariant(method: MethodSpec) -> InvariantProjection:
    return _invariant(
        external_call(
            Atom(value=f"action:{method.method_id}"),
            Atom(value="dast-marker"),
        )
    )


def _invariant(effect: object) -> InvariantProjection:
    return InvariantProjection(
        invariant_id="invariant",
        norm_id="norm",
        statement="textual sink must not be reached",
        severity=Severity.HIGH,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value="norm"), effect),  # type: ignore[arg-type]
        ),
    )


def _plan(
    method: MethodSpec,
    invariant: InvariantProjection,
    **updates: object,
) -> VerificationPlan:
    return VerificationPlan(
        plan_id="plan",
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id="scenario",
        **updates,  # type: ignore[arg-type]
    )


def _parse_xml(value: str) -> None:
    parser = expat.ParserCreate()
    parser.ExternalEntityRefHandler = lambda *args: True
    parser.Parse(value, True)


def test_xml_seed_mutates_into_structurally_valid_entities() -> None:
    method = _method()
    invariant = _marker_invariant(method)
    plan = _plan(
        method,
        invariant,
        grammar_formats=(("payload", "xml"),),
        probe_fields=("payload",),
    )
    seed = StaticSeedGenerator((("payload", "<note><to>seed</to></note>"),))

    checks = TextualGenerator(seed).generate(plan, method, invariant, _scenario())
    repeated = TextualGenerator(seed).generate(plan, method, invariant, _scenario())
    values = [dict(check.request)["payload"] for check in checks]

    assert checks == repeated
    assert checks
    assert all(check.generator == "textual" for check in checks)
    for value in values:
        assert "<!DOCTYPE note [" in value
        assert "&dast" in value
        assert value.count(PROBE_MARKER_PLACEHOLDER) == 1
        _parse_xml(value)
        assert ET.fromstring(value).tag == "note"


def test_xml_oob_placeholder_becomes_external_entity() -> None:
    method = _method()
    invariant = _oob_invariant(method)
    plan = _plan(
        method,
        invariant,
        grammar_formats=(("payload", "xml"),),
        probe_fields=("payload",),
    )
    seed = StaticSeedGenerator((("payload", "<note><to>seed</to></note>"),))

    checks = GoalPayloadGenerator(
        TextualGenerator(seed),
        oob_urls=StaticOobUrls(),
    ).generate(plan, method, invariant, _scenario())
    values = [dict(check.request)["payload"] for check in checks]

    assert checks
    assert any("SYSTEM" in value for value in values)
    for check, value in zip(checks, values, strict=True):
        assert check.probe_marker is not None
        assert value.count(StaticOobUrls().url_for(check.probe_marker)) == 1
        _parse_xml(value)


def test_template_seed_mutates_expressions_deterministically() -> None:
    method = _method()
    invariant = _marker_invariant(method)
    plan = _plan(
        method,
        invariant,
        grammar_formats=(("payload", "template"),),
        grammar_dialects=(("payload", "jinja"),),
        probe_fields=("payload",),
    )
    seed = StaticSeedGenerator((("payload", "Hello {{ user.name }}!"),))

    checks = TextualGenerator(seed).generate(plan, method, invariant, _scenario())
    repeated = TextualGenerator(seed).generate(plan, method, invariant, _scenario())
    values = [dict(check.request)["payload"] for check in checks]

    assert checks == repeated
    assert values
    for value in values:
        assert "{{" in value and "}}" in value
        assert value.count("{{") == value.count("}}")
        assert value.count(PROBE_MARKER_PLACEHOLDER) == 1


def test_pickle_seed_mutates_without_unpickling() -> None:
    method = _method()
    invariant = _marker_invariant(method)
    plan = _plan(
        method,
        invariant,
        grammar_formats=(("payload", "pickle"),),
        probe_fields=("payload",),
    )
    pickle_seed = pickle.dumps(
        {"user": "seed", "count": 1},
        protocol=2,
    ).decode("latin-1")
    seed = StaticSeedGenerator((("payload", pickle_seed),))

    checks = TextualGenerator(seed).generate(plan, method, invariant, _scenario())
    values = [dict(check.request)["payload"] for check in checks]

    assert values
    for value in values:
        raw = value.encode("latin-1")
        assert value.count(PROBE_MARKER_PLACEHOLDER) == 1
        operations = list(pickletools.genops(raw))
        assert operations[-1][0].name == "STOP"
        assert PROBE_MARKER_PLACEHOLDER in repr(pickle.loads(raw))


def test_java_seed_mutates_length_prefixed_string() -> None:
    method = _method()
    invariant = _marker_invariant(method)
    plan = _plan(
        method,
        invariant,
        grammar_formats=(("payload", "java"),),
        probe_fields=("payload",),
    )
    java_seed = bytes.fromhex(
        "aced000573720005506f696e740000000000000000020002490001784c"
        "00046e616d657400124c6a6176612f6c616e672f537472696e673b7870"
        "0000000774000473656564"
    ).decode("latin-1")
    seed = StaticSeedGenerator((("payload", java_seed),))

    checks = TextualGenerator(seed).generate(plan, method, invariant, _scenario())
    values = [dict(check.request)["payload"] for check in checks]

    assert values
    for value in values:
        assert value.startswith("\xac\xed\x00\x05")
        marker_index = value.index(PROBE_MARKER_PLACEHOLDER)
        assert value[marker_index - 3 : marker_index] == "t\x00\x0e"
        assert value.count(PROBE_MARKER_PLACEHOLDER) == 1


def test_json_seed_mutates_structurally_valid_tree() -> None:
    method = _method()
    invariant = _marker_invariant(method)
    plan = _plan(
        method,
        invariant,
        grammar_formats=(("payload", "javascript"),),
        probe_fields=("payload",),
    )
    seed = StaticSeedGenerator((("payload", '{"user":{"name":"seed"}}'),))

    checks = TextualGenerator(seed).generate(plan, method, invariant, _scenario())
    values = [dict(check.request)["payload"] for check in checks]

    assert values
    for value in values:
        assert value.count(PROBE_MARKER_PLACEHOLDER) == 1
        assert PROBE_MARKER_PLACEHOLDER in json.loads(value)["user"]["name"]


def test_repeated_shape_and_resource_fields_are_preserved() -> None:
    method = _method(repeated=True)
    invariant = _marker_invariant(method)
    plan = _plan(
        method,
        invariant,
        grammar_formats=(("tags", "xml"),),
        resource_params=("resource_id",),
    )
    seed = StaticSeedGenerator(
        (
            ("tags", ("<note><to>seed</to></note>",)),
            ("resource_id", "live-resource"),
        )
    )

    checks = TextualGenerator(seed).generate(plan, method, invariant, _scenario())

    assert checks
    for check in checks:
        request = dict(check.request)
        assert isinstance(request["tags"], tuple)
        assert len(request["tags"]) == 1
        assert request["resource_id"] == "live-resource"


def test_unknown_textual_format_returns_seed_unchanged() -> None:
    method = _method()
    invariant = _marker_invariant(method)
    plan = _plan(method, invariant, grammar_formats=(("payload", "text"),))
    seed = StaticSeedGenerator((("payload", "seed"),))

    checks = TextualGenerator(seed).generate(plan, method, invariant, _scenario())

    assert len(checks) == 1
    assert checks[0].request == (("payload", "seed"),)
    assert checks[0].generator == "template"


def test_unknown_template_dialect_is_not_mutated_as_jinja() -> None:
    method = _method()
    invariant = _marker_invariant(method)
    plan = _plan(
        method,
        invariant,
        grammar_formats=(("payload", "template"),),
        probe_fields=("payload",),
    )
    seed = StaticSeedGenerator((("payload", "Hello {{ user.name }}!"),))

    checks = TextualGenerator(seed).generate(plan, method, invariant, _scenario())

    assert len(checks) == 1
    assert checks[0].request == (("payload", "Hello {{ user.name }}!"),)


def test_declared_template_dialect_with_unknown_name_is_not_mutated() -> None:
    method = _method()
    invariant = _marker_invariant(method)
    plan = _plan(
        method,
        invariant,
        grammar_formats=(("payload", "template"),),
        grammar_dialects=(("payload", "custom-engine"),),
        probe_fields=("payload",),
    )
    seed = StaticSeedGenerator((("payload", "Hello {{ user.name }}!"),))

    checks = TextualGenerator(seed).generate(plan, method, invariant, _scenario())

    assert len(checks) == 1
    assert checks[0].request == (("payload", "Hello {{ user.name }}!"),)


def test_unknown_serialization_dialect_is_not_mutated_as_json() -> None:
    method = _method()
    invariant = _marker_invariant(method)
    plan = _plan(
        method,
        invariant,
        grammar_formats=(("payload", "deserialization"),),
        probe_fields=("payload",),
    )
    seed = StaticSeedGenerator((("payload", '{"user":"seed"}'),))

    checks = TextualGenerator(seed).generate(plan, method, invariant, _scenario())

    assert len(checks) == 1
    assert checks[0].request == (("payload", '{"user":"seed"}'),)


def test_serialization_seed_is_not_sniffed_from_magic_bytes() -> None:
    method = _method()
    invariant = _marker_invariant(method)
    plan = _plan(
        method,
        invariant,
        grammar_formats=(("payload", "serialization"),),
        probe_fields=("payload",),
    )
    pickle_seed = pickle.dumps({"user": "seed"}, protocol=2).decode("latin-1")
    seed = StaticSeedGenerator((("payload", pickle_seed),))

    checks = TextualGenerator(seed).generate(plan, method, invariant, _scenario())

    assert len(checks) == 1
    assert checks[0].request == (("payload", pickle_seed),)


def test_goal_payload_replaces_textual_marker_in_place() -> None:
    method = _method()
    invariant = _marker_invariant(method)
    plan = _plan(
        method,
        invariant,
        grammar_formats=(("payload", "xml"),),
        probe_fields=("payload",),
    )
    seed = StaticSeedGenerator((("payload", "<note><to>seed</to></note>"),))

    checks = GoalPayloadGenerator(TextualGenerator(seed)).generate(
        plan,
        method,
        invariant,
        _scenario(),
    )

    assert checks
    for check in checks:
        value = dict(check.request)["payload"]
        assert check.probe_marker is not None
        assert value.count(check.probe_marker) == 1
        _parse_xml(value)


def test_goal_payload_drops_textual_candidate_without_runtime_carrier() -> None:
    method = _method()
    invariant = _marker_invariant(method)
    plan = _plan(method, invariant, grammar_formats=(("payload", "xml"),))
    seed = StaticSeedGenerator((("payload", "<note><to>seed</to></note>"),))

    checks = GoalPayloadGenerator(TextualGenerator(seed)).generate(
        plan,
        method,
        invariant,
        _scenario(),
    )

    assert checks == ()
