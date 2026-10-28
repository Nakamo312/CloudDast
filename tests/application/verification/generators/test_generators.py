from __future__ import annotations

from unittest.mock import Mock

import pytest

from cloud_dast.model import (
    BindingRef,
    Check,
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    PrincipalRef,
    ResourceRef,
    ScenarioPosition,
)
from cloud_dast_fuzzing import (
    GeneratorCatalog,
    GeneratorSelector,
    MinimalSeedGenerator,
    TemplateGenerator,
)
from cloud_dast_fuzzing.strategies.fuzzing import FuzzingGenerator
from cloud_dast_fuzzing.strategies.goal_payload import (
    GoalPayloadGenerator,
)
from cloud_dast_symbolic import Z3SymbolicGenerator


def test_generator_selector_exposes_explicit_strategies(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    template = TemplateGenerator()
    symbolic = Z3SymbolicGenerator(template)
    selector = GeneratorSelector(
        {"template": template, "symbolic": symbolic}, default="template"
    )

    assert selector.select("symbolic") is symbolic
    generated = selector.generate(
        verification_plan, method_spec, invariant, scenario_position
    )
    assert generated[0].generator == "template"

    symbolic_plan = verification_plan.model_copy(update={"generator": "symbolic"})
    generated = selector.generate(
        symbolic_plan, method_spec, invariant, scenario_position
    )
    assert generated[0].generator == "symbolic"

    with pytest.raises(ValueError, match="unknown generator strategy"):
        selector.select("fuzzing")


def test_generator_catalog_decorates_one_shot_and_session_paths_once(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    selector = GeneratorSelector({"template": TemplateGenerator()})
    catalog = GeneratorCatalog(selector)

    one_shot = catalog.one_shot()
    session_generators = catalog.session_generators(exclude=("omit_optional_field",))

    assert isinstance(one_shot, GoalPayloadGenerator)
    assert set(session_generators) == {"template"}
    assert all(
        isinstance(generator, GoalPayloadGenerator)
        for generator in session_generators.values()
    )

    hinted_plan = verification_plan.model_copy(
        update={"seed_hints": (("secret_id", "setup_value"),)}
    )
    one_shot_check = one_shot.generate(
        hinted_plan,
        method_spec,
        invariant,
        scenario_position,
    )[0]
    session_check = session_generators["template"].generate(
        hinted_plan,
        method_spec,
        invariant,
        scenario_position,
    )[0]
    assert one_shot_check.request == session_check.request


def test_template_generator_builds_check_from_contract_and_scenario(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    generated = TemplateGenerator().generate(
        verification_plan,
        method_spec,
        invariant,
        scenario_position,
    )

    assert len(generated) == 1
    assert generated[0].method_id == method_spec.method_id
    assert generated[0].scenario_id == scenario_position.scenario_id
    assert generated[0].invariant_id == invariant.invariant_id
    assert generated[0].request == (("secret_id", "secret-victim"),)
    assert generated[0].identities == ()


def test_template_generator_maps_resources_by_type(
    verification_plan,
    method_spec_with_ids,
    scenario_position,
    invariant,
) -> None:
    typed_plan = verification_plan.model_copy(
        update={
            "resource_types": (
                ("secret_id", "lockbox.secret"),
                ("folder_id", "folder"),
            )
        }
    )
    generated = TemplateGenerator().generate(
        typed_plan,
        method_spec_with_ids,
        invariant,
        scenario_position,
    )

    assert dict(generated[0].request) == {
        "secret_id": "secret-victim",
        "folder_id": "folder-victim",
        "unknown_id": None,
    }


def test_template_generator_does_not_match_resource_type_by_suffix(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    """A ``kms.secret`` stand resource must not satisfy ``lockbox.secret``."""

    method = method_spec.model_copy(
        update={"fields": (FieldSpec(name="secret_id", type="string", required=True),)}
    )
    plan = verification_plan.model_copy(
        update={"resource_types": (("secret_id", "lockbox.secret"),)}
    )
    stand = scenario_position.stand.model_copy(
        update={
            "resources": (
                ResourceRef(
                    service="kms",
                    resource_type="kms.secret",
                    resource_id="kms-secret-1",
                ),
            ),
        }
    )
    scenario = scenario_position.model_copy(update={"stand": stand})

    generated = TemplateGenerator().generate(plan, method, invariant, scenario)

    assert dict(generated[0].request)["secret_id"] is None


def _binding_method_spec(method_spec: MethodSpec) -> MethodSpec:
    return method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(name="resource_id", type="string"),
                FieldSpec(
                    name="access_binding_deltas",
                    type="access.AccessBindingDelta",
                    repeated=True,
                ),
                FieldSpec(
                    name="access_binding_deltas.access_binding.role_id",
                    type="string",
                ),
                FieldSpec(
                    name="access_binding_deltas.access_binding.subject.id",
                    type="string",
                ),
                FieldSpec(
                    name="access_binding_deltas.access_binding.subject.type",
                    type="string",
                ),
            )
        }
    )


def _binding_scenario_position(
    scenario_position: ScenarioPosition,
) -> ScenarioPosition:
    return scenario_position.model_copy(
        update={
            "stand": scenario_position.stand.model_copy(
                update={
                    "principals": (
                        PrincipalRef(principal_id="victim", principal_type="user"),
                        PrincipalRef(principal_id="attacker", principal_type="user"),
                    ),
                    "bindings": (
                        BindingRef(principal_id="victim", role="viewer"),
                        BindingRef(principal_id="attacker", role="editor"),
                    ),
                }
            )
        }
    )


def test_template_generator_keeps_subject_and_role_fields_unresolved_without_facts(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    method = _binding_method_spec(method_spec)
    scenario = _binding_scenario_position(scenario_position)

    generated = TemplateGenerator().generate(
        verification_plan, method, invariant, scenario
    )
    values = dict(generated[0].request)

    assert values["access_binding_deltas.access_binding.role_id"] is None
    assert values["access_binding_deltas.access_binding.subject.id"] is None
    assert values["access_binding_deltas.access_binding.subject.type"] is None


def test_template_generator_maps_subject_and_role_fields_from_reference_facts(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    method = _binding_method_spec(method_spec)
    scenario = _binding_scenario_position(scenario_position)
    plan = verification_plan.model_copy(
        update={
            "subject_params": ("access_binding_deltas.access_binding.subject.id",),
            "subject_refs": (
                ("access_binding_deltas.access_binding.subject.id", "attacker"),
            ),
            "role_params": ("access_binding_deltas.access_binding.role_id",),
            "role_refs": (
                ("access_binding_deltas.access_binding.role_id", "attacker"),
            ),
        }
    )

    generated = TemplateGenerator().generate(plan, method, invariant, scenario)
    values = dict(generated[0].request)

    # The refers_to fact selects the subject; the first stand principal
    # ("victim") must not win by position.
    assert values["access_binding_deltas.access_binding.subject.id"] == "attacker"
    assert values["access_binding_deltas.access_binding.role_id"] == "editor"
    assert values["resource_id"] is None


def test_template_generator_does_not_resolve_resource_id_fields_by_name(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    untyped_plan = verification_plan.model_copy(update={"resource_types": ()})

    generated = TemplateGenerator().generate(
        untyped_plan, method_spec, invariant, scenario_position
    )

    assert dict(generated[0].request)["secret_id"] is None


def test_template_generator_keeps_repeated_field_shape(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    method = method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(name="secret_id", type="string", required=True),
                FieldSpec(name="tags", type="string", required=True, repeated=True),
            )
        }
    )

    generated = TemplateGenerator().generate(
        verification_plan,
        method,
        invariant,
        scenario_position,
    )

    assert dict(generated[0].request) == {
        "secret_id": "secret-victim",
        "tags": (None,),
    }


@pytest.fixture
def rich_method_spec(method_spec: MethodSpec) -> MethodSpec:
    return method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(name="secret_id", type="string", required=True),
                FieldSpec(name="page_token", type="string", required=False),
                FieldSpec(name="limit", type="int32", required=True),
                FieldSpec(name="verbose", type="bool", required=True),
                FieldSpec(name="ratio", type="double", required=True),
                FieldSpec(name="selector_id", type="string", oneof="selector"),
                FieldSpec(name="selector_name", type="string", oneof="selector"),
                FieldSpec(name="tags", type="string", required=True, repeated=True),
            )
        }
    )


@pytest.fixture
def scenario_with_principals(scenario_position: ScenarioPosition) -> ScenarioPosition:
    return scenario_position.model_copy(
        update={
            "stand": scenario_position.stand.model_copy(
                update={
                    "principals": (
                        PrincipalRef(principal_id="attacker", principal_type="user"),
                    )
                }
            )
        }
    )


def test_minimal_seed_keeps_required_fields_and_first_oneof_branch(
    verification_plan,
    rich_method_spec,
    scenario_position,
    invariant,
) -> None:
    seed = MinimalSeedGenerator(TemplateGenerator()).generate(
        verification_plan,
        rich_method_spec,
        invariant,
        scenario_position,
    )

    assert len(seed) == 1
    assert seed[0].request == (
        ("secret_id", "secret-victim"),
        ("limit", 0),
        ("verbose", False),
        ("ratio", 0.0),
        ("selector_id", ""),
        ("tags", ("",)),
    )
    assert seed[0].generator == "template"
    assert seed[0].seed_id is not None


def test_minimal_seed_maps_scenario_principals_and_resources(
    verification_plan,
    method_spec,
    scenario_with_principals,
    invariant,
) -> None:
    method = method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(name="subject_id", type="string", required=True),
                FieldSpec(name="secret_id", type="string", required=True),
            )
        }
    )
    plan = verification_plan.model_copy(
        update={
            "subject_params": ("subject_id",),
            "subject_refs": (("subject_id", "attacker"),),
        }
    )

    seed = MinimalSeedGenerator(TemplateGenerator()).generate(
        plan,
        method,
        invariant,
        scenario_with_principals,
    )

    assert seed[0].request == (
        ("subject_id", "attacker"),
        ("secret_id", "secret-victim"),
    )
    assert seed[0].identities == ("attacker",)


def test_minimal_seed_without_subject_fact_keeps_field_unresolved(
    verification_plan,
    method_spec,
    scenario_with_principals,
    invariant,
) -> None:
    method = method_spec.model_copy(
        update={"fields": (FieldSpec(name="subject_id", type="string", required=True),)}
    )

    seed = MinimalSeedGenerator(TemplateGenerator()).generate(
        verification_plan, method, invariant, scenario_with_principals
    )

    assert seed[0].request == (("subject_id", ""),)


def test_minimal_seed_id_is_deterministic(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    generator = MinimalSeedGenerator(TemplateGenerator())

    first = generator.generate(
        verification_plan,
        method_spec,
        invariant,
        scenario_position,
    )[0]
    second = generator.generate(
        verification_plan,
        method_spec,
        invariant,
        scenario_position,
    )[0]
    other_scenario = scenario_position.model_copy(
        update={"scenario_id": "same-folder-private"}
    )
    other_plan = verification_plan.model_copy(
        update={
            "plan_id": "plan:same-folder-private",
            "scenario_id": other_scenario.scenario_id,
        }
    )
    other = generator.generate(
        other_plan,
        method_spec,
        invariant,
        other_scenario,
    )[0]

    assert first.seed_id == second.seed_id
    assert first.seed_id != other.seed_id


def test_minimal_seed_without_principal_fact_keeps_identity_empty(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    method = method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(name="subject_id", type="string", required=True),
                FieldSpec(name="offset", type="fixed64", required=True),
            )
        }
    )
    scenario_without_principals = scenario_position.model_copy(
        update={"stand": scenario_position.stand.model_copy(update={"principals": ()})}
    )

    seed = MinimalSeedGenerator(TemplateGenerator()).generate(
        verification_plan,
        method,
        invariant,
        scenario_without_principals,
    )[0]

    assert seed.request == (
        ("subject_id", ""),
        ("offset", 0),
    )
    assert seed.identities == ()


def test_minimal_seed_uses_first_enum_value(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    method = method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(
                    name="secret_id",
                    type="string",
                    required=True,
                    enum_values=("read", "write"),
                ),
            )
        }
    )

    seed = MinimalSeedGenerator(TemplateGenerator()).generate(
        verification_plan,
        method,
        invariant,
        scenario_position,
    )[0]

    assert seed.request == (("secret_id", "read"),)


def test_minimal_seed_keeps_numeric_default_inside_bounds(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    method = method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(name="offset", type="int32", required=True, minimum=5),
                FieldSpec(name="ratio", type="double", required=True, maximum=-2.5),
            )
        }
    )

    seed = MinimalSeedGenerator(TemplateGenerator()).generate(
        verification_plan,
        method,
        invariant,
        scenario_position,
    )[0]

    assert seed.request == (("offset", 5), ("ratio", -2.5))


def test_fuzzing_keeps_repeated_numeric_shape(
    verification_plan,
    method_spec,
    scenario_with_principals,
    invariant,
) -> None:
    method = method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(name="ids", type="int64", required=True, repeated=True),
            )
        }
    )

    mutations = FuzzingGenerator(MinimalSeedGenerator(TemplateGenerator())).generate(
        verification_plan,
        method,
        invariant,
        scenario_with_principals,
    )

    assert mutations
    for check in mutations:
        ids = dict(check.request)["ids"]
        assert isinstance(ids, tuple)
        assert all(isinstance(value, int) for value in ids)
        assert all(-(2**63) <= value <= 2**63 - 1 for value in ids)
    assert all(check.identities == ("attacker",) for check in mutations)


def test_fuzzing_applies_bounds_to_repeated_numeric_fields(
    verification_plan,
    method_spec,
    scenario_with_principals,
    invariant,
) -> None:
    method = method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(
                    name="offsets",
                    type="int32",
                    required=True,
                    repeated=True,
                    minimum=-5,
                    maximum=10,
                ),
            )
        }
    )

    mutations = FuzzingGenerator(MinimalSeedGenerator(TemplateGenerator())).generate(
        verification_plan,
        method,
        invariant,
        scenario_with_principals,
    )

    assert mutations
    for check in mutations:
        offsets = dict(check.request)["offsets"]
        assert isinstance(offsets, tuple)
        assert all(-5 <= value <= 10 for value in offsets)
    assert all(check.identities == ("attacker",) for check in mutations)


def test_fuzzing_uses_unsigned_boundaries_for_fixed64(
    verification_plan,
    method_spec,
    scenario_with_principals,
    invariant,
) -> None:
    method = method_spec.model_copy(
        update={"fields": (FieldSpec(name="offset", type="fixed64", required=True),)}
    )

    mutations = FuzzingGenerator(MinimalSeedGenerator(TemplateGenerator())).generate(
        verification_plan,
        method,
        invariant,
        scenario_with_principals,
    )

    values = [dict(check.request)["offset"] for check in mutations]

    assert values
    assert all(isinstance(value, int) and 0 <= value <= 2**64 - 1 for value in values)
    assert {check.identities for check in mutations} == {("attacker",)}


@pytest.mark.parametrize(
    ("field_type", "low", "high"),
    [
        ("int32", -(2**31), 2**31 - 1),
        ("sint32", -(2**31), 2**31 - 1),
        ("sfixed32", -(2**31), 2**31 - 1),
        ("uint32", 0, 2**32 - 1),
        ("fixed32", 0, 2**32 - 1),
        ("int64", -(2**63), 2**63 - 1),
        ("sint64", -(2**63), 2**63 - 1),
        ("sfixed64", -(2**63), 2**63 - 1),
        ("uint64", 0, 2**64 - 1),
        ("fixed64", 0, 2**64 - 1),
    ],
)
def test_fuzzing_keeps_integer_mutations_inside_primitive_range(
    verification_plan,
    method_spec,
    scenario_with_principals,
    invariant,
    field_type: str,
    low: int,
    high: int,
) -> None:
    method = method_spec.model_copy(
        update={"fields": (FieldSpec(name="offset", type=field_type, required=True),)}
    )

    mutations = FuzzingGenerator(MinimalSeedGenerator(TemplateGenerator())).generate(
        verification_plan,
        method,
        invariant,
        scenario_with_principals,
    )
    values = [value for check in mutations for _, value in check.request]

    assert values
    assert all(isinstance(value, int) and low <= value <= high for value in values)


def test_fuzzing_keeps_enum_mutations_inside_allowed_values(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    method = method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(
                    name="secret_id",
                    type="string",
                    required=True,
                    enum_values=("read", "write", "admin"),
                ),
            )
        }
    )

    mutations = FuzzingGenerator(MinimalSeedGenerator(TemplateGenerator())).generate(
        verification_plan,
        method,
        invariant,
        scenario_position,
    )

    values = [dict(check.request)["secret_id"] for check in mutations]

    assert values
    assert all(value in {"read", "write", "admin"} for value in values)


def test_fuzzing_uses_bounded_generic_string_operators(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    method = method_spec.model_copy(
        update={"fields": (FieldSpec(name="payload", type="string", required=True),)}
    )
    seed = Check(
        invariant_id=invariant.invariant_id,
        method_id=method.method_id,
        scenario_id=scenario_position.scenario_id,
        request=(("payload", "seed"),),
        identities=("anonymous",),
        generator="symbolic",
        seed_id="seed-1",
    )

    mutations = FuzzingGenerator(Mock(**{"generate.return_value": (seed,)})).generate(
        verification_plan, method, invariant, scenario_position
    )
    values = [dict(check.request)["payload"] for check in mutations]

    assert values
    assert all(isinstance(value, str) for value in values)
    assert all(len(value) <= 256 for value in values)
    assert all(value != "seed" for value in values)
    assert len(values) == len(set(values))


def test_fuzzing_keeps_numeric_mutations_inside_bounds(
    verification_plan,
    method_spec,
    scenario_with_principals,
    invariant,
) -> None:
    method = method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(
                    name="offset",
                    type="int32",
                    required=True,
                    minimum=-5,
                    maximum=10,
                ),
            )
        }
    )

    mutations = FuzzingGenerator(MinimalSeedGenerator(TemplateGenerator())).generate(
        verification_plan,
        method,
        invariant,
        scenario_with_principals,
    )

    values = [dict(check.request)["offset"] for check in mutations]

    assert values
    assert all(-5 <= value <= 10 for value in values)
    assert all(check.identities == ("attacker",) for check in mutations)


def test_minimal_seed_rejects_foreign_plan_and_layer_mismatch(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    foreign_plan = verification_plan.model_copy(
        update={"method_id": "grpc:yandex.cloud.lockbox.v1.OtherService.Get"}
    )
    public_scenario = scenario_position.model_copy(
        update={
            "profile": scenario_position.profile.model_copy(
                update={"endpoint_layer": EndpointLayer.PUBLIC}
            )
        }
    )

    with pytest.raises(ValueError, match="does not belong"):
        MinimalSeedGenerator(TemplateGenerator()).generate(
            foreign_plan, method_spec, invariant, scenario_position
        )
    with pytest.raises(ValueError, match="does not match"):
        MinimalSeedGenerator(TemplateGenerator()).generate(
            verification_plan, method_spec, invariant, public_scenario
        )


def test_fuzzing_rejects_foreign_plan(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    foreign_plan = verification_plan.model_copy(
        update={"method_id": "grpc:yandex.cloud.lockbox.v1.OtherService.Get"}
    )

    with pytest.raises(ValueError, match="does not belong to method"):
        FuzzingGenerator(Mock(**{"generate.return_value": ()})).generate(
            foreign_plan, method_spec, invariant, scenario_position
        )


def test_minimal_seed_does_not_modify_inputs(
    verification_plan,
    rich_method_spec,
    scenario_position,
    invariant,
) -> None:
    method_before = rich_method_spec.model_dump()
    scenario_before = scenario_position.model_dump()
    plan_before = verification_plan.model_dump()

    MinimalSeedGenerator(TemplateGenerator()).generate(
        verification_plan,
        rich_method_spec,
        invariant,
        scenario_position,
    )

    assert rich_method_spec.model_dump() == method_before
    assert scenario_position.model_dump() == scenario_before
    assert verification_plan.model_dump() == plan_before


def test_minimal_seed_omits_optional_fields_unlike_template(
    verification_plan,
    method_spec_with_ids,
    scenario_position,
    invariant,
) -> None:
    typed_plan = verification_plan.model_copy(
        update={
            "resource_types": (
                ("secret_id", "lockbox.secret"),
                ("folder_id", "folder"),
            )
        }
    )
    template = TemplateGenerator().generate(
        typed_plan,
        method_spec_with_ids,
        invariant,
        scenario_position,
    )[0]
    symbolic = MinimalSeedGenerator(TemplateGenerator()).generate(
        typed_plan,
        method_spec_with_ids,
        invariant,
        scenario_position,
    )[0]

    assert dict(template.request) == {
        "secret_id": "secret-victim",
        "folder_id": "folder-victim",
        "unknown_id": None,
    }
    assert dict(symbolic.request) == {
        "secret_id": "secret-victim",
        "folder_id": "folder-victim",
    }


def test_fuzzing_mutates_seed_fields_and_keeps_lineage(
    verification_plan,
    rich_method_spec,
    scenario_with_principals,
    invariant,
) -> None:
    seed = MinimalSeedGenerator(TemplateGenerator()).generate(
        verification_plan,
        rich_method_spec,
        invariant,
        scenario_with_principals,
    )[0]

    mutations = FuzzingGenerator(MinimalSeedGenerator(TemplateGenerator())).generate(
        verification_plan,
        rich_method_spec,
        invariant,
        scenario_with_principals,
    )

    mutation_keys = [(check.request, check.identities) for check in mutations]
    assert mutations
    assert (seed.request, seed.identities) not in mutation_keys
    assert len(mutation_keys) == len(set(mutation_keys))
    assert all(check.generator == "fuzzing" for check in mutations)
    assert all(check.seed_id == seed.seed_id for check in mutations)
    assert len({check.check_id for check in mutations}) == len(mutations)
    assert seed.check_id not in {check.check_id for check in mutations}
    assert all(check.identities == seed.identities for check in mutations)

    seed_values = dict(seed.request)
    for check in mutations:
        values = dict(check.request)
        changed_fields = [
            name for name, value in values.items() if value != seed_values[name]
        ]
        assert changed_fields
        assert set(values) == set(seed_values)


def test_fuzzing_skips_noop_and_duplicate_mutations(
    verification_plan,
    rich_method_spec,
    scenario_with_principals,
    invariant,
) -> None:
    seed = MinimalSeedGenerator(TemplateGenerator()).generate(
        verification_plan,
        rich_method_spec,
        invariant,
        scenario_with_principals,
    )[0]

    mutations = FuzzingGenerator(MinimalSeedGenerator(TemplateGenerator())).generate(
        verification_plan,
        rich_method_spec,
        invariant,
        scenario_with_principals,
    )

    mutation_keys = [(check.request, check.identities) for check in mutations]
    assert (seed.request, seed.identities) not in mutation_keys
    assert len(mutation_keys) == len(set(mutation_keys))


def test_fuzzing_deduplicates_mutations_across_seeds(
    verification_plan,
    method_spec,
    scenario_with_principals,
    invariant,
) -> None:
    base_seed = Check(
        invariant_id=invariant.invariant_id,
        method_id=method_spec.method_id,
        scenario_id=scenario_with_principals.scenario_id,
        request=(("secret_id", "secret-victim"),),
        identities=("attacker",),
        generator="symbolic",
        seed_id="seed-1",
    )
    duplicate_seed = base_seed.model_copy(update={"seed_id": "seed-2"})
    seed_generator = Mock(
        **{"generate.return_value": (base_seed, duplicate_seed)},
    )

    mutations = FuzzingGenerator(seed_generator=seed_generator).generate(
        verification_plan,
        method_spec,
        invariant,
        scenario_with_principals,
    )
    base_only = FuzzingGenerator(
        Mock(**{"generate.return_value": (base_seed,)})
    ).generate(
        verification_plan,
        method_spec,
        invariant,
        scenario_with_principals,
    )

    assert mutations
    assert mutations == base_only
    assert len({check.check_id for check in mutations}) == len(mutations)


def test_fuzzing_never_injects_an_identity_without_grounded_variants(
    verification_plan,
    method_spec,
    scenario_with_principals,
    invariant,
) -> None:
    seed = Check(
        invariant_id=invariant.invariant_id,
        method_id=method_spec.method_id,
        scenario_id=scenario_with_principals.scenario_id,
        request=(("secret_id", "secret-victim"),),
        identities=("attacker",),
        generator="symbolic",
        seed_id="seed-1",
    )
    seed_generator = Mock(**{"generate.return_value": (seed,)})

    mutations = FuzzingGenerator(seed_generator=seed_generator).generate(
        verification_plan,
        method_spec,
        invariant,
        scenario_with_principals,
    )

    assert mutations
    assert {check.identities for check in mutations} == {("attacker",)}


def test_fuzzing_is_deterministic(
    verification_plan,
    rich_method_spec,
    scenario_with_principals,
    invariant,
) -> None:
    generator = FuzzingGenerator(MinimalSeedGenerator(TemplateGenerator()))

    first = generator.generate(
        verification_plan,
        rich_method_spec,
        invariant,
        scenario_with_principals,
    )
    second = generator.generate(
        verification_plan,
        rich_method_spec,
        invariant,
        scenario_with_principals,
    )

    assert first == second


def test_fuzzing_returns_nothing_without_seed(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    assert (
        FuzzingGenerator(Mock(**{"generate.return_value": ()})).generate(
            verification_plan,
            method_spec,
            invariant,
            scenario_position,
        )
        == ()
    )
