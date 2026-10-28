from __future__ import annotations

import pytest

from cloud_dast.candidates import apply_seed_hints
from cloud_dast.contracts.request_fields import (
    Absent,
    Present,
    field_value,
    omit_optional_field,
)
from cloud_dast.model import (
    Check,
    FieldSpec,
)
from cloud_dast_fuzzing import (
    GeneratorSelector,
    GoalPayloadGenerator,
    OmitOptionalFieldGenerator,
    TemplateGenerator,
)


@pytest.mark.parametrize(
    ("field_name", "field_type", "present_value"),
    [
        ("alpha", "string", "dast-present"),
        ("beta", "int32", 0),
        ("gamma", "bool", False),
        ("delta", "double", 0.0),
    ],
)
def test_omit_strategy_maps_any_optional_field_to_absent(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
    field_name: str,
    field_type: str,
    present_value: object,
) -> None:
    optional = FieldSpec(name=field_name, type=field_type)
    method = method_spec.model_copy(update={"fields": (*method_spec.fields, optional)})

    checks = OmitOptionalFieldGenerator(TemplateGenerator()).generate(
        verification_plan,
        method,
        invariant,
        scenario_position,
    )

    present_request = (
        ("secret_id", "secret-victim"),
        (field_name, present_value),
    )
    assert field_value(present_request, optional) == Present(
        ((field_name, present_value),)
    )
    assert omit_optional_field(present_request, optional) == (
        ("secret_id", "secret-victim"),
    )
    assert len(checks) == 1
    assert field_value(checks[0].request, optional) == Absent()
    assert dict(checks[0].request) == {
        "secret_id": "secret-victim",
    }


def test_omit_strategy_covers_every_optional_field_independently(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    optional_names = ("cursor", "page_size", "verbose", "callback_url")
    method = method_spec.model_copy(
        update={
            "fields": (
                *method_spec.fields,
                FieldSpec(name="cursor", type="string"),
                FieldSpec(name="page_size", type="int32"),
                FieldSpec(name="verbose", type="bool"),
                FieldSpec(name="callback_url", type="url"),
            )
        }
    )

    checks = OmitOptionalFieldGenerator(TemplateGenerator()).generate(
        verification_plan,
        method,
        invariant,
        scenario_position,
    )

    omitted = {
        name
        for check in checks
        for name in optional_names
        if name not in dict(check.request)
    }
    assert len(checks) == len(optional_names)
    assert omitted == set(optional_names)
    assert all(
        len(set(optional_names) - set(dict(check.request))) == 1 for check in checks
    )


def test_omit_strategy_materializes_presence_from_a_partial_seed(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    method = method_spec.model_copy(
        update={
            "fields": (
                *method_spec.fields,
                FieldSpec(name="cursor", type="string"),
                FieldSpec(name="page_size", type="int32"),
            )
        }
    )

    checks = OmitOptionalFieldGenerator(_PartialRequestGenerator()).generate(
        verification_plan,
        method,
        invariant,
        scenario_position,
    )

    assert len(checks) == 2
    assert [tuple(dict(check.request)) for check in checks] == [
        ("secret_id", "page_size"),
        ("secret_id", "cursor"),
    ]


def test_optional_absence_removes_a_flattened_field_subtree() -> None:
    parent = FieldSpec(name="options", type="message")
    request = (
        ("resource_id", "resource"),
        ("options", None),
        ("options.child", "value"),
        ("other", "kept"),
    )

    assert field_value(request, parent) == Present(
        (
            ("options", None),
            ("options.child", "value"),
        )
    )
    omitted = omit_optional_field(request, parent)

    assert field_value(omitted, parent) == Absent()
    assert omitted == (
        ("resource_id", "resource"),
        ("other", "kept"),
    )


def test_required_field_has_no_absent_summand() -> None:
    required = FieldSpec(name="resource_id", type="string", required=True)

    with pytest.raises(ValueError, match="required field"):
        omit_optional_field((("resource_id", "resource"),), required)


def test_generator_selector_exposes_generic_omission_strategy(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    selector = GeneratorSelector({"template": TemplateGenerator()})

    assert "omit_optional_field" in selector.strategies
    selected = selector.select("omit_optional_field")

    assert isinstance(selected, OmitOptionalFieldGenerator)
    method = method_spec.model_copy(
        update={
            "fields": (*method_spec.fields, FieldSpec(name="cursor", type="string"))
        }
    )
    checks = selected.generate(
        verification_plan,
        method,
        invariant,
        scenario_position,
    )
    assert len(checks) == 1
    assert "cursor" not in dict(checks[0].request)


def test_seed_hint_can_materialize_optional_presence(
    method_spec,
    scenario_position,
) -> None:
    optional = FieldSpec(name="cursor", type="string")
    method = method_spec.model_copy(update={"fields": (*method_spec.fields, optional)})
    base = Check(
        invariant_id="inv",
        method_id=method.method_id,
        scenario_id=scenario_position.scenario_id,
        request=(("secret_id", "secret-victim"),),
        identities=(),
    )

    without_hint = apply_seed_hints(base, method, ())
    with_hint = apply_seed_hints(base, method, (("cursor", "setup_value"),))

    assert "cursor" not in dict(without_hint.request)
    assert dict(with_hint.request)["cursor"] == "dast-fixture-cursor"


class _PartialRequestGenerator:
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
                request=(("secret_id", "secret-victim"),),
                identities=("attacker",),
            ),
        )


def test_goal_payload_preserves_intentional_optional_absence(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    method = method_spec.model_copy(
        update={
            "fields": (
                FieldSpec(name="secret_id", type="string", required=True),
                FieldSpec(name="folder_id", type="string"),
            )
        }
    )
    plan = verification_plan.model_copy(
        update={
            "resource_params": ("folder_id",),
            "resource_types": (
                ("secret_id", "lockbox.secret"),
                ("folder_id", "folder"),
            ),
        }
    )

    check = GoalPayloadGenerator(_PartialRequestGenerator()).generate(
        plan,
        method,
        invariant,
        scenario_position,
    )[0]

    assert dict(check.request) == {"secret_id": "secret-victim"}
