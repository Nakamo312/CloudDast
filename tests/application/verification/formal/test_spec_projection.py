from __future__ import annotations

import pytest

from cloud_dast.verification.spec_projection import (
    InputSpecification,
    SpecAction,
    SpecField,
    SpecProjector,
)


def test_spec_projector_compiles_nested_fields_to_qdl() -> None:
    specification = InputSpecification(
        service="device",
        actions=(
            SpecAction(
                action_id="device.Configure",
                fields=(
                    SpecField(
                        name="network",
                        type="object",
                        fields=(
                            SpecField(name="host", type="string", required=True),
                            SpecField(name="port", type="int32", minimum=1),
                        ),
                    ),
                ),
            ),
        ),
    )

    projection = SpecProjector().project(specification)
    facts = projection.graph.facts

    assert any(
        fact.predicate.name == "is"
        and fact.args[0].kind == "atom"
        and fact.args[0].value == "service:device"
        and fact.args[1].value == "Service"
        for fact in facts
    )
    assert any(
        fact.predicate.name == "is"
        and fact.args[0].kind == "atom"
        and fact.args[0].value == "action:device.Configure"
        and fact.args[1].value == "Action"
        for fact in facts
    )
    assert any(
        fact.predicate.name == "field_type"
        and fact.args[0].args[1].value == "network.port"
        and fact.args[1].value == "int32"
        for fact in facts
    )
    assert any(
        fact.predicate.name == "field_required"
        and fact.args[0].args[1].value == "network.host"
        and fact.args[1].value is True
        for fact in facts
    )


def test_spec_projector_reuses_contract_projection_report() -> None:
    specification = InputSpecification(
        service="protocol",
        actions=(
            SpecAction(
                action_id="protocol.Send",
                fields=(SpecField(name="payload", type="bytes"),),
            ),
        ),
    )

    projection = SpecProjector().project(specification)

    assert projection.report.unmapped == ()
    assert projection.canonical_hash == projection.graph.content_hash


def test_input_specification_requires_actions() -> None:
    with pytest.raises(ValueError, match="requires at least one action"):
        InputSpecification(service="device", actions=())
