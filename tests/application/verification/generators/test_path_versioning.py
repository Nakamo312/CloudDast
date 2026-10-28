from __future__ import annotations

import dataclasses

import pytest

from cloud_dast.model import FieldSpec, MethodSpec, PrincipalRef
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    allowed,
    input_field,
)
from cloud_dast.runtime.execution.contracts import (
    QdlExecutionPath,
    QdlExecutionStep,
)
from cloud_dast.runtime.execution.metadata import (
    version_executable_inputs as _version_executable_inputs,
)


def _execution_path(
    plan,
    method: MethodSpec,
    scenario,
    invariant,
):
    step = QdlExecutionStep(
        step_id="step:path:0",
        goal_id="goal:path",
        plan=plan,
        method=method,
        scenario=scenario,
        invariant=invariant,
    )
    return QdlExecutionPath(
        path_id="path",
        goal_id="goal:path",
        kind="invariant",
        description="path",
        steps=(step,),
    )


@pytest.mark.parametrize(
    ("plan_update", "change_method"),
    [
        (
            {
                "couplings": (
                    (
                        input_field(Atom(value="method"), Atom(value="left")),
                        input_field(Atom(value="method"), Atom(value="right")),
                        "eq",
                    ),
                )
            },
            False,
        ),
        ({"probe_fields": ("payload",)}, False),
        ({"resource_params": ("resource_id",)}, False),
        ({"seed_hints": (("payload", "payload"),)}, False),
        ({"resource_types": (("resource_id", "widget"),)}, False),
        ({"subject_refs": (("subject_id", "actor"),)}, False),
        ({"role_refs": (("role_id", "reader"),)}, False),
        ({"sink_types": (("payload", "sql_engine"),)}, False),
        ({"grammar_formats": (("payload", "json"),)}, False),
        ({"grammar_constraints": (("payload", "eq", "value"),)}, False),
        ({"grammar_dialects": (("payload", "ansi"),)}, False),
        (
            {
                "identity_terms": (
                    PrincipalRef(principal_id="actor", principal_type="user"),
                )
            },
            False,
        ),
        ({}, True),
    ],
)
def test_path_versioning_covers_every_executable_input(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
    plan_update,
    change_method,
) -> None:
    base = _execution_path(verification_plan, method_spec, scenario_position, invariant)
    changed_method = method_spec
    if change_method:
        changed_method = method_spec.model_copy(
            update={
                "method_id": f"{method_spec.method_id}:mutating",
                "name": f"{method_spec.name}Mutating",
            }
        )
    changed = _execution_path(
        verification_plan.model_copy(update=plan_update),
        changed_method,
        scenario_position,
        invariant,
    )

    base_id = _version_executable_inputs([base])[0].path_id
    changed_id = _version_executable_inputs([changed])[0].path_id

    assert base_id.startswith("path:pv")
    assert changed_id.startswith("path:pv")
    assert changed_id != base_id


def test_path_versioning_is_stable_for_unchanged_inputs(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    path = _execution_path(verification_plan, method_spec, scenario_position, invariant)

    first = _version_executable_inputs([path])[0].path_id
    second = _version_executable_inputs([dataclasses.replace(path)])[0].path_id

    assert first == second


def test_path_versioning_includes_changed_action_method_contract(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
) -> None:
    base_method = method_spec.model_copy(
        update={
            "method_id": "grpc:action",
            "name": "Action",
            "fields": (FieldSpec(name="payload", type="string"),),
        }
    )
    changed_method = base_method.model_copy(
        update={"fields": (FieldSpec(name="payload", type="url"),)}
    )

    base = _execution_path(
        verification_plan,
        base_method,
        scenario_position,
        invariant,
    )
    changed = _execution_path(
        verification_plan,
        changed_method,
        scenario_position,
        invariant,
    )

    first = _version_executable_inputs([base])[0].path_id
    second = _version_executable_inputs([changed])[0].path_id

    assert first != second


@pytest.mark.parametrize(
    "field", ["required_effects", "evidence_graph", "irreversible"]
)
def test_path_versioning_includes_ordinary_causal_inputs(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
    field,
):
    path = _execution_path(verification_plan, method_spec, scenario_position, invariant)
    action = Atom(value=f"action:{method_spec.method_id}")
    effect = allowed(action)
    graph = QdlGraph(
        facts=(
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(action, Atom(value="Action")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(effect, Atom(value="Effect")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("causes"),
                args=(action, effect),
            ),
        )
    )
    values = {
        "required_effects": (effect,),
        "evidence_graph": graph,
        "irreversible": True,
    }
    step = dataclasses.replace(path.steps[0], **{field: values[field]})
    changed = dataclasses.replace(path, steps=(step,))
    assert (
        _version_executable_inputs([path])[0].path_id
        != _version_executable_inputs([changed])[0].path_id
    )
    assert (
        _version_executable_inputs([changed])[0].path_id
        == _version_executable_inputs([dataclasses.replace(changed)])[0].path_id
    )


def test_path_versioning_tracks_changed_evidence_and_not_fact_order(
    verification_plan,
    method_spec,
    scenario_position,
    invariant,
):
    action = Atom(value=f"action:{method_spec.method_id}")
    declaration = Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name("is"),
        args=(action, Atom(value="Action")),
    )
    graph = QdlGraph(facts=(declaration,))
    path = _execution_path(verification_plan, method_spec, scenario_position, invariant)
    base = dataclasses.replace(
        path, steps=(dataclasses.replace(path.steps[0], evidence_graph=graph),)
    )
    effect = allowed(action)
    enriched = QdlGraph(
        facts=(
            declaration,
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("is"),
                args=(effect, Atom(value="Effect")),
            ),
            Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("causes"),
                args=(action, effect),
            ),
        )
    )
    changed = dataclasses.replace(
        path, steps=(dataclasses.replace(path.steps[0], evidence_graph=enriched),)
    )
    reordered = dataclasses.replace(
        changed,
        steps=(
            dataclasses.replace(
                changed.steps[0],
                evidence_graph=QdlGraph(facts=tuple(reversed(enriched.facts))),
            ),
        ),
    )
    assert (
        _version_executable_inputs([base])[0].path_id
        != _version_executable_inputs([changed])[0].path_id
    )
    assert (
        _version_executable_inputs([changed])[0].path_id
        == _version_executable_inputs([reordered])[0].path_id
    )
