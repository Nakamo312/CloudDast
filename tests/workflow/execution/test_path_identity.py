from __future__ import annotations

import dataclasses
import re

from cloud_dast.contracts.plan import (
    InvariantProjection,
    QdlExecutionPath,
    QdlExecutionStep,
    VerificationPlan,
)
from cloud_dast.model import (
    MethodSpec,
    ScenarioPosition,
)
from cloud_dast.qdl.graph import Atom, Context, Fact, Predicate, QdlGraph, allowed
from cloud_dast.qdl.state_machine import (
    state_machine_graph,
)
from cloud_dast.runtime.execution.metadata import (
    version_executable_inputs,
)
from cloud_dast.runtime.planning import QdlPlanner

_PATH_ID = re.compile(r"qdl-(?:attack|state|forbidden)-[0-9a-f]{64}")
_VERSIONED_PATH_ID = re.compile(
    r"qdl-(?:attack|state|forbidden)-[0-9a-f]{64}:pv[0-9a-f]{64}"
)


def _version_id(path: QdlExecutionPath) -> str:
    return version_executable_inputs([path])[0].path_id


def test_planner_path_ids_are_structural_hashes_independent_of_unrelated_facts() -> (
    None
):
    graph = state_machine_graph(
        states=("created", "approved"),
        actions=("approve",),
        initial_states=("created",),
        transitions=(("approve", "created", "approved"),),
    )
    unrelated_fact = Fact(
        context=Context.CONTRACT,
        predicate=Predicate.from_name("is"),
        args=(Atom(value="resource:unrelated"), Atom(value="Resource")),
    )
    changed_graph = QdlGraph(facts=(*graph.facts, unrelated_fact))

    first = QdlPlanner().plan(graph)
    second = QdlPlanner().plan(changed_graph)

    first_ids = {path.path_id for path in first.state_paths}
    second_ids = {path.path_id for path in second.state_paths}
    assert first_ids
    assert all(_PATH_ID.fullmatch(path_id) for path_id in first_ids)
    assert first_ids == second_ids
    assert first.graph_hash != second.graph_hash


def test_bound_path_identity_is_stable_and_component_addressed(
    method_spec: MethodSpec,
    scenario_position: ScenarioPosition,
    invariant: InvariantProjection,
    verification_plan: VerificationPlan,
) -> None:
    base_path_id = f"qdl-attack-{'a' * 64}"
    base = _path(
        base_path_id,
        method_spec,
        scenario_position,
        invariant,
        verification_plan,
    )
    rebuilt = _path(
        base_path_id,
        method_spec,
        scenario_position,
        invariant,
        verification_plan,
    )

    identity = _version_id(base)
    assert identity == _version_id(rebuilt)
    assert _VERSIONED_PATH_ID.fullmatch(identity)

    variants = {
        _version_id(dataclasses.replace(base, path_id=f"qdl-attack-{'b' * 64}")),
        _version_id(dataclasses.replace(base, kind="forbidden")),
        _version_id(
            _path(
                base_path_id,
                method_spec.model_copy(update={"method_id": "other.Method"}),
                scenario_position,
                invariant,
                verification_plan,
            )
        ),
        _version_id(
            _path(
                base_path_id,
                method_spec,
                scenario_position.model_copy(update={"scenario_id": "other-scenario"}),
                invariant,
                verification_plan,
            )
        ),
        _version_id(
            _path(
                base_path_id,
                method_spec,
                scenario_position,
                invariant.model_copy(
                    update={
                        "invariant_id": "other-invariant",
                        "norm_fact": Fact(
                            context=Context.ACCEPTED,
                            predicate=Predicate.from_name("prevents"),
                            args=(
                                Atom(value="norm:other"),
                                allowed(Atom(value="action:other")),
                            ),
                        ),
                    }
                ),
                verification_plan,
            )
        ),
        _version_id(
            _path(
                base_path_id,
                method_spec,
                scenario_position,
                invariant,
                verification_plan.model_copy(update={"probe_fields": ("secret_id",)}),
            )
        ),
    }

    assert identity not in variants
    assert len(variants) == 6


def _path(
    path_id: str,
    method: MethodSpec,
    scenario: ScenarioPosition,
    invariant: InvariantProjection,
    plan: VerificationPlan,
) -> QdlExecutionPath:
    step = QdlExecutionStep(
        step_id=f"step:{path_id}:0",
        goal_id=f"goal:{path_id}",
        plan=plan,
        method=method,
        scenario=scenario,
        invariant=invariant,
    )
    return QdlExecutionPath(
        path_id=path_id,
        goal_id=f"goal:{path_id}",
        kind="attack",
        description="identity test path",
        steps=(step,),
    )


def test_bound_version_tracks_own_requirements_not_whole_evidence_graph(
    method_spec, scenario_position, invariant, verification_plan
):
    action = Atom(value="action:" + method_spec.method_id)
    source = Atom(value="action:opaque.source")
    effect = allowed(source)

    def fact(name, *args, context=Context.CONTRACT):
        return Fact(context=context, predicate=Predicate.from_name(name), args=args)

    graph = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action")),
            fact("is", source, Atom(value="Action")),
            fact("is", effect, Atom(value="Effect")),
        )
    )
    base = _path(
        f"qdl-attack-{'a' * 64}",
        method_spec,
        scenario_position,
        invariant,
        verification_plan,
    )

    def identity(evidence):
        path = dataclasses.replace(
            base, steps=(dataclasses.replace(base.steps[0], evidence_graph=evidence),)
        )
        return _version_id(path)

    original = identity(graph)
    assert original == identity(
        QdlGraph(
            facts=(
                *graph.facts,
                fact("is", Atom(value="resource:unrelated"), Atom(value="Resource")),
            )
        )
    )
    assert original == identity(
        QdlGraph(
            facts=(
                *graph.facts,
                fact("requires", action, effect, context=Context.PROPOSAL),
            )
        )
    )
    assert original != identity(
        QdlGraph(facts=(*graph.facts, fact("requires", action, effect)))
    )


def test_shared_requirements_are_scoped_to_one_versioning_call(
    method_spec, scenario_position, invariant, verification_plan, monkeypatch
):
    from cloud_dast.runtime.execution import metadata

    action = Atom(value=f"action:{method_spec.method_id}")
    source = Atom(value="action:source")
    effect = allowed(source)

    def fact(name, *args):
        return Fact(
            context=Context.CONTRACT, predicate=Predicate.from_name(name), args=args
        )

    graph = QdlGraph(
        facts=(
            fact("is", action, Atom(value="Action")),
            fact("is", source, Atom(value="Action")),
            fact("is", effect, Atom(value="Effect")),
        )
    )
    enriched = QdlGraph(facts=(*graph.facts, fact("requires", action, effect)))
    base = _path("path", method_spec, scenario_position, invariant, verification_plan)
    first = dataclasses.replace(base.steps[0], evidence_graph=graph)
    changed = dataclasses.replace(first, evidence_graph=enriched)
    paths = [
        dataclasses.replace(base, steps=(first, first)),
        dataclasses.replace(base, steps=(changed, first)),
    ]
    calls = []
    derive = metadata.derive_requirements

    def counted(snapshot, **kwargs):
        calls.append(snapshot)
        return derive(snapshot, **kwargs)

    monkeypatch.setattr(metadata, "derive_requirements", counted)
    results = version_executable_inputs(paths)
    assert results[0].path_id != results[1].path_id
    assert len(calls) == 2
    assert calls[0] is graph and calls[1] is enriched
    assert version_executable_inputs(paths) == results
    assert len(calls) == 4
