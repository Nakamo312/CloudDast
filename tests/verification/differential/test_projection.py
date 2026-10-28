"""Runtime QDL projection of measured control/treatment differences."""

from __future__ import annotations

from cloud_dast.qdl.graph import Atom, Context, canonical_json
from cloud_dast.verification.differential import project_diff
from cloud_dast.verification.differential.report import DiffReport


def _report(
    *,
    action_id: str = "grpc:orders.Get",
    control_observation_id: str = "control-1",
    treatment_observation_id: str = "treatment-1",
) -> DiffReport:
    return DiffReport(
        action_id=action_id,
        control_observation_id=control_observation_id,
        treatment_observation_id=treatment_observation_id,
        outcome_differs=True,
        value_differs=("email",),
    )


def test_project_diff_emits_valid_runtime_graph() -> None:
    graph = project_diff(_report())

    # QdlGraph construction itself validates declarations and references.
    assert all(fact.context is Context.RUNTIME for fact in graph.facts)
    declarations = {
        canonical_json(fact.args[0])
        for fact in graph.facts
        if fact.predicate.name == "is"
    }
    assert declarations == {
        canonical_json(Atom(value="action:grpc:orders.Get")),
        canonical_json(Atom(value="observation:control-1")),
        canonical_json(Atom(value="observation:treatment-1")),
    }


def test_project_diff_links_pair_and_attaches_evidence_to_treatment() -> None:
    graph = project_diff(_report())

    paired = [fact for fact in graph.facts if fact.predicate.name == "paired"]
    assert len(paired) == 1
    assert paired[0].args[0].value == "observation:control-1"
    assert paired[0].args[1].value == "observation:treatment-1"

    evidence = [fact for fact in graph.facts if fact.predicate.name == "evidence"]
    assert {
        (
            fact.args[0].value,
            fact.args[1].name,
            fact.args[1].args[0].value,
            fact.args[1].args[1].value,
        )
        for fact in evidence
    } == {
        (
            "observation:treatment-1",
            "differs",
            "action:grpc:orders.Get",
            "outcome",
        ),
        (
            "observation:treatment-1",
            "differs",
            "action:grpc:orders.Get",
            "value",
        ),
    }


def test_project_diff_is_stable_across_id_spellings() -> None:
    raw = project_diff(_report())
    prefixed = project_diff(
        _report(
            action_id="action:grpc:orders.Get",
            control_observation_id="observation:control-1",
            treatment_observation_id="observation:treatment-1",
        )
    )

    assert raw == prefixed
    assert raw.content_hash == prefixed.content_hash
