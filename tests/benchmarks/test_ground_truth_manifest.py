"""Tests for the versioned NSFy Bench ground-truth manifest."""

from __future__ import annotations

import pytest
from benchmarks.nsfy_bench import M1_SCENARIOS, load_manifest, match_findings
from benchmarks.nsfy_bench.manifest import GroundTruthManifest
from benchmarks.nsfy_bench.norms import norm_facts
from pydantic import ValidationError

from cloud_dast.model import (
    Finding,
    Severity,
    VerdictStatus,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    Term,
    canonical_json,
)
from cloud_dast.qdl.graph_ops import atom_value


def _effects() -> dict[str, Term]:
    effects: dict[str, Term] = {}
    for fact in norm_facts():
        if fact.predicate.name != "prevents" or len(fact.args) != 2:
            continue
        norm_id = atom_value(fact.args[0])
        if norm_id is not None:
            effects.setdefault(norm_id, fact.args[1])
    return effects


def _scenario_by_id(scenario_id: str):
    return next(
        scenario for scenario in M1_SCENARIOS if scenario.scenario_id == scenario_id
    )


def _finding(
    scenario,
    *,
    finding_id: str,
    invariant_id: str,
    cwe: tuple[str, ...],
) -> Finding:
    return Finding(
        finding_id=finding_id,
        observation_id=f"observation-{finding_id}",
        invariant_id=invariant_id,
        method_id=scenario.method_id,
        scenario_id=scenario.scenario_id,
        severity=Severity.HIGH,
        title="Engine finding",
        description="Synthetic finding for matcher tests",
        remediation="Fix the defect",
        cwe=cwe,
        norm_fact=Fact(
            context=Context.ACCEPTED,
            predicate=Predicate.from_name("prevents"),
            args=(Atom(value=invariant_id), _effects()[scenario.norm_id]),
        ),
    )


def test_manifest_tracks_the_planted_stand_defects() -> None:
    expected_scenarios = tuple(
        scenario for scenario in M1_SCENARIOS if scenario.expected is VerdictStatus.FAIL
    )
    effects = _effects()
    manifest = load_manifest()

    assert manifest.schema_version == 1
    assert tuple(bug.bug_id for bug in manifest.bugs) == tuple(
        scenario.scenario_id for scenario in expected_scenarios
    )
    for bug, scenario in zip(manifest.bugs, expected_scenarios, strict=True):
        assert bug.cwe == scenario.cwe
        assert bug.method_id == scenario.method_id
        assert bug.condition == canonical_json(effects[scenario.norm_id])


def test_matcher_reports_tp_fp_and_fn() -> None:
    sql = _scenario_by_id("sql-injection-search")
    control = _scenario_by_id("control-invoice-read")
    tp = _finding(
        sql,
        finding_id="finding-tp",
        invariant_id="engine-generated-invariant",
        cwe=sql.cwe,
    )
    fp = _finding(
        control,
        finding_id="finding-fp",
        invariant_id="engine-control-finding",
        cwe=control.cwe,
    )

    report = match_findings((tp, fp))

    assert report.tp_count == 1
    assert report.fp_count == 1
    assert report.fn_count == 8
    assert report.findings[0].classification == "TP"
    assert report.findings[0].expected_bug_id == "sql-injection-search"
    assert report.findings[1].classification == "FP"
    assert report.findings[1].expected_bug_id is None
    assert tuple(outcome.bug_id for outcome in report.false_negatives) == tuple(
        bug.bug_id
        for bug in report.manifest.bugs
        if bug.bug_id != "sql-injection-search"
    )
    assert report.precision == 0.5
    assert report.recall == 1 / 9
    assert report.f1 == 2 / 11


def test_matcher_uses_method_and_condition_not_engine_ids() -> None:
    scenario = _scenario_by_id("bola-order-read")
    finding = _finding(
        scenario,
        finding_id="finding-generated-id",
        invariant_id="invariant:qdl:engine-generated:digest",
        cwe=(),
    )

    report = match_findings((finding,))

    assert report.tp_count == 1
    assert report.findings[0].expected_bug_id == "bola-order-read"
    assert report.findings[0].cwe_matches is None
    assert report.cwe_mismatches == ()


def test_matcher_counts_duplicates_and_wrong_conditions_as_fp() -> None:
    sql = _scenario_by_id("sql-injection-search")
    first = _finding(
        sql,
        finding_id="finding-first",
        invariant_id="invariant:first",
        cwe=sql.cwe,
    )
    duplicate = _finding(
        sql,
        finding_id="finding-duplicate",
        invariant_id="invariant:duplicate",
        cwe=sql.cwe,
    )
    wrong_condition = _finding(
        _scenario_by_id("path-traversal-doc"),
        finding_id="finding-wrong-condition",
        invariant_id="invariant:wrong-condition",
        cwe=("CWE-89",),
    )
    wrong_condition = wrong_condition.model_copy(
        update={
            "norm_fact": Fact(
                context=Context.ACCEPTED,
                predicate=Predicate.from_name("prevents"),
                args=(
                    Atom(value="invariant:wrong-condition"),
                    _effects()["norm:sql-injection-search"],
                ),
            )
        }
    )

    report = match_findings((first, duplicate, wrong_condition))

    assert report.tp_count == 1
    assert report.fp_count == 2
    assert report.fn_count == 8
    assert report.findings[1].classification == "FP"
    assert report.findings[1].expected_bug_id == "sql-injection-search"
    assert report.findings[2].classification == "FP"
    assert report.findings[2].expected_bug_id is None
    assert report.unexpected_findings == (report.findings[2],)


def test_matcher_reports_cwe_mismatch_without_changing_detection() -> None:
    scenario = _scenario_by_id("mass-assign-total")
    finding = _finding(
        scenario,
        finding_id="finding-wrong-cwe",
        invariant_id="invariant:mass-assignment",
        cwe=("CWE-94",),
    )

    report = match_findings((finding,))

    assert report.tp_count == 1
    assert report.findings[0].cwe_matches is False
    assert report.cwe_mismatches == ("finding-wrong-cwe",)


def test_manifest_rejects_unknown_schema_version() -> None:
    payload = load_manifest().model_dump(mode="json")
    payload["schema_version"] = 2

    with pytest.raises(ValidationError, match="schema_version"):
        GroundTruthManifest.model_validate(payload)


def test_manifest_rejects_a_corrupted_fingerprint() -> None:
    payload = load_manifest().model_dump(mode="json")
    payload["bugs"][0]["fingerprint"] = "0" * 64

    with pytest.raises(ValidationError, match="fingerprint does not match"):
        GroundTruthManifest.model_validate(payload)
