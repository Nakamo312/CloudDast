from __future__ import annotations

import json

from cloud_dast.contracts.assessment import (
    CoverageMatrix,
    EffectCoverageCell,
    FieldCoverageCell,
    StateMachineCoverage,
    StateMachineStateCoverage,
)
from cloud_dast.model import (
    PolicyVerdict,
    Severity,
    VerdictStatus,
)
from cloud_dast.verification.oracles import leads
from cloud_dast_reporting import (
    CampaignInfo,
    CampaignMetricsSnapshot,
    OwaspAxisScore,
    ReportService,
    TokenUsageSnapshot,
)
from cloud_dast_reporting.formats.json import (
    REPORT_SCHEMA_NAME,
    REPORT_SCHEMA_VERSION,
    JsonReportRenderer,
)


def _coverage() -> CoverageMatrix:
    return CoverageMatrix(
        service="orders",
        fields=(
            FieldCoverageCell(
                field_id="field:z",
                field_name="z",
                field_kind="input",
                semantic_role="object_ref",
                primitive="marker",
                status="covered",
                rationale="observed",
                request_executed=True,
                request_deficit=False,
                oracle_witness_observed=True,
            ),
            FieldCoverageCell(
                field_id="field:a",
                field_name="a",
                field_kind="input",
                semantic_role="object_ref",
                primitive="unknown",
                status="blind",
                deficit="capability_blind",
                rationale="no witness",
                request_executed=False,
                request_deficit=True,
                oracle_witness_observed=False,
            ),
        ),
        effects=(
            EffectCoverageCell(
                effect_id="effect:changed",
                effect_kind="changed",
                primitive="marker",
                status="unresolved",
                deficit="evidence_blind",
                rationale="not observed",
            ),
        ),
        state_machine=StateMachineCoverage(
            states=(
                StateMachineStateCoverage(
                    state_id="draft",
                    initial=True,
                    reachable=True,
                    status="covered",
                ),
            ),
            initial_states=("draft",),
            reachable_states=("draft",),
        ),
    )


def _lead() -> leads.Lead:
    return leads.Lead(
        norm_id="norm:lead:sensitive:0123456789ab",
        role="sensitive",
        effect="has(principal:attacker, field(resource:user, email))",
        verdict=PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=1.0,
            rationale="operator review",
            model_id="classification-lead",
            deterministic=True,
            grounded=False,
        ),
    )


def _metrics() -> CampaignMetricsSnapshot:
    return CampaignMetricsSnapshot(
        intent_states={"intent:2": "verified", "intent:1": "blocked"},
        intent_labels={"intent:2": "B", "intent:1": "A"},
        tokens=TokenUsageSnapshot(
            input_tokens=10,
            cached_input_tokens=4,
            output_tokens=2,
            request_count=3,
        ),
        tokens_by_phase={
            "planning": TokenUsageSnapshot(input_tokens=3, output_tokens=1),
            "grounding": TokenUsageSnapshot(input_tokens=7, output_tokens=1),
        },
        model_id="model",
        generator_stats={
            ("action:z", "fuzzing"): {"pass": 2, "fail": 1},
            ("action:a", "template"): {"pass": 1},
        },
        total_checks=3,
        total_findings=1,
        grounding_cache_hits=2,
        grounding_cache_misses=1,
        diff_pairs_evaluated=4,
        diff_pairs_by_mode={"factors": 3, "payload": 1},
        diff_norms_promoted=2,
    )


def test_render_emits_the_versioned_bundle_schema(
    finding,
    allowed_observation,
    invariant,
    scenario_position,
) -> None:
    unclassified_finding = finding.model_copy(
        update={
            "owasp": (),
            "minimal_poc": (("secret_id", ""),),
        }
    )
    bundle = ReportService().bundle(
        campaign=CampaignInfo(
            service="orders",
            principal_id="attacker",
            resource_id="resource",
            scenario_id=scenario_position.scenario_id,
            campaign_id="campaign:orders",
            run_id="run:orders",
        ),
        findings=(unclassified_finding,),
        observations=(allowed_observation,),
        invariants=(invariant,),
        scenarios=(scenario_position,),
        leads=(_lead(),),
        metrics=_metrics(),
        coverage=_coverage(),
    )

    document = json.loads(JsonReportRenderer().render(bundle))

    assert set(document) == {
        "schema",
        "schema_version",
        "campaign",
        "findings",
        "finding_summary",
        "diagnostics",
        "observations",
        "invariants",
        "scenarios",
        "scenario_classes",
        "scenario_coverage",
        "leads",
        "metrics",
        "coverage",
        "owasp",
        "owasp_ground_truth",
    }
    assert document["schema"] == REPORT_SCHEMA_NAME
    assert document["schema_version"] == REPORT_SCHEMA_VERSION
    assert document["campaign"]["service"] == "orders"
    assert document["findings"][0]["finding_id"] == finding.finding_id
    assert document["findings"][0]["minimal_poc"] == [["secret_id", ""]]
    assert document["diagnostics"] == []
    assert document["observations"][0]["observation_id"] == (
        allowed_observation.observation_id
    )
    assert document["invariants"][0]["invariant_id"] == invariant.invariant_id
    assert document["scenarios"][0]["scenario_id"] == scenario_position.scenario_id
    assert document["scenario_coverage"] == {
        scenario_position.scenario_id: True,
    }
    assert document["leads"][0]["norm_id"] == _lead().norm_id
    assert document["metrics"]["tokens"]["total"] == 12
    assert document["metrics"]["generators"][0]["action_id"] == "action:a"
    assert document["coverage"]["field_cells"][0]["field_id"] == "field:a"
    assert document["coverage"]["field_cells"][0]["request_executed"] is False
    assert document["coverage"]["field_cells"][0]["request_deficit"] is True
    assert document["coverage"]["field_cells"][0]["oracle_witness_observed"] is False
    assert document["coverage"]["field_cells"][1]["request_executed"] is True
    assert document["coverage"]["field_cells"][1]["request_deficit"] is False
    assert document["coverage"]["field_cells"][1]["oracle_witness_observed"] is True
    assert document["coverage"]["request_deficit_count"] == 1
    assert document["coverage"]["effect_cells"][0]["effect_kind"] == "changed"
    assert document["coverage"]["term_cells"]
    assert document["coverage"]["missing_factor_counts"]
    assert document["coverage"]["deficits"]["capability_blind"] == 1
    assert document["coverage"]["gaps"][0]["deficit"] == "capability_blind"
    assert document["coverage"]["state_machine"]["initial_states"] == ["draft"]
    assert document["owasp"] == [
        {"category": "unclassified", "count": 1, "ring_fraction": 1.0},
    ]
    assert document["owasp_ground_truth"] is None


def test_render_excludes_classification_deficits_from_findings(finding) -> None:
    deficit = finding.model_copy(
        update={
            "finding_id": "finding:deficit",
            "vulnerability_class": "classification_deficit",
            "classification_deficits": ("missing_input_role",),
        }
    )
    bundle = ReportService().bundle(
        campaign=CampaignInfo(service="orders"),
        findings=(deficit,),
    )

    document = json.loads(JsonReportRenderer().render(bundle))

    assert document["findings"] == []
    assert document["finding_summary"] == []
    assert document["owasp"] == []


def test_render_projects_classification_deficits_into_diagnostics(finding) -> None:
    deficit = finding.model_copy(
        update={
            "finding_id": "finding:deficit",
            "vulnerability_class": "classification_deficit",
            "classification_deficits": ("missing_input_role",),
        }
    )
    bundle = ReportService().bundle(
        campaign=CampaignInfo(service="orders"),
        findings=(deficit,),
    )

    document = json.loads(JsonReportRenderer().render(bundle))

    assert len(document["diagnostics"]) == 1
    diagnostic = document["diagnostics"][0]
    assert diagnostic["finding_id"] == deficit.finding_id
    assert diagnostic["observation_id"] == deficit.observation_id
    assert diagnostic["invariant_id"] == deficit.invariant_id
    assert diagnostic["method_id"] == deficit.method_id
    assert diagnostic["scenario_id"] == deficit.scenario_id
    assert diagnostic["vulnerability_class"] == "classification_deficit"
    assert diagnostic["classification_deficits"] == ["missing_input_role"]
    assert diagnostic["severity"] == "high"


def test_render_keeps_confirmed_findings_as_findings(finding) -> None:
    bundle = ReportService().bundle(
        campaign=CampaignInfo(service="orders"),
        findings=(finding,),
    )

    document = json.loads(JsonReportRenderer().render(bundle))

    assert [item["finding_id"] for item in document["findings"]] == [finding.finding_id]
    assert document["findings"][0]["vulnerability_class"] == (
        finding.vulnerability_class
    )
    assert document["diagnostics"] == []
    assert document["finding_summary"] == [
        {
            "vulnerability_class": finding.vulnerability_class,
            "cwe": list(sorted(finding.cwe)),
            "severity": str(finding.severity),
            "count": 1,
        }
    ]


def test_render_emits_finding_summary_groups(finding) -> None:
    first = finding.model_copy(
        update={
            "finding_id": "finding-1",
            "vulnerability_class": "authorization-policy-bypass",
            "cwe": ("CWE-862", "CWE-284"),
        }
    )
    second = finding.model_copy(
        update={
            "finding_id": "finding-2",
            "vulnerability_class": "authorization-policy-bypass",
            "cwe": ("CWE-284", "CWE-862"),
        }
    )
    third = finding.model_copy(
        update={
            "finding_id": "finding-3",
            "vulnerability_class": "secret-exposure",
            "cwe": ("CWE-200",),
            "severity": Severity.CRITICAL,
        }
    )
    bundle = ReportService().bundle(
        campaign=CampaignInfo(service="orders"),
        findings=(third, second, first),
    )

    document = json.loads(JsonReportRenderer().render(bundle))

    assert document["finding_summary"] == [
        {
            "vulnerability_class": "authorization-policy-bypass",
            "cwe": ["CWE-284", "CWE-862"],
            "severity": "high",
            "count": 2,
        },
        {
            "vulnerability_class": "secret-exposure",
            "cwe": ["CWE-200"],
            "severity": "critical",
            "count": 1,
        },
    ]


def test_render_emits_owasp_ground_truth_scores(finding) -> None:
    bundle = ReportService().bundle(
        campaign=CampaignInfo(service="orders"),
        findings=(finding,),
        owasp_ground_truth=(
            OwaspAxisScore("API1", expected=2, matched=1),
            OwaspAxisScore("API3", expected=1, matched=1),
        ),
    )

    document = json.loads(JsonReportRenderer().render(bundle))

    assert document["owasp_ground_truth"] == [
        {
            "axis": "API1",
            "expected": 2,
            "matched": 1,
            "recall": 0.5,
        },
        {
            "axis": "API3",
            "expected": 1,
            "matched": 1,
            "recall": 1.0,
        },
    ]


def test_render_is_canonical_for_equivalent_bundles(
    finding,
    allowed_observation,
    invariant,
    scenario_position,
) -> None:
    second_finding = finding.model_copy(update={"finding_id": "finding:b"})
    second_observation = allowed_observation.model_copy(
        update={"observation_id": "observation:b", "check_id": "check:b"}
    )
    second_invariant = invariant.model_copy(update={"invariant_id": "invariant:b"})
    second_scenario = scenario_position.model_copy(update={"scenario_id": "scenario:b"})
    campaign = CampaignInfo(service="orders")

    forward = ReportService().bundle(
        campaign=campaign,
        findings=(finding, second_finding),
        observations=(allowed_observation, second_observation),
        invariants=(invariant, second_invariant),
        scenarios=(scenario_position, second_scenario),
        coverage=_coverage(),
    )
    reverse = ReportService().bundle(
        campaign=campaign,
        findings=(second_finding, finding),
        observations=(second_observation, allowed_observation),
        invariants=(second_invariant, invariant),
        scenarios=(second_scenario, scenario_position),
        coverage=_coverage(),
    )

    rendered = JsonReportRenderer().render(forward)

    assert rendered == JsonReportRenderer().render(reverse)
    assert rendered == json.dumps(
        json.loads(rendered),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
