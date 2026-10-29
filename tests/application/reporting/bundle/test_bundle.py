from __future__ import annotations

from dataclasses import dataclass

import pytest

from cloud_dast.model import Finding
from cloud_dast_reporting import (
    CampaignInfo,
    CampaignMetricsSnapshot,
    FindingSummaryGroup,
    OwaspSlice,
    ReportService,
)
from cloud_dast_reporting.service import QdlTermCoverageItem


@dataclass(frozen=True, slots=True)
class _FieldCell:
    field_id: str
    field_name: str
    field_kind: str
    semantic_role: str
    primitive: str
    status: str
    deficit: str | None
    rationale: str
    request_executed: bool = False
    request_deficit: bool = False
    oracle_witness_observed: bool = False


@dataclass(frozen=True, slots=True)
class _TermCell:
    term_id: str
    term_kind: str
    status: str
    deficit: str | None
    missing_factor: str | None


@dataclass(frozen=True, slots=True)
class _CoverageMatrix:
    service: str
    fields: tuple[_FieldCell, ...]
    effects: tuple[()]
    state_machine: None = None

    @property
    def terms(self) -> tuple[_TermCell, ...]:
        return tuple(
            _TermCell(
                term_id=cell.field_id,
                term_kind="field",
                status=cell.status,
                deficit=cell.deficit,
                missing_factor=(
                    "runtime" if cell.deficit == "evidence_blind" else None
                ),
            )
            for cell in self.fields
        )

    @property
    def missing_factor_counts(self) -> dict[str, int]:
        return {"semantic": 0, "setup": 0, "oracle": 0, "runtime": 0}

    @property
    def request_deficit_count(self) -> int:
        return sum(cell.request_deficit for cell in self.fields)


@dataclass(frozen=True, slots=True)
class _LeadView:
    norm_id: str
    role: str
    effect: str
    verdict_status: str
    rationale: str


def test_bundle_materializes_one_immutable_report_read_model(
    finding: Finding,
    scenario_position,
) -> None:
    unclassified_finding = finding.model_copy(update={"owasp": ()})
    metrics = CampaignMetricsSnapshot(total_checks=2, total_findings=1)
    coverage = _CoverageMatrix(
        service="orders",
        fields=(
            _FieldCell(
                field_id="field:get:secret_id",
                field_name="secret_id",
                field_kind="input",
                semantic_role="object_ref",
                primitive="marker",
                status="covered",
                deficit=None,
                rationale="observed",
            ),
        ),
        effects=(),
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
        scenarios=(scenario_position,),
        metrics=metrics,
        coverage=coverage,
    )

    assert bundle.findings == (unclassified_finding,)
    assert bundle.metrics is metrics
    assert bundle.coverage is not None
    assert bundle.coverage.service == "orders"
    assert bundle.coverage.fields.covered == 1
    assert bundle.coverage.term_cells == (
        QdlTermCoverageItem(
            term_id="field:get:secret_id",
            term_kind="field",
            status="covered",
            deficit=None,
            missing_factor=None,
        ),
    )
    assert bundle.coverage.missing_factor_counts == {
        "semantic": 0,
        "setup": 0,
        "oracle": 0,
        "runtime": 0,
    }
    assert bundle.scenario_classes
    assert bundle.scenario_coverage[scenario_position.scenario_id] is False
    assert bundle.owasp[0].category == "unclassified"
    assert bundle.owasp[0].count == 1

    with pytest.raises(AttributeError):
        bundle.findings = ()
    with pytest.raises(TypeError):
        bundle.scenario_coverage["new-scenario"] = True


def test_bundle_routes_classification_deficits_to_diagnostics(
    finding: Finding,
) -> None:
    deficit = finding.model_copy(
        update={
            "finding_id": "finding:deficit",
            "vulnerability_class": "classification_deficit",
            "classification_deficits": ("missing_input_role",),
        }
    )

    bundle = ReportService().bundle(
        campaign=CampaignInfo(service="orders"),
        findings=(deficit, finding),
    )

    assert bundle.findings == (finding,)
    assert bundle.diagnostics == (deficit,)
    assert bundle.finding_summary == (
        FindingSummaryGroup(
            vulnerability_class=finding.vulnerability_class,
            cwe=tuple(sorted(finding.cwe)),
            severity=finding.severity,
            count=1,
        ),
    )
    assert bundle.owasp == (OwaspSlice(category="API5", count=1, ring_fraction=1.0),)


def test_bundle_preserves_one_row_per_stable_lead() -> None:
    lead = _LeadView(
        norm_id="lead:sensitive:digest",
        role="sensitive",
        effect="reached(input_field(action:get, secret_id))",
        verdict_status="unscoreable",
        rationale="parked for operator review",
    )
    repeated = _LeadView(
        norm_id=lead.norm_id,
        role=lead.role,
        effect=lead.effect,
        verdict_status=lead.verdict_status,
        rationale="repeat consultation without new evidence",
    )
    revised = _LeadView(
        norm_id=lead.norm_id,
        role=lead.role,
        effect=lead.effect,
        verdict_status="parked",
        rationale="revised by new evidence",
    )

    bundle = ReportService().bundle(
        campaign=CampaignInfo(service="orders"),
        leads=(lead, repeated, revised),
    )

    assert bundle.leads == (lead, revised)


def test_bundle_keeps_confirmed_findings_as_findings(finding: Finding) -> None:
    bundle = ReportService().bundle(
        campaign=CampaignInfo(service="orders"),
        findings=(finding,),
    )

    assert bundle.findings == (finding,)
    assert bundle.diagnostics == ()
    assert bundle.finding_summary[0].vulnerability_class == (
        finding.vulnerability_class
    )
    assert bundle.owasp[0].category == "API5"
