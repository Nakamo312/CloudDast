"""Canonical machine-readable rendering of a report bundle."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    Finding,
    Observation,
    ScenarioPosition,
)
from cloud_dast_reporting import (
    CampaignInfo,
    CampaignMetricsSnapshot,
    OwaspAxisScore,
    QdlCoverageCounts,
    QdlCoverageModel,
    QdlEffectCoverageItem,
    QdlFieldCoverageItem,
    QdlPlanSnapshot,
    QdlStateMachineCoverageModel,
    QdlTermCoverageItem,
    ReportBundle,
    ReportLeadView,
    TokenUsageSnapshot,
)

REPORT_SCHEMA_NAME = "cloud-dast.report"
REPORT_SCHEMA_VERSION = 1


class JsonReportRenderer:
    """Render the immutable report bundle as canonical JSON."""

    def render(self, bundle: ReportBundle) -> str:
        return _canonical_json(_document(bundle))


def _document(bundle: ReportBundle) -> dict[str, object]:
    document: dict[str, object] = {
        "schema": REPORT_SCHEMA_NAME,
        "schema_version": REPORT_SCHEMA_VERSION,
        "campaign": _campaign(bundle.campaign),
        "findings": _sorted_documents(_finding(item) for item in bundle.findings),
        "finding_summary": [
            {
                "vulnerability_class": group.vulnerability_class,
                "cwe": list(group.cwe),
                "severity": str(group.severity),
                "count": group.count,
            }
            for group in bundle.finding_summary
        ],
        "diagnostics": _sorted_documents(_finding(item) for item in bundle.diagnostics),
        "observations": _sorted_documents(
            _observation(item) for item in bundle.observations
        ),
        "invariants": _sorted_documents(_invariant(item) for item in bundle.invariants),
        "scenarios": _sorted_documents(_scenario(item) for item in bundle.scenarios),
        "scenario_classes": _scenario_classes(bundle.scenario_classes),
        "scenario_coverage": dict(sorted(bundle.scenario_coverage.items())),
        "leads": _sorted_documents(_lead(item) for item in bundle.leads),
        "metrics": _metrics(bundle.metrics),
        "coverage": (
            _coverage(bundle.coverage) if bundle.coverage is not None else None
        ),
        "owasp": [
            {
                "category": item.category,
                "count": item.count,
                "ring_fraction": item.ring_fraction,
            }
            for item in bundle.owasp
        ],
        "owasp_ground_truth": (
            _owasp_ground_truth(bundle.owasp_ground_truth)
            if bundle.owasp_ground_truth is not None
            else None
        ),
    }
    if bundle.method_action_coverage is not None:
        document["method_action_coverage"] = _method_action_coverage(
            bundle.method_action_coverage
        )
    if bundle.plan is not None:
        document["plan"] = _plan(bundle.plan)
    return document


def _campaign(campaign: CampaignInfo) -> dict[str, object]:
    return {
        "service": campaign.service,
        "principal_id": campaign.principal_id,
        "resource_id": campaign.resource_id,
        "method_id": campaign.method_id,
        "max_checks": campaign.max_checks,
        "scenario_id": campaign.scenario_id,
        "campaign_id": campaign.campaign_id,
        "run_id": campaign.run_id,
        "plan_hash": campaign.plan_hash,
    }


def _finding(finding: Finding) -> dict[str, Any]:
    document = finding.model_dump(mode="json")
    for field in (
        "evidence_refs",
        "classification_deficits",
        "cwe",
        "owasp",
        "stride",
    ):
        document[field] = sorted(document[field])
    return document


def _observation(observation: Observation) -> dict[str, Any]:
    document = observation.model_dump(mode="json")
    if observation.output is not None:
        document["output"]["fields"] = sorted(
            document["output"]["fields"], key=lambda field: field[0]
        )
        document["output"]["field_names"] = sorted(observation.output.field_names)
    document["response_tree"] = sorted(
        document["response_tree"], key=lambda leaf: leaf[0]
    )
    return document


def _invariant(invariant: InvariantProjection) -> dict[str, Any]:
    return invariant.model_dump(mode="json")


def _scenario(scenario: ScenarioPosition) -> dict[str, Any]:
    document = scenario.model_dump(mode="json")
    stand = document["stand"]
    stand["effective_permissions"] = sorted(scenario.stand.effective_permissions)
    stand["resources"] = _sorted_documents(stand["resources"])
    stand["principals"] = _sorted_documents(stand["principals"])
    stand["bindings"] = _sorted_documents(stand["bindings"])
    return document


def _lead(lead: ReportLeadView) -> dict[str, object]:
    return {
        "norm_id": lead.norm_id,
        "role": lead.role,
        "effect": lead.effect,
        "verdict_status": lead.verdict_status,
        "rationale": lead.rationale,
    }


def _owasp_ground_truth(
    scores: Iterable[OwaspAxisScore],
) -> list[dict[str, object]]:
    return [
        {
            "axis": score.axis,
            "expected": score.expected,
            "matched": score.matched,
            "recall": score.recall,
        }
        for score in sorted(scores, key=lambda score: score.axis)
    ]


def _metrics(metrics: CampaignMetricsSnapshot) -> dict[str, object]:
    return {
        "model_id": metrics.model_id,
        "current_activity": metrics.current_activity,
        "model_requests": {
            "active": metrics.model_requests_active,
            "completed": metrics.model_requests_completed,
        },
        "intents": {
            "states": dict(metrics.intent_states),
            "labels": dict(metrics.intent_labels),
        },
        "tokens": {
            **_token_usage(metrics.tokens),
            "by_phase": {
                phase: _token_usage(usage)
                for phase, usage in metrics.tokens_by_phase.items()
            },
        },
        "generators": _sorted_documents(
            {
                "action_id": action_id,
                "strategy": strategy,
                "outcomes": dict(outcomes),
            }
            for (action_id, strategy), outcomes in metrics.generator_stats.items()
        ),
        "checks": metrics.total_checks,
        "findings": metrics.total_findings,
        "grounding_cache": {
            "hits": metrics.grounding_cache_hits,
            "misses": metrics.grounding_cache_misses,
        },
        "differential": {
            "pairs_evaluated": metrics.diff_pairs_evaluated,
            "pairs_by_mode": dict(metrics.diff_pairs_by_mode),
            "norms_promoted": metrics.diff_norms_promoted,
        },
        "component_activity": {
            component: activity.summary()
            for component, activity in metrics.component_activity.items()
        },
    }


def _token_usage(usage: TokenUsageSnapshot) -> dict[str, object]:
    return {
        "input": usage.input_tokens,
        "cached_input": usage.cached_input_tokens,
        "uncached_input": usage.uncached_input_tokens,
        "output": usage.output_tokens,
        "total": usage.total_tokens,
        "cache_hit_rate": usage.cache_hit_rate,
        "requests": usage.request_count,
    }


def _coverage(coverage: QdlCoverageModel) -> dict[str, object]:
    return {
        "service": coverage.service,
        "fields": _counts(coverage.fields),
        "effects": _counts(coverage.effects),
        "by_field_kind": {
            field_kind: _counts(counts)
            for field_kind, counts in coverage.by_field_kind.items()
        },
        "deficits": dict(coverage.deficit_counts),
        "request_deficit_count": coverage.request_deficit_count,
        "field_cells": _sorted_documents(
            _field_coverage_cell(item) for item in coverage.field_cells
        ),
        "effect_cells": _sorted_documents(
            _effect_coverage_cell(item) for item in coverage.effect_cells
        ),
        "term_cells": _sorted_documents(
            _term_coverage_cell(item) for item in coverage.term_cells
        ),
        "missing_factor_counts": dict(sorted(coverage.missing_factor_counts.items())),
        "gaps": _sorted_documents(_gap_cell(item) for item in coverage.gaps),
        "state_machine": (
            _state_machine(coverage.state_machine)
            if coverage.state_machine is not None
            else None
        ),
    }


def _term_coverage_cell(cell: QdlTermCoverageItem) -> dict[str, object]:
    return {
        "term_id": cell.term_id,
        "term_kind": cell.term_kind,
        "status": cell.status,
        "deficit": cell.deficit,
        "missing_factor": cell.missing_factor,
        "rationale": cell.rationale,
    }


def _method_action_coverage(model) -> dict[str, object]:
    return {
        "methods": dict(sorted(model.methods.items())),
        "actions": dict(sorted(model.actions.items())),
    }


def _plan(plan: QdlPlanSnapshot) -> dict[str, object]:
    return {
        "graph_hash": plan.graph_hash,
        "snapshot_kind": plan.snapshot_kind,
        "paths": [
            {
                "path_id": path.path_id,
                "goal_id": path.goal_id,
                "gate": path.gate,
                "steps": [
                    {"step_id": step.step_id, "method_id": step.method_id}
                    for step in path.steps
                ],
            }
            for path in plan.paths
        ],
    }


def _counts(counts: QdlCoverageCounts) -> dict[str, object]:
    return {
        "total": counts.total,
        "covered": counts.covered,
        "unresolved": counts.unresolved,
        "blind": counts.blind,
        "not_applicable": counts.not_applicable,
    }


def _field_coverage_cell(cell: QdlFieldCoverageItem) -> dict[str, object]:
    return {
        "field_id": cell.field_id,
        "field_name": cell.field_name,
        "field_kind": cell.field_kind,
        "semantic_role": cell.semantic_role,
        "primitive": cell.primitive,
        "status": cell.status,
        "deficit": cell.deficit,
        "rationale": cell.rationale,
        "request_executed": cell.request_executed,
        "request_deficit": cell.request_deficit,
        "oracle_witness_observed": cell.oracle_witness_observed,
    }


def _effect_coverage_cell(cell: QdlEffectCoverageItem) -> dict[str, object]:
    return {
        "effect_id": cell.effect_id,
        "effect_kind": cell.effect_kind,
        "primitive": cell.primitive,
        "status": cell.status,
        "deficit": cell.deficit,
        "rationale": cell.rationale,
    }


def _gap_cell(cell: QdlFieldCoverageItem | QdlEffectCoverageItem) -> dict[str, object]:
    if isinstance(cell, QdlFieldCoverageItem):
        return _field_coverage_cell(cell)
    return _effect_coverage_cell(cell)


def _state_machine(
    state_machine: QdlStateMachineCoverageModel,
) -> dict[str, object]:
    return {
        "states": _counts(state_machine.states),
        "transitions": _counts(state_machine.transitions),
        "forbidden_states": _counts(state_machine.forbidden_states),
        "initial_states": list(state_machine.initial_states),
        "reachable_states": list(state_machine.reachable_states),
        "mismatches": state_machine.mismatches,
    }


def _scenario_classes(
    classes: Mapping[object, tuple[ScenarioPosition, ...]],
) -> list[dict[str, object]]:
    return _sorted_documents(
        {
            "key": _class_key(key),
            "scenario_ids": sorted(scenario.scenario_id for scenario in scenarios),
        }
        for key, scenarios in classes.items()
    )


def _class_key(key: object) -> list[str]:
    if isinstance(key, tuple):
        return [str(item) for item in key]
    return [str(key)]


def _sorted_documents(
    documents: Iterable[Mapping[str, object]],
) -> list[dict[str, object]]:
    return sorted(
        (dict(document) for document in documents),
        key=_canonical_json,
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
