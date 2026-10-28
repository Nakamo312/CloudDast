"""SARIF 2.1.0 rendering of a report bundle."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cloud_dast.model import (
    Finding,
    Severity,
)
from cloud_dast.model.evidence import severity_score
from cloud_dast_reporting import ReportBundle

SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Cloud DAST"
CWE_TAXONOMY_NAME = "CWE"

_SEVERITY_LEVEL: dict[Severity, str] = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


class SarifReportRenderer:
    """Render the immutable report bundle as canonical SARIF 2.1.0."""

    def render(self, bundle: ReportBundle) -> str:
        return _canonical_json(_document(bundle))


def _document(bundle: ReportBundle) -> dict[str, Any]:
    findings = tuple(sorted(bundle.findings, key=_finding_order))
    rules = _rules(findings)
    rule_indexes = {str(rule["id"]): index for index, rule in enumerate(rules)}
    cwes = _unique_cwe(findings)

    driver: dict[str, Any] = {
        "name": TOOL_NAME,
        "rules": rules,
    }
    if cwes:
        driver["supportedTaxonomies"] = [
            {"name": CWE_TAXONOMY_NAME},
        ]

    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "results": [
            _result(finding, rule_indexes[finding.vulnerability_class])
            for finding in findings
        ],
        "properties": {
            "cloudDastFindingSummary": [
                {
                    "vulnerability_class": group.vulnerability_class,
                    "cwe": list(group.cwe),
                    "severity": str(group.severity),
                    "count": group.count,
                }
                for group in bundle.finding_summary
            ]
        },
    }
    if cwes:
        run["taxonomies"] = [_taxonomy(cwes)]

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def _rules(findings: tuple[Finding, ...]) -> list[dict[str, Any]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.vulnerability_class, []).append(finding)

    return [
        _rule(vulnerability_class, tuple(group_findings))
        for vulnerability_class, group_findings in sorted(grouped.items())
    ]


def _rule(vulnerability_class: str, findings: tuple[Finding, ...]) -> dict[str, Any]:
    representative = min(findings, key=_rule_metadata_order)
    rule: dict[str, Any] = {
        "id": vulnerability_class,
        "name": vulnerability_class,
        "shortDescription": {"text": representative.title},
        "fullDescription": {"text": representative.description},
        "defaultConfiguration": {"level": _highest_level(findings)},
    }
    if representative.remediation:
        rule["help"] = {"text": representative.remediation}

    cwes = _unique_cwe(findings)
    if cwes:
        rule["relationships"] = [_relationship(cwe) for cwe in cwes]
    return rule


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.vulnerability_class,
        "ruleIndex": rule_index,
        "level": _SEVERITY_LEVEL[finding.severity],
        "message": {"text": finding.title},
        "locations": [_location(finding.method_id)],
    }

    cwes = _unique_cwe((finding,))
    if cwes:
        result["taxa"] = [_taxon_reference(cwe) for cwe in cwes]
    if finding.path_id is not None:
        # GitHub consumes only primaryLocationLineHash. Dynamic API findings
        # have no source line, so the content-addressed path identity is used.
        result["partialFingerprints"] = {
            "primaryLocationLineHash": _path_fingerprint(finding.path_id),
            "cloudDastPathIdV1": finding.path_id,
        }
    return result


def _location(method_id: str) -> dict[str, Any]:
    """Return a logical API location without fabricating source coordinates."""

    method_name = method_id.rsplit(".", 1)[-1]
    return {
        "logicalLocations": [
            {
                "name": method_name,
                "fullyQualifiedName": method_id,
                "kind": "member",
            },
        ],
    }


def _taxonomy(cwes: tuple[str, ...]) -> dict[str, Any]:
    return {
        "name": CWE_TAXONOMY_NAME,
        "organization": "MITRE",
        "informationUri": "https://cwe.mitre.org/",
        "isComprehensive": False,
        "taxa": [{"id": cwe, "name": cwe} for cwe in cwes],
    }


def _relationship(cwe: str) -> dict[str, Any]:
    return {
        "target": _taxon_reference(cwe),
        "kinds": ["superset"],
    }


def _taxon_reference(cwe: str) -> dict[str, Any]:
    return {
        "id": cwe,
        "toolComponent": {"name": CWE_TAXONOMY_NAME},
    }


def _highest_level(findings: tuple[Finding, ...]) -> str:
    most_severe = max(findings, key=lambda finding: severity_score(finding.severity))
    return _SEVERITY_LEVEL[most_severe.severity]


def _unique_cwe(findings: tuple[Finding, ...]) -> tuple[str, ...]:
    return tuple(sorted({cwe for finding in findings for cwe in finding.cwe if cwe}))


def _path_fingerprint(path_id: str) -> str:
    return hashlib.sha256(path_id.encode("utf-8")).hexdigest()


def _finding_order(finding: Finding) -> tuple[object, ...]:
    return (
        finding.vulnerability_class,
        -severity_score(finding.severity),
        finding.method_id,
        finding.scenario_id,
        finding.path_id or "",
        finding.title,
        finding.description,
        finding.remediation,
        tuple(sorted(finding.cwe)),
    )


def _rule_metadata_order(finding: Finding) -> tuple[object, ...]:
    return (
        -severity_score(finding.severity),
        finding.title,
        finding.description,
        finding.remediation,
        tuple(sorted(finding.cwe)),
        finding.method_id,
        finding.scenario_id,
        finding.path_id or "",
    )


def _canonical_json(document: dict[str, Any]) -> str:
    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
