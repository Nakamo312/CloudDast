from __future__ import annotations

import hashlib
import json

from cloud_dast.model import (
    Finding,
    Severity,
)
from cloud_dast_reporting import (
    CampaignInfo,
    ReportBundle,
    ReportService,
)
from cloud_dast_reporting.formats.sarif import SarifReportRenderer


def _bundle(findings: tuple[Finding, ...] = ()) -> ReportBundle:
    return ReportService().bundle(
        campaign=CampaignInfo(service="orders"),
        findings=findings,
    )


def _finding(**changes: object) -> Finding:
    values: dict[str, object] = {
        "observation_id": "observation",
        "invariant_id": "invariant",
        "method_id": "orders.OrderService.Get",
        "scenario_id": "scenario",
        "severity": Severity.HIGH,
        "title": "Unauthorized order read",
        "description": "The attacker read another folder's order",
        "remediation": "Restrict folder-level access",
        "vulnerability_class": "authorization-policy-bypass",
        "cwe": ("CWE-862",),
        "path_id": "qdl-attack-6f56b7f6",
    }
    values.update(changes)
    return Finding(**values)  # type: ignore[arg-type]


def _render(findings: tuple[Finding, ...] = ()) -> dict[str, object]:
    return json.loads(SarifReportRenderer().render(_bundle(findings)))


def test_empty_bundle_emits_a_minimal_sarif_run() -> None:
    document = _render()

    assert document["$schema"] == (
        "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
        "sarif-schema-2.1.0.json"
    )
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "Cloud DAST"
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []
    assert run["properties"]["cloudDastFindingSummary"] == []
    assert "taxonomies" not in run


def test_results_resolve_to_rules_and_derive_path_fingerprints() -> None:
    first = _finding(
        vulnerability_class="authorization-policy-bypass",
        severity=Severity.CRITICAL,
        path_id="qdl-attack-111111",
    )
    second = _finding(
        vulnerability_class="secret-exposure",
        severity=Severity.LOW,
        cwe=("CWE-200",),
        path_id=None,
    )
    document = _render((second, first))
    run = document["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]

    assert [rule["id"] for rule in rules] == [
        "authorization-policy-bypass",
        "secret-exposure",
    ]
    assert [result["ruleId"] for result in results] == [
        "authorization-policy-bypass",
        "secret-exposure",
    ]
    assert [result["level"] for result in results] == ["error", "note"]
    for result in results:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]

    expected_hash = hashlib.sha256(b"qdl-attack-111111").hexdigest()
    assert results[0]["partialFingerprints"] == {
        "primaryLocationLineHash": expected_hash,
        "cloudDastPathIdV1": "qdl-attack-111111",
    }
    assert "partialFingerprints" not in results[1]


def test_rule_default_level_is_the_highest_severity_in_the_class() -> None:
    low = _finding(
        title="Low-severity policy bypass",
        severity=Severity.LOW,
    )
    critical = _finding(
        title="Critical policy bypass",
        severity=Severity.CRITICAL,
    )
    document = _render((low, critical))
    rule = document["runs"][0]["tool"]["driver"]["rules"][0]

    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["shortDescription"]["text"] == "Critical policy bypass"
    assert rule["help"]["text"] == "Restrict folder-level access"


def test_run_properties_include_the_finding_summary() -> None:
    first = _finding(
        vulnerability_class="authorization-policy-bypass",
        cwe=("CWE-862", "CWE-284", "CWE-862"),
    )
    second = _finding(
        vulnerability_class="secret-exposure",
        severity=Severity.CRITICAL,
        cwe=("CWE-200",),
    )

    document = _render((second, first))

    assert document["runs"][0]["properties"]["cloudDastFindingSummary"] == [
        {
            "vulnerability_class": "authorization-policy-bypass",
            "cwe": ["CWE-284", "CWE-862"],
            "severity": "high",
            "count": 1,
        },
        {
            "vulnerability_class": "secret-exposure",
            "cwe": ["CWE-200"],
            "severity": "critical",
            "count": 1,
        },
    ]


def test_cwe_is_a_well_known_taxonomy_related_to_rules_and_results() -> None:
    finding = _finding(
        cwe=("CWE-862", "CWE-284", "CWE-862"),
    )
    document = _render((finding,))
    run = document["runs"][0]
    taxonomy = run["taxonomies"][0]
    driver = run["tool"]["driver"]

    assert taxonomy["name"] == "CWE"
    assert taxonomy["organization"] == "MITRE"
    assert taxonomy["informationUri"] == "https://cwe.mitre.org/"
    assert taxonomy["isComprehensive"] is False
    assert [taxon["id"] for taxon in taxonomy["taxa"]] == [
        "CWE-284",
        "CWE-862",
    ]
    assert driver["supportedTaxonomies"] == [{"name": "CWE"}]

    relationship = driver["rules"][0]["relationships"][0]
    assert relationship["target"] == {
        "id": "CWE-284",
        "toolComponent": {"name": "CWE"},
    }
    assert relationship["kinds"] == ["superset"]
    assert run["results"][0]["taxa"] == [
        {"id": "CWE-284", "toolComponent": {"name": "CWE"}},
        {"id": "CWE-862", "toolComponent": {"name": "CWE"}},
    ]


def test_locations_are_logical_api_locations_without_fake_source_lines() -> None:
    document = _render((_finding(),))
    location = document["runs"][0]["results"][0]["locations"][0]

    assert location == {
        "logicalLocations": [
            {
                "name": "Get",
                "fullyQualifiedName": "orders.OrderService.Get",
                "kind": "member",
            },
        ],
    }
    assert "physicalLocation" not in location


def test_rendering_is_canonical_and_independent_of_finding_order() -> None:
    first = _finding(
        vulnerability_class="authorization-policy-bypass",
        path_id="qdl-attack-first",
    )
    second = _finding(
        vulnerability_class="secret-exposure",
        cwe=("CWE-200",),
        path_id="qdl-attack-second",
    )
    forward = SarifReportRenderer().render(_bundle((first, second)))
    reverse = SarifReportRenderer().render(_bundle((second, first)))

    assert forward == reverse
    assert forward == json.dumps(
        json.loads(forward),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
