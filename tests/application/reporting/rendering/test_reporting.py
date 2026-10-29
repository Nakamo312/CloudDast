from __future__ import annotations

from collections.abc import Iterable

from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    EndpointLayer,
    Finding,
    Observation,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
)
from cloud_dast_reporting import CampaignInfo, ReportService
from cloud_dast_reporting.formats.markdown import MarkdownReportRenderer


def _render(
    findings: Iterable[Finding] = (),
    observations: Iterable[Observation] = (),
    invariants: Iterable[InvariantProjection] = (),
    scenarios: Iterable[ScenarioPosition] = (),
) -> str:
    bundle = ReportService().bundle(
        campaign=CampaignInfo(service="orders"),
        findings=findings,
        observations=observations,
        invariants=invariants,
        scenarios=scenarios,
    )
    return MarkdownReportRenderer().render(bundle)


def test_report_starts_with_title_and_summary(
    finding: Finding,
    denied_observation: Observation,
    invariant: InvariantProjection,
) -> None:
    report = _render([finding], [denied_observation], [invariant])

    lines = report.splitlines()
    assert lines[0] == "# Cloud DAST report"
    assert "- Findings: 1" in lines
    assert "- Observations: 1" in lines


def test_report_renders_every_finding(
    finding: Finding,
    denied_observation: Observation,
    invariant: InvariantProjection,
) -> None:
    report = _render([finding], [denied_observation], [invariant])

    finding_block = "\n".join(
        [
            f"### {finding.title}",
            "",
            f"- Finding ID: `{finding.finding_id}`",
            f"- Invariant ID: `{finding.invariant_id}`",
            f"- Observation ID: `{finding.observation_id}`",
            f"- Severity: {finding.severity}",
            f"- Method: `{finding.method_id}`",
            f"- Scenario: `{finding.scenario_id}`",
            f"- CWE: {', '.join(f'`{value}`' for value in finding.cwe) or 'none'}",
            (
                "- OWASP: "
                f"{', '.join(f'`{value}`' for value in finding.owasp) or 'unclassified'}"
            ),
            (
                "- STRIDE: "
                f"{', '.join(f'`{value}`' for value in finding.stride) or 'none'}"
            ),
            f"- Description: {finding.description}",
            f"- Remediation: {finding.remediation}",
        ]
    )
    assert finding_block in report


def test_report_renders_every_observation(
    finding: Finding,
    denied_observation: Observation,
    allowed_observation: Observation,
    invariant: InvariantProjection,
) -> None:
    report = _render(
        [finding],
        [denied_observation, allowed_observation],
        [invariant],
    )

    denied_block = "\n".join(
        [
            f"### Check `{denied_observation.check_id}`",
            "",
            f"- Observation ID: `{denied_observation.observation_id}`",
            f"- Observed outcome: {denied_observation.observed_outcome}",
            f"- Transport status: {denied_observation.transport_status.token}",
            f"- Response summary: {denied_observation.response_summary}",
        ]
    )
    allowed_block = "\n".join(
        [
            f"### Check `{allowed_observation.check_id}`",
            "",
            f"- Observation ID: `{allowed_observation.observation_id}`",
            f"- Observed outcome: {allowed_observation.observed_outcome}",
            f"- Transport status: {allowed_observation.transport_status.token}",
            f"- Response summary: {allowed_observation.response_summary}",
        ]
    )
    assert denied_block in report
    assert allowed_block in report
    assert "- Observations: 2" in report.splitlines()


def test_report_renders_every_invariant(
    finding: Finding,
    denied_observation: Observation,
    invariant: InvariantProjection,
) -> None:
    report = _render([finding], [denied_observation], [invariant])

    invariant_block = "\n".join(
        [
            f"### `{invariant.invariant_id}`",
            "",
            f"- Statement: {invariant.statement}",
            f"- Severity: {invariant.severity}",
            f"- Norm: `{invariant.norm_id}`",
            f"- Policy: {invariant.policy}",
        ]
    )
    assert invariant_block in report


def test_report_links_finding_to_observation_and_invariant(
    finding: Finding,
    allowed_observation: Observation,
    invariant: InvariantProjection,
) -> None:
    report = _render([finding], [allowed_observation], [invariant])

    assert finding.observation_id == allowed_observation.observation_id
    assert finding.invariant_id == invariant.invariant_id

    finding_block = "\n".join(
        [
            f"### {finding.title}",
            "",
            f"- Finding ID: `{finding.finding_id}`",
            f"- Invariant ID: `{finding.invariant_id}`",
            f"- Observation ID: `{finding.observation_id}`",
        ]
    )
    observation_block = "\n".join(
        [
            f"### Check `{allowed_observation.check_id}`",
            "",
            f"- Observation ID: `{allowed_observation.observation_id}`",
        ]
    )

    assert finding_block in report
    assert observation_block in report
    assert f"- Invariant ID: `{invariant.invariant_id}`" in report
    assert f"- Norm: `{invariant.norm_id}`" in report
    assert f"- Policy: {invariant.policy}" in report


def test_report_sections_follow_documented_order(
    finding: Finding,
    denied_observation: Observation,
    invariant: InvariantProjection,
) -> None:
    report = _render([finding], [denied_observation], [invariant])

    assert report.index("# Cloud DAST report") < report.index("## Summary")
    assert report.index("## Summary") < report.index("## Findings")
    assert report.index("## Findings") < report.index("## Observations")
    assert report.index("## Observations") < report.index("## Invariants")
    assert report.index("## Invariants") < report.index("## Scenario classes")
    assert report.index("## Scenario classes") < report.index("## Coverage")


def test_empty_report_keeps_sections_and_counts() -> None:
    report = _render()

    lines = report.splitlines()
    assert lines[0] == "# Cloud DAST report"
    assert "- Findings: 0" in lines
    assert "- Observations: 0" in lines
    assert "_No findings._" in lines
    assert "_No observations._" in lines
    assert "_No invariants._" in lines
    assert "- Scenario classes: 0" in lines
    assert "_No scenarios._" in lines
    assert "- Covered scenarios: 0 of 0" in lines


def test_report_keeps_input_order_for_multiple_items(
    finding: Finding,
    denied_observation: Observation,
    invariant: InvariantProjection,
) -> None:
    another_finding = finding.model_copy(
        update={"finding_id": "finding-second", "title": "Second finding"}
    )
    another_invariant = invariant.model_copy(
        update={"invariant_id": "invariant-second", "statement": "Second invariant"}
    )

    report = _render(
        [finding, another_finding],
        [denied_observation],
        [invariant, another_invariant],
    )

    assert report.index(f"### {finding.title}") < report.index(
        f"### {another_finding.title}"
    )
    assert report.index(f"### `{invariant.invariant_id}`") < report.index(
        f"### `{another_invariant.invariant_id}`"
    )
    assert "- Findings: 2" in report.splitlines()


def test_report_groups_scenarios_and_renders_coverage(
    scenario_position: ScenarioPosition,
    denied_observation: Observation,
) -> None:
    another_scenario = scenario_position.model_copy(
        update={"scenario_id": "same-folder-private"}
    )

    report = _render(
        [],
        [denied_observation],
        [],
        scenarios=[scenario_position, another_scenario],
    )

    lines = report.splitlines()
    assert "- Scenario classes: 1" in lines
    assert "- Scenarios: 2" in lines
    assert f"- `{scenario_position.scenario_id}`" in lines
    assert f"- `{another_scenario.scenario_id}`" in lines
    assert "- Covered scenarios: 1 of 2" in lines
    assert f"- `{scenario_position.scenario_id}`: covered" in lines
    assert f"- `{another_scenario.scenario_id}`: uncovered" in lines


def test_report_has_exact_markdown_format() -> None:
    finding = Finding(
        finding_id="finding-1",
        observation_id="observation-1",
        invariant_id="invariant-1",
        method_id="method-1",
        scenario_id="scenario-1",
        severity=Severity.HIGH,
        title="Foreign secret read",
        description="Attacker read a foreign secret",
        remediation="Restrict the role",
        vulnerability_class="function_level_authz",
        classification_deficits=(),
        cwe=("CWE-285", "CWE-284"),
        owasp=("API5",),
        stride=("E",),
    )
    observation = Observation(
        observation_id="observation-1",
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="Secret payload returned",
        transport_status=None,
    )
    invariant = InvariantProjection(
        invariant_id="invariant-1",
        norm_id="threat-1",
        statement="Attacker must not read a foreign secret",
        severity=Severity.HIGH,
        policy="response access must be denied",
    )
    scenario = ScenarioPosition(
        scenario_id="scenario-1",
        profile=ScenarioProfile(
            scope_relation=ScopeRelation.CROSS_FOLDER,
            binding_level="folder",
            endpoint_layer=EndpointLayer.PRIVATE,
            resource_state="created",
            identity_class="attacker",
            addressing_mode="direct",
        ),
        stand=StandState(),
    )

    expected = """# Cloud DAST report

## Summary

- Findings: 1
- Observations: 1

### Finding summary

| vulnerability class | CWE | severity | count |
|---|---|---|---:|
| `function_level_authz` | `CWE-284`, `CWE-285` | high | 1 |

## Campaign metrics

- Input tokens: 0
- Cached input tokens: 0
- Uncached input tokens: 0
- Output tokens: 0
- Total tokens: 0
- Model requests: 0
- Cache hit rate: 0.0%
- Wall time: 0:00:00

## Findings

### Foreign secret read

- Finding ID: `finding-1`
- Invariant ID: `invariant-1`
- Observation ID: `observation-1`
- Severity: high
- Method: `method-1`
- Scenario: `scenario-1`
- CWE: `CWE-285`, `CWE-284`
- OWASP: `API5`
- STRIDE: `E`
- Description: Attacker read a foreign secret
- Remediation: Restrict the role

## OWASP API Top 10

```text
                   ███████
            █████████████████████
         ███████████████████████████
      █████████████████████████████████
     ███████████████████████████████████
   ███████████████         ███████████████
  ████████████                 ████████████
 ███████████                     ███████████
 ██████████                       ██████████
███████████           1           ███████████
██████████                         ██████████
███████████       findings        ███████████
 ██████████                       ██████████
 ███████████                     ███████████
  ████████████                 ████████████
   ███████████████         ███████████████
     ███████████████████████████████████
      █████████████████████████████████
         ███████████████████████████
            █████████████████████
                   ███████
```

█ API5           1  100.0%  Function Level Authorization

| Category | Class | Count | Ring share |
|---|---|---:|---:|
| `API5` | Function Level Authorization | 1 | 100.0% |

_Findings tagged with several categories are counted in each; ring share is relative to classified occurrences._

## Observations

### Check `check-1`

- Observation ID: `observation-1`
- Observed outcome: allowed
- Transport status: none
- Response summary: Secret payload returned

## Invariants

### `invariant-1`

- Statement: Attacker must not read a foreign secret
- Severity: high
- Norm: `threat-1`
- Policy: response access must be denied

## Scenario classes

- Scenario classes: 1

### Class 1

- Scenarios: 1

- `scenario-1`

## Coverage

- Covered scenarios: 1 of 1

- `scenario-1`: covered
"""

    assert (
        _render(
            [finding],
            [observation],
            [invariant],
            scenarios=[scenario],
        )
        == expected
    )
