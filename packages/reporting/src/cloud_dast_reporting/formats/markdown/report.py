from __future__ import annotations

import html
import json
from collections.abc import Sequence
from datetime import timedelta

from cloud_dast_reporting import ReportBundle, TokenUsageSnapshot
from cloud_dast_reporting.formats.charts import (
    category_title,
    owasp_legend_line,
    render_owasp_ascii_donut,
)


def _escape_markdown(value: object) -> str:
    """Encode an untrusted value for a Markdown text context."""

    encoded = html.escape(str(value), quote=True)
    return (
        encoded.replace("\r", "&#13;")
        .replace("\n", "&#10;")
        .replace("`", "&#96;")
        .replace("|", "&#124;")
    )


def _inline_code(value: object) -> str:
    return f"`{_escape_markdown(value)}`"


def _format_duration(duration: timedelta) -> str:
    return str(duration)


def _format_taxonomy(values: Sequence[str], *, empty: str = "none") -> str:
    unique = tuple(dict.fromkeys(values))
    if not unique:
        return empty
    return ", ".join(_inline_code(value) for value in unique)


class MarkdownReportRenderer:
    """Builds a Markdown report from the report read model."""

    def render(self, bundle: ReportBundle) -> str:
        sections = [
            ["# Cloud DAST report", ""],
            self._summary(bundle),
            self._campaign_metrics(bundle),
            self._findings(bundle),
            self._owasp_distribution(bundle),
            self._leads(bundle),
            self._observations(bundle),
            self._invariants(bundle),
            self._scenario_classes(bundle),
            self._method_action_coverage(bundle),
            self._plan(bundle),
            self._qdl_coverage(bundle),
            self._coverage(bundle),
        ]
        lines = [line for section in sections for line in section]
        return "\n".join(lines).rstrip() + "\n"

    def _summary(self, bundle: ReportBundle) -> list[str]:
        lines = [
            "## Summary",
            "",
            f"- Findings: {len(bundle.findings)}",
        ]
        if bundle.leads:
            lines.append(f"- Leads: {len(bundle.leads)}")
        lines.append(f"- Observations: {len(bundle.observations)}")
        if bundle.finding_summary:
            lines.extend(
                [
                    "",
                    "### Finding summary",
                    "",
                    "| vulnerability class | CWE | severity | count |",
                    "|---|---|---|---:|",
                ]
            )
            for group in bundle.finding_summary:
                lines.append(
                    f"| {_inline_code(group.vulnerability_class)} "
                    f"| {_format_taxonomy(group.cwe)} "
                    f"| {_escape_markdown(group.severity)} | {group.count} |"
                )
            lines.append("")
        else:
            lines.append("")
        return lines

    def _method_action_coverage(self, bundle: ReportBundle) -> list[str]:
        model = bundle.method_action_coverage
        if model is None:
            return []
        lines = [
            "## Method/action coverage",
            "",
            "### Methods",
            "",
            "| method | status |",
            "|---|---|",
        ]
        lines.extend(
            f"| {_inline_code(method_id)} | {'covered' if covered else 'uncovered'} |"
            for method_id, covered in sorted(model.methods.items())
        )
        lines.extend(["", "### Actions", "", "| action | status |", "|---|---|"])
        lines.extend(
            f"| {_inline_code(action_id)} | {'covered' if covered else 'uncovered'} |"
            for action_id, covered in sorted(model.actions.items())
        )
        lines.append("")
        return lines

    def _plan(self, bundle: ReportBundle) -> list[str]:
        plan = bundle.plan
        if plan is None:
            return []
        lines = [
            "## Runtime plan",
            "",
            f"- Snapshot: {_inline_code(plan.snapshot_kind)}",
            f"- Graph hash: {_inline_code(plan.graph_hash)}",
            f"- Paths: {len(plan.paths)}",
            "",
        ]
        for path in plan.paths:
            methods = ", ".join(_inline_code(step.method_id) for step in path.steps)
            lines.append(
                f"- {_inline_code(path.path_id)} ({_inline_code(path.goal_id)}): "
                f"{methods or 'no steps'}"
            )
        lines.append("")
        return lines

    def _campaign_metrics(self, bundle: ReportBundle) -> list[str]:
        metrics = bundle.metrics
        tokens = metrics.tokens
        lines = [
            "## Campaign metrics",
            "",
            f"- Input tokens: {tokens.input_tokens}",
            f"- Cached input tokens: {tokens.cached_input_tokens}",
            f"- Uncached input tokens: {tokens.uncached_input_tokens}",
            f"- Output tokens: {tokens.output_tokens}",
            f"- Total tokens: {tokens.total_tokens}",
            f"- Model requests: {tokens.request_count}",
            f"- Cache hit rate: {tokens.cache_hit_rate:.1%}",
            f"- Wall time: {_format_duration(metrics.timing.wall_time)}",
        ]

        phases = set(metrics.tokens_by_phase) | set(metrics.timing.phase_elapsed)
        if not phases:
            lines.append("")
            return lines

        lines.extend(
            [
                "",
                ("| phase | input | cached | output | total | requests | elapsed |"),
                "|---|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for phase in sorted(phases):
            usage = metrics.tokens_by_phase.get(phase, TokenUsageSnapshot())
            elapsed = metrics.timing.phase_elapsed.get(phase, timedelta())
            lines.append(
                f"| {_inline_code(phase)} | {usage.input_tokens}"
                f" | {usage.cached_input_tokens} | {usage.output_tokens}"
                f" | {usage.total_tokens} | {usage.request_count}"
                f" | {_format_duration(elapsed)} |"
            )
        lines.append("")
        return lines

    def _owasp_distribution(self, bundle: ReportBundle) -> list[str]:
        """Render the Dota-style radial OWASP distribution section."""

        slices = bundle.owasp
        if not slices:
            return []
        lines = ["## OWASP API Top 10", ""]
        lines.append("```text")
        lines.extend(
            render_owasp_ascii_donut(
                slices, total_findings=len(bundle.findings)
            ).splitlines()
        )
        lines.append("```")
        lines.append("")
        for index, slice_ in enumerate(slices):
            lines.append(owasp_legend_line(slice_, index))
        lines.append("")
        lines.extend(
            [
                "| Category | Class | Count | Ring share |",
                "|---|---|---:|---:|",
            ]
        )
        for slice_ in slices:
            lines.append(
                f"| {_inline_code(slice_.category)} "
                f"| {_escape_markdown(category_title(slice_.category))} "
                f"| {slice_.count} | {slice_.ring_fraction:.1%} |"
            )
        lines.append("")
        lines.append(
            "_Findings tagged with several categories are counted in each; "
            "ring share is relative to classified occurrences._"
        )
        lines.append("")
        return lines

    def _findings(self, bundle: ReportBundle) -> list[str]:
        if not bundle.findings:
            return ["## Findings", "", "_No findings._", ""]

        lines = ["## Findings", ""]
        for finding in bundle.findings:
            lines.extend(
                [
                    f"### {_escape_markdown(finding.title)}",
                    "",
                    f"- Finding ID: {_inline_code(finding.finding_id)}",
                    f"- Invariant ID: {_inline_code(finding.invariant_id)}",
                    f"- Observation ID: {_inline_code(finding.observation_id)}",
                    f"- Severity: {_escape_markdown(finding.severity)}",
                    f"- Method: {_inline_code(finding.method_id)}",
                    f"- Scenario: {_inline_code(finding.scenario_id)}",
                    f"- CWE: {_format_taxonomy(finding.cwe)}",
                    f"- OWASP: {_format_taxonomy(finding.owasp, empty='unclassified')}",
                    f"- STRIDE: {_format_taxonomy(finding.stride)}",
                    *(
                        [f"- Attack goal: {_inline_code(finding.goal_id)}"]
                        if finding.goal_id
                        else []
                    ),
                    *(
                        [f"- Attack path: {_inline_code(finding.path_id)}"]
                        if finding.path_id
                        else []
                    ),
                    *(
                        [f"- Attack step: {_inline_code(finding.step_id)}"]
                        if finding.step_id
                        else []
                    ),
                    *(
                        [f"- Oracle confidence: {_escape_markdown(finding.confidence)}"]
                        if finding.confidence is not None
                        else []
                    ),
                    *(
                        [
                            "- Minimal PoC: "
                            + _inline_code(
                                json.dumps(
                                    dict(finding.minimal_poc),
                                    ensure_ascii=False,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                )
                            )
                        ]
                        if finding.minimal_poc is not None
                        else []
                    ),
                    *(
                        [
                            "- Evidence: "
                            + ", ".join(
                                _escape_markdown(ref) for ref in finding.evidence_refs
                            )
                        ]
                        if finding.evidence_refs
                        else []
                    ),
                    f"- Description: {_escape_markdown(finding.description)}",
                    f"- Remediation: {_escape_markdown(finding.remediation)}",
                    "",
                ]
            )
        return lines

    def _leads(self, bundle: ReportBundle) -> list[str]:
        if not bundle.leads:
            return []

        lines = ["## Leads", ""]
        for lead in bundle.leads:
            lines.extend(
                [
                    f"### {_inline_code(lead.norm_id)}",
                    "",
                    f"- Verdict: {_escape_markdown(lead.verdict_status)}",
                    f"- Role: {_escape_markdown(lead.role)}",
                    f"- Effect: {_inline_code(lead.effect)}",
                    f"- Rationale: {_escape_markdown(lead.rationale)}",
                    "",
                ]
            )
        return lines

    def _observations(self, bundle: ReportBundle) -> list[str]:
        if not bundle.observations:
            return ["## Observations", "", "_No observations._", ""]

        lines = ["## Observations", ""]
        for observation in bundle.observations:
            transport_status = (
                observation.transport_status.token
                if observation.transport_status is not None
                else "none"
            )
            lines.extend(
                [
                    f"### Check {_inline_code(observation.check_id)}",
                    "",
                    f"- Observation ID: {_inline_code(observation.observation_id)}",
                    (
                        "- Observed outcome: "
                        f"{_escape_markdown(observation.observed_outcome)}"
                    ),
                    f"- Transport status: {_escape_markdown(transport_status)}",
                    (
                        "- Response summary: "
                        f"{_escape_markdown(observation.response_summary)}"
                    ),
                    "",
                ]
            )
        return lines

    def _invariants(self, bundle: ReportBundle) -> list[str]:
        if not bundle.invariants:
            return ["## Invariants", "", "_No invariants._", ""]

        lines = ["## Invariants", ""]
        for invariant in bundle.invariants:
            lines.extend(
                [
                    f"### {_inline_code(invariant.invariant_id)}",
                    "",
                    f"- Statement: {_escape_markdown(invariant.statement)}",
                    f"- Severity: {_escape_markdown(invariant.severity)}",
                    f"- Norm: {_inline_code(invariant.norm_id)}",
                    *(
                        [f"- Policy: {_escape_markdown(invariant.policy)}"]
                        if invariant.policy
                        else []
                    ),
                    "",
                ]
            )
        return lines

    def _scenario_classes(self, bundle: ReportBundle) -> list[str]:
        classes = bundle.scenario_classes
        lines = [
            "## Scenario classes",
            "",
            f"- Scenario classes: {len(classes)}",
            "",
        ]

        if not classes:
            lines.extend(["_No scenarios._", ""])
            return lines

        for number, scenarios in enumerate(classes.values(), start=1):
            lines.extend(
                [
                    f"### Class {number}",
                    "",
                    f"- Scenarios: {len(scenarios)}",
                    "",
                ]
            )
            lines.extend(
                f"- {_inline_code(scenario.scenario_id)}" for scenario in scenarios
            )
            lines.append("")

        return lines

    def _coverage(self, bundle: ReportBundle) -> list[str]:
        coverage = bundle.scenario_coverage
        covered = sum(coverage.values())
        lines = [
            "## Coverage",
            "",
            f"- Covered scenarios: {covered} of {len(coverage)}",
            "",
        ]

        if not coverage:
            lines.extend(["_No scenarios._", ""])
            return lines

        for scenario_id, is_covered in coverage.items():
            state = "covered" if is_covered else "uncovered"
            lines.append(f"- {_inline_code(scenario_id)}: {state}")
        lines.append("")

        return lines

    def _qdl_coverage(self, bundle: ReportBundle) -> list[str]:
        """Render QDL field/effect/state coverage and typed deficits."""

        if bundle.coverage is None:
            return []
        model = bundle.coverage
        lines = [
            "## QDL coverage",
            "",
            f"- Service: {_inline_code(model.service)}",
            (
                f"- Fields: {model.fields.covered} of {model.fields.total}"
                f" covered (unresolved {model.fields.unresolved},"
                f" blind {model.fields.blind},"
                f" N/A {model.fields.not_applicable})"
            ),
            (
                f"- Effects: {model.effects.covered} of {model.effects.total}"
                f" covered (unresolved {model.effects.unresolved},"
                f" blind {model.effects.blind},"
                f" N/A {model.effects.not_applicable})"
            ),
            "### Field coverage",
            "",
            (
                "| field | kind | role | primitive | status | deficit | request"
                " | request deficit | witness |"
            ),
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for cell in model.field_cells:
            lines.append(
                f"| {_inline_code(cell.field_name)}"
                f" | {_escape_markdown(cell.field_kind)}"
                f" | {_escape_markdown(cell.semantic_role)}"
                f" | {_escape_markdown(cell.primitive)}"
                f" | {_escape_markdown(cell.status.replace('_', ' '))}"
                f" | {_escape_markdown((cell.deficit or 'none').replace('_', ' '))}"
                f" | {'yes' if cell.request_executed else 'no'}"
                f" | {'yes' if cell.request_deficit else 'no'}"
                f" | {'yes' if cell.oracle_witness_observed else 'no'} |"
            )
        lines.append("")

        if model.effect_cells:
            lines.extend(
                [
                    "### Effect coverage",
                    "",
                    "| effect | primitive | status | deficit |",
                    "|---|---|---|---|",
                ]
            )
            for cell in model.effect_cells:
                lines.append(
                    f"| {_inline_code(cell.effect_kind)}"
                    f" | {_escape_markdown(cell.primitive)}"
                    f" | {_escape_markdown(cell.status.replace('_', ' '))}"
                    f" | {_escape_markdown((cell.deficit or 'none').replace('_', ' '))} |"
                )
            lines.append("")

        deficit_rows = [
            (deficit, count)
            for deficit, count in sorted(model.deficit_counts.items())
            if count
        ]
        if deficit_rows:
            lines.extend(
                [
                    "### Coverage deficits",
                    "",
                    "| deficit | count |",
                    "|---|---|",
                ]
            )
            for deficit, count in deficit_rows:
                lines.append(
                    f"| {_escape_markdown(deficit.replace('_', ' '))} | {count} |"
                )
            lines.append("")

        if model.term_cells:
            lines.extend(
                [
                    "### S24R term diagnostics",
                    "",
                    "| term | kind | status | deficit | missing factor | rationale |",
                    "|---|---|---|---|---|---|",
                ]
            )
            for cell in model.term_cells:
                lines.append(
                    f"| {_inline_code(cell.term_id)}"
                    f" | {_escape_markdown(cell.term_kind)}"
                    f" | {_escape_markdown(cell.status.replace('_', ' '))}"
                    f" | {_escape_markdown((cell.deficit or 'none').replace('_', ' '))}"
                    f" | {_escape_markdown((cell.missing_factor or 'none').replace('_', ' '))}"
                    f" | {_escape_markdown(cell.rationale or 'none')} |"
                )
            lines.append("")
        missing_factor_rows = [
            (factor, count)
            for factor, count in sorted(model.missing_factor_counts.items())
            if count
        ]
        if missing_factor_rows:
            lines.extend(
                [
                    "### S24R missing factors",
                    "",
                    "| factor | count |",
                    "|---|---|",
                ]
            )
            lines.extend(
                f"| {_escape_markdown(factor)} | {count} |"
                for factor, count in missing_factor_rows
            )
            lines.append("")

        if model.state_machine is not None:
            state_machine = model.state_machine
            lines.extend(
                [
                    "### State machine coverage",
                    "",
                    (
                        "- Initial states: "
                        f"{_escape_markdown(', '.join(state_machine.initial_states) or 'none')}"
                    ),
                    (
                        "- Reachable states: "
                        f"{_escape_markdown(', '.join(state_machine.reachable_states) or 'none')}"
                    ),
                    f"- Runtime mismatches: {state_machine.mismatches}",
                    "",
                    "| projection | total | covered | unresolved | blind | N/A |",
                    "|---|---|---|---|---|---|",
                ]
            )
            for label, counts in (
                ("states", state_machine.states),
                ("transitions", state_machine.transitions),
                ("forbidden states", state_machine.forbidden_states),
            ):
                lines.append(
                    f"| {label} | {counts.total} | {counts.covered}"
                    f" | {counts.unresolved} | {counts.blind}"
                    f" | {counts.not_applicable} |"
                )
            lines.append("")

        return lines
