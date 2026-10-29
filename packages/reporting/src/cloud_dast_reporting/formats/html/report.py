"""Self-contained HTML rendering of a Cloud DAST report bundle."""

from __future__ import annotations

import html
from collections.abc import Iterable, Sequence
from datetime import timedelta

from cloud_dast_reporting import (
    QdlCoverageCounts,
    QdlCoverageModel,
    QdlEffectCoverageItem,
    QdlFieldCoverageItem,
    QdlTermCoverageItem,
    ReportBundle,
    TokenUsageSnapshot,
)
from cloud_dast_reporting.formats.html.radar import (
    OwaspRadarPoint,
    owasp_radar_points,
    render_owasp_radar_svg,
)

_CSS = """
:root {
  color-scheme: light;
  --background: #f4f5f7;
  --surface: #ffffff;
  --border: #d9dce3;
  --muted: #667085;
  --text: #17181c;
  --accent: #3e63dd;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--background);
  color: var(--text);
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.5;
}
.page { max-width: 1140px; margin: 0 auto; padding: 0 24px 72px; }
.hero {
  background: #101216;
  color: #f7f8f8;
  padding: 56px 24px 48px;
}
.hero-inner { max-width: 1140px; margin: 0 auto; padding: 0 24px; }
.eyebrow {
  color: #a5b4fc;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: .12em;
  margin: 0 0 8px;
  text-transform: uppercase;
}
h1 { font-size: 36px; line-height: 1.15; margin: 0; }
h2 { font-size: 22px; margin: 0 0 16px; }
h3 { font-size: 17px; margin: 0; }
.meta {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
  gap: 12px;
  margin: 28px 0 0;
}
.meta div { border-left: 2px solid rgba(255,255,255,.25); padding-left: 12px; }
.meta dt { color: #a1a1aa; font-size: 12px; margin: 0; }
.meta dd { margin: 2px 0 0; }
.section {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  margin-top: 28px;
  padding: 24px;
}
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(165px, 1fr));
  gap: 14px;
}
.card {
  background: #f8f9fb;
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px;
}
.card span { color: var(--muted); display: block; font-size: 13px; }
.card strong { display: block; font-size: 28px; margin-top: 4px; }
.muted { color: var(--muted); }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; }
th, td {
  border-bottom: 1px solid var(--border);
  font-size: 14px;
  padding: 10px 12px;
  text-align: left;
  vertical-align: top;
}
th { background: #f8f9fb; color: #4b5565; font-size: 12px; }
code {
  background: #eef0f4;
  border-radius: 4px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: .92em;
  padding: 1px 5px;
}
.radar { margin: 8px 0 20px; }
.radar svg { display: block; height: auto; width: 100%; }
.finding {
  border: 1px solid var(--border);
  border-left-width: 5px;
  border-radius: 12px;
  margin-top: 16px;
  padding: 18px;
}
.finding.low { border-left-color: #22c55e; }
.finding.medium { border-left-color: #f59e0b; }
.finding.high { border-left-color: #ef4444; }
.finding.critical { border-left-color: #dc2626; }
.finding-header { align-items: center; display: flex; justify-content: space-between; gap: 16px; }
.badge {
  background: #eef0f4;
  border-radius: 999px;
  color: #4b5565;
  display: inline-block;
  font-size: 12px;
  font-weight: 700;
  padding: 3px 10px;
  text-transform: uppercase;
}
.finding-meta {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
  gap: 10px;
  margin: 18px 0 0;
}
.finding-meta div { min-width: 0; }
.finding-meta dt { color: var(--muted); font-size: 12px; margin: 0; }
.finding-meta dd { margin: 2px 0 0; overflow-wrap: anywhere; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { background: #eef0f4; border-radius: 999px; padding: 2px 8px; }
.finding-body { margin-top: 18px; }
.finding-body p { margin: 0; }
.finding-body strong { color: #4b5565; }
.empty {
  background: #f8f9fb;
  border: 1px dashed var(--border);
  border-radius: 12px;
  color: var(--muted);
  padding: 18px;
  text-align: center;
}
details { margin-top: 14px; }
summary { color: var(--accent); cursor: pointer; font-weight: 600; }
@media (max-width: 720px) {
  h1 { font-size: 28px; }
  .section { border-radius: 10px; padding: 16px; }
  .finding-header { align-items: flex-start; flex-direction: column; }
}
"""


class HtmlReportRenderer:
    """Build a complete HTML document without JavaScript dependencies."""

    def render(self, bundle: ReportBundle) -> str:
        points = owasp_radar_points(bundle)
        value_label = (
            "ground-truth recall"
            if bundle.owasp_ground_truth is not None
            else "findings share"
        )
        radar = render_owasp_radar_svg(points, value_label=value_label)
        sections = [
            self._summary(bundle),
            self._radar(bundle, points, radar, value_label),
            self._metrics(bundle),
            self._findings(bundle),
            self._leads(bundle),
            self._observations(bundle),
            self._invariants(bundle),
            self._method_action_coverage(bundle),
            self._plan(bundle),
            self._coverage(bundle),
        ]
        return "\n".join(
            [
                "<!doctype html>",
                '<html lang="en">',
                "<head>",
                '<meta charset="utf-8">',
                '<meta name="viewport" content="width=device-width, initial-scale=1">',
                f"<title>{_escape(bundle.campaign.service)} — Cloud DAST report</title>",
                f"<style>{_CSS}</style>",
                "</head>",
                "<body>",
                self._header(bundle),
                '<main class="page">',
                *sections,
                "</main>",
                "</body>",
                "</html>",
            ]
        )

    def _header(self, bundle: ReportBundle) -> str:
        campaign = bundle.campaign
        return "\n".join(
            [
                '<header class="hero">',
                '<div class="hero-inner">',
                '<p class="eyebrow">Cloud DAST report</p>',
                f"<h1>{_escape(campaign.service)}</h1>",
                '<dl class="meta">',
                _definition("Scenario", campaign.scenario_id or "—"),
                _definition("Campaign", campaign.campaign_id or "—"),
                _definition("Run", campaign.run_id or "—"),
                _definition("Plan hash", campaign.plan_hash or "—"),
                _definition("Method", campaign.method_id or "—"),
                "</dl>",
                "</div>",
                "</header>",
            ]
        )

    def _summary(self, bundle: ReportBundle) -> str:
        summary_rows = [
            [
                _code(group.vulnerability_class),
                _chips(group.cwe),
                _escape(group.severity),
                str(group.count),
            ]
            for group in bundle.finding_summary
        ]
        summary_table = (
            _table(
                ("Vulnerability class", "CWE", "Severity", "Count"),
                summary_rows,
            )
            if summary_rows
            else _empty("No grouped findings.")
        )
        return "\n".join(
            [
                '<section class="section" aria-labelledby="summary-heading">',
                '<h2 id="summary-heading">Summary</h2>',
                '<div class="cards">',
                _card("Findings", len(bundle.findings)),
                _card("Observations", len(bundle.observations)),
                _card("Leads", len(bundle.leads)),
                _card("Invariants", len(bundle.invariants)),
                _card("Checks", bundle.metrics.total_checks),
                "</div>",
                "<h3>Findings by class, CWE, and severity</h3>",
                summary_table,
                "</section>",
            ]
        )

    def _radar(
        self,
        bundle: ReportBundle,
        points: Sequence[OwaspRadarPoint],
        radar: str,
        value_label: str,
    ) -> str:
        if bundle.owasp_ground_truth is None:
            explanation = (
                "No ground truth is attached. Each axis shows the share of "
                "findings tagged with that OWASP API class."
            )
        else:
            explanation = (
                "Ground truth is attached. Each axis shows recall: matched "
                "expected findings divided by expected findings."
            )
        rows = [
            [
                _code(point.code),
                _escape(point.title),
                f"{point.value:.1%}",
                str(point.findings),
                "—" if point.expected is None else str(point.expected),
                "—" if point.matched is None else str(point.matched),
            ]
            for point in points
        ]
        return "\n".join(
            [
                '<section class="section" aria-labelledby="owasp-heading">',
                '<h2 id="owasp-heading">OWASP API Top 10 radar</h2>',
                f'<p class="muted">{_escape(explanation)}</p>',
                f'<div class="radar">{radar}</div>',
                _table(
                    (
                        "Category",
                        "Title",
                        "Value",
                        "Findings",
                        "Expected",
                        "Matched",
                    ),
                    rows,
                ),
                "</section>",
            ]
        )

    def _metrics(self, bundle: ReportBundle) -> str:
        metrics = bundle.metrics
        tokens = metrics.tokens
        tokens_by_phase = metrics.tokens_by_phase
        phases = sorted(set(tokens_by_phase) | set(metrics.timing.phase_elapsed))
        phase_rows = []
        for phase in phases:
            usage = tokens_by_phase.get(phase, TokenUsageSnapshot())
            elapsed = metrics.timing.phase_elapsed.get(phase, timedelta())
            phase_rows.append(
                [
                    _code(phase),
                    str(usage.input_tokens),
                    str(usage.output_tokens),
                    str(usage.total_tokens),
                    str(usage.request_count),
                    _escape(_duration(elapsed)),
                ]
            )
        return "\n".join(
            [
                '<section class="section" aria-labelledby="metrics-heading">',
                '<h2 id="metrics-heading">Campaign metrics</h2>',
                '<div class="cards">',
                _card("Input tokens", tokens.input_tokens),
                _card("Output tokens", tokens.output_tokens),
                _card("Total tokens", tokens.total_tokens),
                _card("Model requests", tokens.request_count),
                _card("Wall time", _duration(metrics.timing.wall_time)),
                "</div>",
                _table(
                    ("Phase", "Input", "Output", "Total", "Requests", "Elapsed"),
                    phase_rows,
                ),
                "</section>",
            ]
        )

    def _findings(self, bundle: ReportBundle) -> str:
        if not bundle.findings:
            return _section("Findings", _empty("No findings."))
        parts = [
            '<section class="section" aria-labelledby="findings-heading">',
            '<h2 id="findings-heading">Findings</h2>',
        ]
        for finding in bundle.findings:
            severity = str(finding.severity)
            parts.extend(
                [
                    f'<article class="finding {severity}">',
                    '<div class="finding-header">',
                    f"<h3>{_escape(finding.title)}</h3>",
                    f'<span class="badge">{_escape(severity)}</span>',
                    "</div>",
                    '<dl class="finding-meta">',
                    _definition("Finding", finding.finding_id, code=True),
                    _definition("Invariant", finding.invariant_id, code=True),
                    _definition("Observation", finding.observation_id, code=True),
                    _definition("Method", finding.method_id, code=True),
                    _definition("Scenario", finding.scenario_id, code=True),
                    _definition("CWE", _chips(finding.cwe), raw=True),
                    _definition("OWASP", _chips(finding.owasp), raw=True),
                    _definition("STRIDE", _chips(finding.stride), raw=True),
                    _definition(
                        "Confidence",
                        "—"
                        if finding.confidence is None
                        else f"{finding.confidence:.0%}",
                    ),
                    _definition(
                        "Evidence",
                        _chips(finding.evidence_refs),
                        raw=True,
                    ),
                    "</dl>",
                    '<div class="finding-body">',
                    f"<p><strong>Description.</strong> {_escape(finding.description)}</p>",
                    f"<p><strong>Remediation.</strong> {_escape(finding.remediation)}</p>",
                    "</div>",
                    "</article>",
                ]
            )
        parts.append("</section>")
        return "\n".join(parts)

    def _leads(self, bundle: ReportBundle) -> str:
        if not bundle.leads:
            return ""
        rows = [
            [
                _code(lead.norm_id),
                _escape(lead.verdict_status),
                _escape(lead.role),
                _code(lead.effect),
                _escape(lead.rationale),
            ]
            for lead in bundle.leads
        ]
        return _section(
            "Leads",
            _table(("Norm", "Verdict", "Role", "Effect", "Rationale"), rows),
        )

    def _observations(self, bundle: ReportBundle) -> str:
        if not bundle.observations:
            return _section("Observations", _empty("No observations."))
        rows = [
            [
                _code(observation.observation_id),
                _code(observation.check_id),
                _code(observation.scenario_id),
                _escape(observation.observed_outcome),
                _escape(
                    observation.transport_status.token
                    if observation.transport_status is not None
                    else "—"
                ),
                _escape(observation.response_summary),
            ]
            for observation in bundle.observations
        ]
        return _section(
            "Observations",
            _table(
                (
                    "Observation",
                    "Check",
                    "Scenario",
                    "Outcome",
                    "Transport",
                    "Response",
                ),
                rows,
            ),
        )

    def _invariants(self, bundle: ReportBundle) -> str:
        if not bundle.invariants:
            return _section("Invariants", _empty("No invariants."))
        rows = [
            [
                _code(invariant.invariant_id),
                _code(invariant.norm_id),
                _escape(invariant.severity),
                _escape(invariant.policy or "—"),
                _escape(invariant.statement),
            ]
            for invariant in bundle.invariants
        ]
        return _section(
            "Invariants",
            _table(("Invariant", "Norm", "Severity", "Policy", "Statement"), rows),
        )

    def _coverage(self, bundle: ReportBundle) -> str:
        coverage = bundle.scenario_coverage
        covered = sum(coverage.values())
        scenario_rows = [
            [
                _code(scenario_id),
                "covered" if is_covered else "uncovered",
            ]
            for scenario_id, is_covered in coverage.items()
        ]
        parts = [
            '<section class="section" aria-labelledby="coverage-heading">',
            '<h2 id="coverage-heading">Coverage</h2>',
            f'<p class="muted">Covered scenarios: {covered} of {len(coverage)}.</p>',
            _table(("Scenario", "Status"), scenario_rows),
        ]
        if bundle.coverage is not None:
            parts.extend(self._qdl_coverage(bundle.coverage))
        parts.append("</section>")
        return "\n".join(parts)

    def _method_action_coverage(self, bundle: ReportBundle) -> str:
        model = bundle.method_action_coverage
        if model is None:
            return ""
        method_rows = [
            [_code(method_id), "covered" if covered else "uncovered"]
            for method_id, covered in sorted(model.methods.items())
        ]
        action_rows = [
            [_code(action_id), "covered" if covered else "uncovered"]
            for action_id, covered in sorted(model.actions.items())
        ]
        return _section(
            "Method/action coverage",
            "\n".join(
                [
                    "<h3>Methods</h3>",
                    _table(("Method", "Status"), method_rows),
                    "<h3>Actions</h3>",
                    _table(("Action", "Status"), action_rows),
                ]
            ),
        )

    def _plan(self, bundle: ReportBundle) -> str:
        plan = bundle.plan
        if plan is None:
            return ""
        rows = [
            [
                _code(path.path_id),
                _code(path.goal_id),
                _escape(", ".join(step.method_id for step in path.steps) or "none"),
            ]
            for path in plan.paths
        ]
        return _section(
            "Runtime plan",
            "\n".join(
                [
                    _definition("Snapshot", plan.snapshot_kind),
                    _definition("Graph hash", plan.graph_hash, code=True),
                    _table(("Path", "Goal", "Methods"), rows),
                ]
            ),
        )

    def _qdl_coverage(self, model: QdlCoverageModel) -> list[str]:
        field_rows = [
            [
                _code(cell.field_name),
                _escape(cell.field_kind),
                _escape(cell.semantic_role),
                _escape(cell.primitive),
                _escape(cell.status.replace("_", " ")),
                _escape((cell.deficit or "none").replace("_", " ")),
                "yes" if cell.request_executed else "no",
                "yes" if cell.request_deficit else "no",
                "yes" if cell.oracle_witness_observed else "no",
            ]
            for cell in model.field_cells
        ]
        effect_rows = [
            [
                _code(cell.effect_kind),
                _escape(cell.primitive),
                _escape(cell.status.replace("_", " ")),
                _escape((cell.deficit or "none").replace("_", " ")),
            ]
            for cell in model.effect_cells
        ]
        field_kind_rows = [
            [
                _code(field_kind),
                str(counts.total),
                str(counts.covered),
                str(counts.unresolved),
                str(counts.blind),
                str(counts.not_applicable),
            ]
            for field_kind, counts in sorted(model.by_field_kind.items())
        ]
        deficit_rows = [
            [_code(deficit.replace("_", " ")), str(count)]
            for deficit, count in sorted(model.deficit_counts.items())
            if count
        ]
        gap_rows = [_coverage_gap_row(cell) for cell in model.gaps]
        state_machine = model.state_machine

        parts = [
            "<details>",
            "<summary>QDL coverage</summary>",
            '<dl class="finding-meta">',
            _definition("Service", model.service, code=True),
            _definition("Fields", _coverage_summary(model.fields)),
            _definition("Effects", _coverage_summary(model.effects)),
            "</dl>",
            "<h3>Field coverage</h3>",
            _table(
                (
                    "Field",
                    "Kind",
                    "Role",
                    "Primitive",
                    "Status",
                    "Deficit",
                    "Request",
                    "Request deficit",
                    "Witness",
                ),
                field_rows,
            ),
            "<h3>Effect coverage</h3>",
            _table(("Effect", "Primitive", "Status", "Deficit"), effect_rows),
            "<h3>Coverage by field kind</h3>",
            _table(
                (
                    "Field kind",
                    "Total",
                    "Covered",
                    "Unresolved",
                    "Blind",
                    "N/A",
                ),
                field_kind_rows,
            ),
        ]
        if deficit_rows:
            parts.extend(
                [
                    "<h3>Coverage deficits</h3>",
                    _table(("Deficit", "Count"), deficit_rows),
                ]
            )
        if gap_rows:
            parts.extend(
                [
                    "<h3>Coverage gaps</h3>",
                    _table(
                        ("Type", "Item", "Primitive", "Status", "Deficit"),
                        gap_rows,
                    ),
                ]
            )
        if model.term_cells:
            parts.extend(
                [
                    "<h3>S24R term diagnostics</h3>",
                    _table(
                        (
                            "Term",
                            "Kind",
                            "Status",
                            "Deficit",
                            "Missing factor",
                            "Rationale",
                        ),
                        [_term_coverage_row(cell) for cell in model.term_cells],
                    ),
                ]
            )
        missing_factor_rows = [
            [_code(factor), str(count)]
            for factor, count in sorted(model.missing_factor_counts.items())
            if count
        ]
        if missing_factor_rows:
            parts.extend(
                [
                    "<h3>S24R missing factors</h3>",
                    _table(("Factor", "Count"), missing_factor_rows),
                ]
            )
        if state_machine is not None:
            parts.extend(
                [
                    "<h3>State machine coverage</h3>",
                    '<dl class="finding-meta">',
                    _definition(
                        "Initial states",
                        ", ".join(state_machine.initial_states) or "none",
                    ),
                    _definition(
                        "Reachable states",
                        ", ".join(state_machine.reachable_states) or "none",
                    ),
                    _definition("Runtime mismatches", state_machine.mismatches),
                    "</dl>",
                    _table(
                        (
                            "Projection",
                            "Total",
                            "Covered",
                            "Unresolved",
                            "Blind",
                            "N/A",
                        ),
                        [
                            _state_machine_row("States", state_machine.states),
                            _state_machine_row(
                                "Transitions", state_machine.transitions
                            ),
                            _state_machine_row(
                                "Forbidden states",
                                state_machine.forbidden_states,
                            ),
                        ],
                    ),
                ]
            )
        parts.append("</details>")
        return parts


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _code(value: object) -> str:
    return f"<code>{_escape(value)}</code>"


def _card(label: str, value: object) -> str:
    return (
        f'<article class="card"><span>{_escape(label)}</span>'
        f"<strong>{_escape(value)}</strong></article>"
    )


def _definition(
    term: str,
    value: object,
    *,
    code: bool = False,
    raw: bool = False,
) -> str:
    if code:
        rendered = _code(value)
    elif raw:
        rendered = str(value)
    else:
        rendered = _escape(value)
    return f"<div><dt>{_escape(term)}</dt><dd>{rendered}</dd></div>"


def _chips(values: Iterable[object]) -> str:
    unique = tuple(dict.fromkeys(values))
    if not unique:
        return '<span class="muted">—</span>'
    return "".join(f'<span class="chip">{_escape(value)}</span>' for value in unique)


def _coverage_summary(counts: QdlCoverageCounts) -> str:
    return (
        f"{counts.covered} of {counts.total} covered "
        f"(unresolved {counts.unresolved}, blind {counts.blind}, "
        f"N/A {counts.not_applicable})"
    )


def _coverage_gap_row(
    cell: QdlFieldCoverageItem | QdlEffectCoverageItem,
) -> list[str]:
    if isinstance(cell, QdlFieldCoverageItem):
        return [
            _code("field"),
            _code(cell.field_name),
            _escape(cell.primitive),
            _escape(cell.status.replace("_", " ")),
            _escape((cell.deficit or "none").replace("_", " ")),
        ]
    return [
        _code("effect"),
        _code(cell.effect_kind),
        _escape(cell.primitive),
        _escape(cell.status.replace("_", " ")),
        _escape((cell.deficit or "none").replace("_", " ")),
    ]


def _term_coverage_row(cell: QdlTermCoverageItem) -> list[str]:
    return [
        _code(cell.term_id),
        _escape(cell.term_kind),
        _escape(cell.status.replace("_", " ")),
        _escape((cell.deficit or "none").replace("_", " ")),
        _escape((cell.missing_factor or "none").replace("_", " ")),
        _escape(cell.rationale or "none"),
    ]


def _state_machine_row(label: str, counts: QdlCoverageCounts) -> list[str]:
    return [
        _escape(label),
        str(counts.total),
        str(counts.covered),
        str(counts.unresolved),
        str(counts.blind),
        str(counts.not_applicable),
    ]


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    head = "".join(f'<th scope="col">{_escape(header)}</th>' for header in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows
    )
    return (
        '<div class="table-wrap"><table>'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )


def _section(title: str, content: str) -> str:
    identifier = _slug(title)
    return (
        f'<section class="section" aria-labelledby="{identifier}-heading">'
        f'<h2 id="{identifier}-heading">{_escape(title)}</h2>{content}</section>'
    )


def _empty(message: str) -> str:
    return f'<p class="empty">{_escape(message)}</p>'


def _duration(duration: timedelta) -> str:
    return str(duration)


def _slug(value: str) -> str:
    return "".join(
        character.lower() if character.isalnum() else "-" for character in value
    ).strip("-")


__all__ = ["HtmlReportRenderer"]
