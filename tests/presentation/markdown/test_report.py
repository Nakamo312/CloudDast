from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta

from cloud_dast.contracts.assessment import (
    CoverageMatrix,
    FieldCoverageCell,
    StateMachineCoverage,
)
from cloud_dast.contracts.metrics import CampaignTimingSnapshot
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    AccessOutcome,
    EndpointLayer,
    Finding,
    Observation,
    PolicyVerdict,
    ScenarioPosition,
    ScenarioProfile,
    ScopeRelation,
    Severity,
    StandState,
    VerdictStatus,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    changed,
    input_field,
    outcome,
)
from cloud_dast.qdl.state_machine import state_machine_graph
from cloud_dast.verification.coverage import Builder
from cloud_dast.verification.oracles import ClassificationLead
from cloud_dast.verification.term_coverage import evidence_target_fact
from cloud_dast_reporting import (
    CampaignInfo,
    CampaignMetricsSnapshot,
    ReportLeadView,
    ReportService,
    TokenUsageSnapshot,
)
from cloud_dast_reporting.formats.markdown import MarkdownReportRenderer


def _qfact(
    predicate: str,
    *args: Atom,
    context: Context = Context.CONTRACT,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,
    )


def _qdl_matrix() -> CoverageMatrix:
    service = Atom(value="service:orders")
    action = Atom(value="action:grpc:orders.Update")
    resource = Atom(value="resource:order")
    status = Atom(value="status")
    role_field = input_field(action, Atom(value="role"))
    owner_field = input_field(action, Atom(value="owner"))
    observation = Atom(value="observation:obs-1")
    contract_facts = (
        _qfact("is", service, Atom(value="Service")),
        _qfact("is", action, Atom(value="Action")),
        _qfact("is", resource, Atom(value="ResourceType")),
        _qfact("is", role_field, Atom(value="InputField")),
        _qfact("is", owner_field, Atom(value="InputField")),
        _qfact("part", role_field, action),
        _qfact("part", owner_field, action),
        _qfact("causes", action, changed(resource, status)),
        _qfact("has", role_field, Atom(value="privileged_attribute")),
        _qfact("has", owner_field, Atom(value="privileged_attribute")),
        _qfact("is", observation, Atom(value="Observation"), context=Context.RUNTIME),
        _qfact(
            "evidence",
            observation,
            outcome(action, Atom(value="allowed")),
            context=Context.RUNTIME,
        ),
        evidence_target_fact(
            observation,
            action,
            role_field,
            "privileged_attribute",
            "differential",
        ),
    )
    state_machine = state_machine_graph(
        states=("draft", "published"),
        actions=("publish",),
        norms=("no_published",),
        initial_states=("draft",),
        transitions=(("publish", "draft", "published"),),
        forbidden_states=(("no_published", "published"),),
        observed_transitions=(("publish", "draft", "published"),),
    )
    return Builder().build(QdlGraph(facts=(*contract_facts, *state_machine.facts)))


def _render(
    findings: Iterable[Finding] = (),
    observations: Iterable[Observation] = (),
    invariants: Iterable[InvariantProjection] = (),
    scenarios: Iterable[ScenarioPosition] = (),
    coverage: CoverageMatrix | None = None,
    leads: Iterable[ReportLeadView] = (),
    metrics: CampaignMetricsSnapshot | None = None,
) -> str:
    bundle = ReportService().bundle(
        campaign=CampaignInfo(service="orders"),
        findings=findings,
        observations=observations,
        invariants=invariants,
        scenarios=scenarios,
        coverage=coverage,
        leads=leads,
        metrics=metrics,
    )
    return MarkdownReportRenderer().render(bundle)


def test_report_renders_qdl_field_and_effect_coverage_tables() -> None:
    report = _render(coverage=_qdl_matrix())

    assert "## QDL coverage" in report
    assert "- Service: `service:orders`" in report
    assert "- Fields: 1 of 3 covered (unresolved 1, blind 1, N/A 0)" in report
    assert "| field | kind | role | primitive | status | deficit |" in report
    assert (
        "| `role` | input | privileged_attribute"
        " | differential | covered | none |" in report
    )
    assert (
        "| `owner` | input | privileged_attribute"
        " | differential | unresolved | evidence blind |" in report
    )
    assert (
        "| `status` | resource | state_transition"
        " | marker | blind | setup blind |" in report
    )
    assert "### Effect coverage" in report
    assert "| `changed` | marker | blind | setup blind |" in report
    assert "### Coverage deficits" in report
    assert "| evidence blind | 2 |" in report
    assert "| setup blind | 2 |" in report


def test_report_renders_state_machine_coverage_section() -> None:
    report = _render(coverage=_qdl_matrix())

    assert "### State machine coverage" in report
    assert "- Initial states: draft" in report
    assert "- Reachable states: draft, published" in report
    assert "- Runtime mismatches: 0" in report
    assert "| states | 2 | 2 | 0 | 0 | 0 |" in report
    assert "| transitions | 1 | 1 | 0 | 0 | 0 |" in report
    assert "| forbidden states | 1 | 0 | 1 | 0 | 0 |" in report


def test_report_qdl_coverage_section_precedes_scenario_coverage() -> None:
    report = _render(coverage=_qdl_matrix())

    assert report.index("## Scenario classes") < report.index("## QDL coverage")
    assert report.index("## QDL coverage") < report.index("## Coverage")


def test_report_without_coverage_keeps_previous_format() -> None:
    report = _render()

    assert "## QDL coverage" not in report
    assert "## Coverage" in report


def test_report_renders_classification_leads_without_findings() -> None:
    lead = ClassificationLead(
        norm_id="norm:lead:sensitive:0123456789ab",
        role="sensitive",
        effect="has(principal:attacker, field(resource:user, email))",
        verdict=PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=1.0,
            rationale=(
                "protected role 'sensitive' has no provenance; "
                "the classification is parked as a lead for operator review"
            ),
            model_id="classification-lead",
            deterministic=True,
            grounded=False,
        ),
    )

    report = _render(leads=(lead,))

    assert "## Leads" in report
    assert "- Leads: 1" in report
    assert "### `norm:lead:sensitive:0123456789ab`" in report
    assert "- Verdict: unscoreable" in report
    assert "- Role: sensitive" in report
    assert "- Effect: `has(principal:attacker, field(resource:user, email))`" in report
    assert "operator review" in report
    assert "## Findings" in report


def test_report_without_leads_keeps_the_previous_format() -> None:
    report = _render()

    assert "## Leads" not in report
    assert "- Leads:" not in report


def test_report_encodes_target_controlled_markdown_values() -> None:
    unsafe = "target & | \"`code`\"\r\n<script>alert('x')</script>"
    encoded = (
        "target &amp; &#124; &quot;&#96;code&#96;&quot;&#13;&#10;"
        "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;"
    )
    finding = Finding(
        finding_id=unsafe,
        observation_id=unsafe,
        invariant_id=unsafe,
        method_id=unsafe,
        scenario_id=unsafe,
        severity=Severity.HIGH,
        title=unsafe,
        description=unsafe,
        remediation=unsafe,
        vulnerability_class="authorization-policy-bypass",
        classification_deficits=(),
        goal_id=unsafe,
        path_id=unsafe,
        step_id=unsafe,
        confidence=0.5,
        evidence_refs=(unsafe,),
    )
    observation = Observation(
        observation_id=unsafe,
        check_id=unsafe,
        scenario_id=unsafe,
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary=unsafe,
        transport_status=None,
    )
    invariant = InvariantProjection(
        invariant_id=unsafe,
        norm_id=unsafe,
        statement=unsafe,
        severity=Severity.HIGH,
        policy=unsafe,
    )
    scenario = ScenarioPosition(
        scenario_id=unsafe,
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
    lead = ClassificationLead(
        norm_id=unsafe,
        role=unsafe,
        effect=unsafe,
        verdict=PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=1.0,
            rationale=unsafe,
            model_id="classification-lead",
            deterministic=True,
            grounded=False,
        ),
    )
    coverage = CoverageMatrix(
        service=unsafe,
        fields=(
            FieldCoverageCell(
                field_id="field",
                field_name=unsafe,
                field_kind="input",
                semantic_role=unsafe,
                primitive="marker",
                status="covered",
            ),
        ),
        state_machine=StateMachineCoverage(
            initial_states=(unsafe,),
            reachable_states=(unsafe,),
        ),
    )

    report = _render(
        [finding],
        [observation],
        [invariant],
        scenarios=[scenario],
        coverage=coverage,
        leads=(lead,),
    )
    lines = report.splitlines()

    assert unsafe not in report
    assert f"- Service: `{encoded}`" in lines
    assert f"### {encoded}" in lines
    assert f"### `{encoded}`" in lines
    assert f"- Description: {encoded}" in lines
    assert f"- Evidence: {encoded}" in lines
    assert f"- Response summary: {encoded}" in lines
    assert f"- Statement: {encoded}" in lines
    assert f"- Rationale: {encoded}" in lines
    assert f"- `{encoded}`" in lines
    assert f"- `{encoded}`: covered" in lines
    assert (
        f"| `{encoded}` | input | {encoded} | marker | covered | none | no | no"
        " | no |" in lines
    )
    assert f"- Initial states: {encoded}" in lines
    assert f"- Reachable states: {encoded}" in lines


def _tagged_finding(finding_id: str, *owasp: str) -> Finding:
    return Finding(
        finding_id=finding_id,
        observation_id=f"observation:{finding_id}",
        invariant_id=f"invariant:{finding_id}",
        method_id="svc.Get",
        scenario_id="scenario",
        severity=Severity.HIGH,
        title="classification",
        description="description",
        remediation="remediation",
        vulnerability_class="authorization-policy-bypass",
        classification_deficits=(),
        owasp=owasp,
    )


def test_report_renders_owasp_distribution_section() -> None:
    findings = (
        _tagged_finding("f1", "API1"),
        _tagged_finding("f2", "API1", "API3"),
        _tagged_finding("f3"),
    )

    markdown = _render(findings)

    assert "## OWASP API Top 10" in markdown
    assert "Broken Object Level Authorization" in markdown
    assert "unclassified" in markdown
    assert "| Ring share |" in markdown
    assert "findings" in markdown


def test_report_renders_minimal_poc() -> None:
    finding = _tagged_finding("f1").model_copy(
        update={"minimal_poc": (("secret_id", ""),)},
    )

    markdown = _render([finding])

    assert "- Minimal PoC: `{&quot;secret_id&quot;:&quot;&quot;}`" in markdown


def test_report_omits_owasp_section_without_findings() -> None:
    assert "## OWASP API Top 10" not in _render()


def test_report_renders_finding_taxonomy() -> None:
    finding = _tagged_finding("f1", "API1").model_copy(
        update={
            "cwe": ("CWE-639", "CWE-639", "CWE-284"),
            "stride": ("E", "I"),
        }
    )

    markdown = _render([finding])

    assert "- CWE: `CWE-639`, `CWE-284`" in markdown
    assert "- OWASP: `API1`" in markdown
    assert "- STRIDE: `E`, `I`" in markdown


def test_report_renders_finding_summary_grouping() -> None:
    first = _tagged_finding("f1").model_copy(
        update={
            "vulnerability_class": "authorization-policy-bypass",
            "cwe": ("CWE-639", "CWE-284"),
        }
    )
    second = _tagged_finding("f2").model_copy(
        update={
            "vulnerability_class": "authorization-policy-bypass",
            "cwe": ("CWE-284", "CWE-639"),
        }
    )
    third = _tagged_finding("f3").model_copy(
        update={
            "vulnerability_class": "ssrf",
            "cwe": ("CWE-918",),
            "severity": Severity.CRITICAL,
        }
    )

    markdown = _render((third, second, first))

    assert "### Finding summary" in markdown
    assert (
        "| `authorization-policy-bypass` | `CWE-284`, `CWE-639` | high | 2 |"
        in markdown
    )
    assert "| `ssrf` | `CWE-918` | critical | 1 |" in markdown


def test_report_renders_unclassified_finding_taxonomy() -> None:
    finding = _tagged_finding("f1")

    markdown = _render([finding])

    assert "- CWE: none" in markdown
    assert "- OWASP: unclassified" in markdown
    assert "- STRIDE: none" in markdown


def test_report_renders_token_and_time_metrics() -> None:
    metrics = CampaignMetricsSnapshot(
        tokens=TokenUsageSnapshot(
            input_tokens=120,
            cached_input_tokens=50,
            output_tokens=30,
            request_count=4,
        ),
        tokens_by_phase={
            "grounding:roles": TokenUsageSnapshot(
                input_tokens=120,
                cached_input_tokens=50,
                output_tokens=30,
                request_count=4,
            )
        },
        timing=CampaignTimingSnapshot(
            wall_time=timedelta(minutes=2),
            phase_elapsed={"grounding:roles": timedelta(seconds=30)},
        ),
    )

    markdown = _render(metrics=metrics)

    assert "## Campaign metrics" in markdown
    assert "- Input tokens: 120" in markdown
    assert "- Cached input tokens: 50" in markdown
    assert "- Uncached input tokens: 70" in markdown
    assert "- Output tokens: 30" in markdown
    assert "- Total tokens: 150" in markdown
    assert "- Model requests: 4" in markdown
    assert "- Cache hit rate: 41.7%" in markdown
    assert "- Wall time: 0:02:00" in markdown
    assert "| `grounding:roles` | 120 | 50 | 30 | 150 | 4 | 0:00:30 |" in markdown
