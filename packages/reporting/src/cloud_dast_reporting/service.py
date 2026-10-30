"""Reporting read models over immutable core execution results."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal, Protocol

from cloud_dast.api import is_classification_deficit
from cloud_dast.contracts.metrics import CampaignMetricsSnapshot
from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    Finding,
    MethodSpec,
    Observation,
    ScenarioPosition,
    ScenarioProfile,
    Severity,
)
from cloud_dast.model.events import (
    CheckCompleted,
    CoverageUpdated,
    DomainEvent,
    Event,
    FindingRaised,
)
from cloud_dast.model.evidence import severity_score


class _CoverageStatusView(Protocol):
    """Minimal status surface shared by every coverage projection."""

    @property
    def status(self) -> str: ...


class _QdlFieldCellView(Protocol):
    """Field-level QDL coverage cell consumed by the report read model."""

    @property
    def field_id(self) -> str: ...

    @property
    def field_name(self) -> str: ...

    @property
    def field_kind(self) -> str: ...

    @property
    def semantic_role(self) -> str: ...

    @property
    def primitive(self) -> str: ...

    @property
    def status(self) -> str: ...

    @property
    def deficit(self) -> str | None: ...

    @property
    def rationale(self) -> str: ...

    @property
    def request_executed(self) -> bool: ...

    @property
    def request_deficit(self) -> bool: ...

    @property
    def oracle_witness_observed(self) -> bool: ...


class _QdlEffectCellView(Protocol):
    """Effect-level QDL coverage cell consumed by the report read model."""

    @property
    def effect_id(self) -> str: ...

    @property
    def effect_kind(self) -> str: ...

    @property
    def primitive(self) -> str: ...

    @property
    def status(self) -> str: ...

    @property
    def deficit(self) -> str | None: ...

    @property
    def rationale(self) -> str: ...


class _QdlTermCellView(Protocol):
    """Generic term-level QDL coverage cell consumed by reports (S24R)."""

    @property
    def term_id(self) -> str: ...

    @property
    def term_kind(self) -> str: ...

    @property
    def status(self) -> str: ...

    @property
    def deficit(self) -> str | None: ...

    @property
    def missing_factor(self) -> str | None: ...


class _QdlStateMachineCoverageView(Protocol):
    """First-class QDL state-machine projection consumed by reports."""

    @property
    def states(self) -> Sequence[_CoverageStatusView]: ...

    @property
    def transitions(self) -> Sequence[_CoverageStatusView]: ...

    @property
    def forbidden_states(self) -> Sequence[_CoverageStatusView]: ...

    @property
    def mismatches(self) -> Sequence[object]: ...

    @property
    def initial_states(self) -> Sequence[str]: ...

    @property
    def reachable_states(self) -> Sequence[str]: ...

    @property
    def deficits(self) -> Sequence[str]: ...


class QdlCoverageMatrixView(Protocol):
    """Structural view over the derivation-based QDL coverage matrix.

    The reporting package must not import workflow types, so this read model
    depends only on the projection surface implemented by ``CoverageMatrix``.
    """

    @property
    def service(self) -> str: ...

    @property
    def fields(self) -> Sequence[_QdlFieldCellView]: ...

    @property
    def effects(self) -> Sequence[_QdlEffectCellView]: ...

    @property
    def state_machine(self) -> _QdlStateMachineCoverageView | None: ...

    @property
    def terms(self) -> Sequence[_QdlTermCellView]: ...

    @property
    def missing_factor_counts(self) -> Mapping[str, int]: ...

    @property
    def request_deficit_count(self) -> int: ...


class _QdlPlanMethodView(Protocol):
    """Method identity needed by the plan read model."""

    @property
    def method_id(self) -> str: ...


class QdlPlanStepView(Protocol):
    """Minimal plan-step surface consumed by presentation."""

    @property
    def step_id(self) -> str: ...

    @property
    def method(self) -> _QdlPlanMethodView: ...


class QdlPlanPathView(Protocol):
    """Minimal plan-path surface consumed by presentation."""

    @property
    def path_id(self) -> str: ...

    @property
    def goal_id(self) -> str: ...

    @property
    def gate(self) -> str: ...

    @property
    def steps(self) -> Sequence[QdlPlanStepView]: ...


class QdlPlanView(Protocol):
    """Structural read-model contract for a QDL execution plan."""

    @property
    def graph_hash(self) -> str: ...

    @property
    def paths(self) -> Sequence[QdlPlanPathView]: ...


class ReportLeadView(Protocol):
    """Minimal lead surface consumed by report formatters."""

    @property
    def norm_id(self) -> str: ...

    @property
    def role(self) -> str: ...

    @property
    def effect(self) -> str: ...

    @property
    def verdict_status(self) -> str: ...

    @property
    def rationale(self) -> str: ...


def lead_report_key(lead: ReportLeadView) -> tuple[str, str, str, str]:
    """Return the stable identity of one lead revision in the report."""

    return (lead.norm_id, lead.role, lead.effect, lead.verdict_status)


def dedupe_leads(
    leads: Iterable[ReportLeadView],
) -> tuple[ReportLeadView, ...]:
    """Collapse repeated consultations of one lead into a single row.

    A repeat consultation without new evidence preserves the lead (S32R):
    the report projection keeps the first stable lead revision instead of
    duplicating a row for every consultation attempt.  A genuine revision
    with a changed verdict stays visible as its own row.
    """

    seen: set[tuple[str, str, str, str]] = set()
    unique: list[ReportLeadView] = []
    for lead in leads:
        key = lead_report_key(lead)
        if key in seen:
            continue
        seen.add(key)
        unique.append(lead)
    return tuple(unique)


class _FindingSummaryView(Protocol):
    """Minimal finding surface consumed by the summary read model."""

    @property
    def vulnerability_class(self) -> str: ...

    @property
    def cwe(self) -> tuple[str, ...]: ...

    @property
    def severity(self) -> Severity: ...


@dataclass(frozen=True, slots=True)
class QdlCoverageCounts:
    """Status counts for one coverage projection."""

    total: int
    covered: int
    unresolved: int
    blind: int
    not_applicable: int


@dataclass(frozen=True, slots=True)
class QdlFieldCoverageItem:
    """One field-level coverage row for reports."""

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
class QdlEffectCoverageItem:
    """One effect-level coverage row for reports."""

    effect_id: str
    effect_kind: str
    primitive: str
    status: str
    deficit: str | None
    rationale: str


@dataclass(frozen=True, slots=True)
class QdlTermCoverageItem:
    """One generic term-level coverage row for reports (S24R).

    The row is keyed by a QDL term — never by action or path.  Its deficit
    is typed by the first missing coverage factor
    ``semantic × setup × oracle × runtime``.
    """

    term_id: str
    term_kind: str
    status: str
    deficit: str | None
    missing_factor: str | None
    rationale: str = ""


@dataclass(frozen=True, slots=True)
class MethodActionCoverageModel:
    """Coverage of declared methods and their derived QDL actions.

    This is intentionally separate from ``QdlCoverageModel.term_cells``:
    methods/actions are execution-surface accounting, while terms are the
    S24R semantic coverage units.
    """

    methods: Mapping[str, bool] = field(default_factory=dict)
    actions: Mapping[str, bool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "methods", MappingProxyType(dict(self.methods)))
        object.__setattr__(self, "actions", MappingProxyType(dict(self.actions)))


PlanSnapshotKind = Literal["initial", "final"]


@dataclass(frozen=True, slots=True)
class QdlStateMachineCoverageModel:
    """State-machine coverage read model: states, transitions, bans."""

    states: QdlCoverageCounts
    transitions: QdlCoverageCounts
    forbidden_states: QdlCoverageCounts
    initial_states: tuple[str, ...]
    reachable_states: tuple[str, ...]
    mismatches: int


@dataclass(frozen=True, slots=True)
class QdlCoverageModel:
    """QDL coverage business read model consumed by report formatters."""

    service: str
    fields: QdlCoverageCounts
    effects: QdlCoverageCounts
    by_field_kind: Mapping[str, QdlCoverageCounts]
    deficit_counts: Mapping[str, int]
    field_cells: tuple[QdlFieldCoverageItem, ...]
    effect_cells: tuple[QdlEffectCoverageItem, ...]
    gaps: tuple[QdlFieldCoverageItem | QdlEffectCoverageItem, ...]
    state_machine: QdlStateMachineCoverageModel | None
    term_cells: tuple[QdlTermCoverageItem, ...] = ()
    missing_factor_counts: Mapping[str, int] = field(default_factory=dict)
    request_deficit_count: int = 0


@dataclass(frozen=True, slots=True)
class QdlPlanStepSnapshot:
    """One presentation step in an immutable QDL plan snapshot."""

    step_id: str
    method_id: str


@dataclass(frozen=True, slots=True)
class QdlPlanPathSnapshot:
    """One presentation path in an immutable QDL plan snapshot."""

    path_id: str
    goal_id: str
    gate: str
    steps: tuple[QdlPlanStepSnapshot, ...]


@dataclass(frozen=True, slots=True)
class QdlPlanSnapshot:
    """Immutable presentation projection of a QDL execution view."""

    graph_hash: str
    paths: tuple[QdlPlanPathSnapshot, ...]
    snapshot_kind: PlanSnapshotKind = "initial"

    @property
    def is_final(self) -> bool:
        return self.snapshot_kind == "final"


@dataclass(frozen=True, slots=True)
class CampaignInfo:
    """Immutable campaign identity and launch context for reports."""

    service: str
    principal_id: str = ""
    resource_id: str = ""
    method_id: str | None = None
    max_checks: int | None = None
    scenario_id: str = ""
    campaign_id: str | None = None
    run_id: str | None = None
    plan_hash: str = ""


@dataclass(frozen=True, slots=True)
class FindingSummaryGroup:
    """One deterministic row in the findings summary projection."""

    vulnerability_class: str
    cwe: tuple[str, ...]
    severity: Severity
    count: int


@dataclass(frozen=True, slots=True)
class ReportBundle:
    """Immutable read model consumed by every report format.

    ``findings`` carries security findings only.  Classification deficits
    stay fully observable in ``diagnostics`` with their provenance intact.
    """

    campaign: CampaignInfo
    findings: tuple[Finding, ...]
    diagnostics: tuple[Finding, ...]
    observations: tuple[Observation, ...]
    invariants: tuple[InvariantProjection, ...]
    scenarios: tuple[ScenarioPosition, ...]
    leads: tuple[ReportLeadView, ...]
    metrics: CampaignMetricsSnapshot
    coverage: QdlCoverageModel | None
    scenario_classes: Mapping[object, tuple[ScenarioPosition, ...]]
    scenario_coverage: Mapping[str, bool]
    finding_summary: tuple[FindingSummaryGroup, ...]
    owasp: tuple[OwaspSlice, ...]
    owasp_ground_truth: tuple[OwaspAxisScore, ...] | None = None
    method_action_coverage: MethodActionCoverageModel | None = None
    plan: QdlPlanSnapshot | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "scenario_classes",
            MappingProxyType(dict(self.scenario_classes)),
        )
        object.__setattr__(
            self,
            "scenario_coverage",
            MappingProxyType(dict(self.scenario_coverage)),
        )


class ReportRenderer(Protocol):
    """Format-neutral entry point for report presentation."""

    def render(self, bundle: ReportBundle) -> str | bytes: ...


def _scenario_class_key(profile: ScenarioProfile) -> tuple[object, ...]:
    """Return the reporting-only grouping key for scenario dimensions."""

    return (
        profile.scope_relation,
        profile.binding_level,
        profile.endpoint_layer,
        profile.resource_state,
        profile.identity_class,
        profile.addressing_mode,
    )


class ReportService:
    """Build business read models consumed by presentation formatters."""

    def bundle(
        self,
        *,
        campaign: CampaignInfo,
        findings: Iterable[Finding] = (),
        observations: Iterable[Observation] = (),
        invariants: Iterable[InvariantProjection] = (),
        scenarios: Iterable[ScenarioPosition] = (),
        leads: Iterable[ReportLeadView] = (),
        metrics: CampaignMetricsSnapshot | None = None,
        coverage: QdlCoverageMatrixView | None = None,
        owasp_ground_truth: Iterable[OwaspAxisScore] | None = None,
        method_action_coverage: MethodActionCoverageModel | None = None,
        plan: QdlPlanSnapshot | None = None,
    ) -> ReportBundle:
        """Materialize the single read model used by every report format.

        Classification deficits are not security findings: they are projected
        into ``diagnostics``, while findings, the finding summary, and the
        OWASP distribution describe classifiable security findings only.
        """

        finding_items = _dedupe_by_id(findings, lambda finding: finding.finding_id)
        security_findings, diagnostic_findings = split_classification_deficits(
            finding_items
        )
        observation_items = tuple(observations)
        invariant_items = tuple(invariants)
        scenario_items = tuple(scenarios)
        lead_items = dedupe_leads(leads)

        return ReportBundle(
            campaign=campaign,
            findings=security_findings,
            diagnostics=diagnostic_findings,
            observations=observation_items,
            invariants=invariant_items,
            scenarios=scenario_items,
            leads=lead_items,
            metrics=metrics if metrics is not None else CampaignMetricsSnapshot(),
            coverage=self.qdl_coverage(coverage) if coverage is not None else None,
            scenario_classes=self.scenarios(scenario_items),
            scenario_coverage=self.coverage(observation_items, scenario_items),
            finding_summary=finding_summary(security_findings),
            owasp=owasp_distribution(security_findings),
            owasp_ground_truth=(
                tuple(owasp_ground_truth) if owasp_ground_truth is not None else None
            ),
            method_action_coverage=method_action_coverage,
            plan=plan,
        )

    def contracts(
        self, methods: Iterable[MethodSpec]
    ) -> Mapping[str, tuple[MethodSpec, ...]]:
        grouped: dict[str, list[MethodSpec]] = {}
        for method in methods:
            grouped.setdefault(method.service, []).append(method)
        return {service: tuple(items) for service, items in grouped.items()}

    def coverage(
        self,
        observations: Iterable[Observation],
        scenarios: Iterable[ScenarioPosition],
    ) -> Mapping[str, bool]:
        covered = {observation.scenario_id for observation in observations}
        return {
            scenario.scenario_id: scenario.scenario_id in covered
            for scenario in scenarios
        }

    def coverage_from_events(
        self, events: Iterable[DomainEvent], scenarios: Iterable[ScenarioPosition]
    ) -> Mapping[str, bool]:
        covered = {
            event.scenario_id for event in events if isinstance(event, CoverageUpdated)
        }
        return {
            scenario.scenario_id: scenario.scenario_id in covered
            for scenario in scenarios
        }

    def method_coverage(
        self, events: Iterable[DomainEvent], methods: Iterable[MethodSpec]
    ) -> Mapping[str, bool]:
        covered = {
            event.method_id for event in events if isinstance(event, CoverageUpdated)
        }
        return {method.method_id: method.method_id in covered for method in methods}

    def action_coverage(
        self, events: Iterable[DomainEvent], methods: Iterable[MethodSpec]
    ) -> Mapping[str, bool]:
        """Project method coverage onto the corresponding QDL action IDs."""

        method_coverage = self.method_coverage(events, methods)
        return {
            f"action:{method_id}": covered
            for method_id, covered in method_coverage.items()
        }

    def method_action_coverage(
        self, events: Iterable[DomainEvent], methods: Iterable[MethodSpec]
    ) -> MethodActionCoverageModel:
        """Return independent method and action execution projections."""

        event_items = tuple(events)
        method_items = tuple(methods)
        return MethodActionCoverageModel(
            methods=self.method_coverage(event_items, method_items),
            actions=self.action_coverage(event_items, method_items),
        )

    def invariant_coverage(
        self, events: Iterable[DomainEvent], invariants: Iterable[InvariantProjection]
    ) -> Mapping[str, bool]:
        covered = {
            event.invariant_id for event in events if isinstance(event, CoverageUpdated)
        }
        return {
            invariant.invariant_id: invariant.invariant_id in covered
            for invariant in invariants
        }

    def evidence(self, events: Iterable[Event]) -> Mapping[str, str | None]:
        evidence: dict[str, str | None] = {}
        for event in events:
            if isinstance(event, CheckCompleted):
                evidence.setdefault(event.observation.observation_id, None)
            elif isinstance(event, FindingRaised):
                evidence[event.finding.observation_id] = event.finding.finding_id
        return evidence

    def scenarios(
        self, scenarios: Iterable[ScenarioPosition]
    ) -> Mapping[object, tuple[ScenarioPosition, ...]]:
        grouped: dict[object, list[ScenarioPosition]] = {}
        for scenario in scenarios:
            grouped.setdefault(_scenario_class_key(scenario.profile), []).append(
                scenario
            )
        return {key: tuple(items) for key, items in grouped.items()}

    def qdl_coverage(self, matrix: QdlCoverageMatrixView) -> QdlCoverageModel:
        """Build the derivation-based QDL coverage read model.

        Only QDL field, effect, and state-machine projections are
        represented — never action-level cells (S24 v2).  The generic
        term projection and its missing-factor counts expose the S24R
        algebra ``coverage(term) = semantic × setup × oracle × runtime``
        without importing workflow types.
        """

        field_cells = tuple(
            QdlFieldCoverageItem(
                field_id=cell.field_id,
                field_name=cell.field_name,
                field_kind=cell.field_kind,
                semantic_role=cell.semantic_role,
                primitive=cell.primitive,
                status=cell.status,
                deficit=cell.deficit,
                rationale=cell.rationale,
                request_executed=cell.request_executed,
                request_deficit=cell.request_deficit,
                oracle_witness_observed=cell.oracle_witness_observed,
            )
            for cell in matrix.fields
        )
        effect_cells = tuple(
            QdlEffectCoverageItem(
                effect_id=cell.effect_id,
                effect_kind=cell.effect_kind,
                primitive=cell.primitive,
                status=cell.status,
                deficit=cell.deficit,
                rationale=cell.rationale,
            )
            for cell in matrix.effects
        )
        state_machine = self._state_machine_model(matrix.state_machine)
        term_cells = tuple(
            QdlTermCoverageItem(
                term_id=cell.term_id,
                term_kind=cell.term_kind,
                status=cell.status,
                deficit=cell.deficit,
                missing_factor=cell.missing_factor,
                rationale=getattr(cell, "rationale", ""),
            )
            for cell in matrix.terms
        )
        deficit_counts = Counter(
            deficit
            for deficit in (
                *(cell.deficit for cell in field_cells),
                *(cell.deficit for cell in effect_cells),
                *(matrix.state_machine.deficits if matrix.state_machine else ()),
            )
            if deficit is not None
        )
        return QdlCoverageModel(
            service=matrix.service,
            fields=_count_statuses(field_cells),
            effects=_count_statuses(effect_cells),
            by_field_kind={
                kind: _count_statuses(
                    cell for cell in field_cells if cell.field_kind == kind
                )
                for kind in ("input", "output", "resource")
            },
            deficit_counts=dict(deficit_counts),
            field_cells=field_cells,
            effect_cells=effect_cells,
            gaps=tuple(
                cell
                for cell in (*field_cells, *effect_cells)
                if cell.status in {"unresolved", "blind"}
            ),
            state_machine=state_machine,
            term_cells=term_cells,
            missing_factor_counts=dict(matrix.missing_factor_counts),
            request_deficit_count=matrix.request_deficit_count,
        )

    def qdl_plan(
        self,
        plan: QdlPlanView,
        *,
        snapshot_kind: PlanSnapshotKind = "initial",
    ) -> QdlPlanSnapshot:
        """Build an immutable, explicitly initial or final plan snapshot.

        The live workflow currently publishes the initial snapshot before
        reactive grounding.  A final caller can use the same owned read model
        with ``snapshot_kind="final"`` instead of presenting that initial
        PlanReady projection as the final runtime plan.
        """

        if snapshot_kind not in {"initial", "final"}:
            raise ValueError("snapshot_kind must be 'initial' or 'final'")

        return QdlPlanSnapshot(
            graph_hash=plan.graph_hash,
            paths=tuple(
                QdlPlanPathSnapshot(
                    path_id=path.path_id,
                    goal_id=path.goal_id,
                    gate=path.gate,
                    steps=tuple(
                        QdlPlanStepSnapshot(
                            step_id=step.step_id,
                            method_id=step.method.method_id,
                        )
                        for step in path.steps
                    ),
                )
                for path in plan.paths
            ),
            snapshot_kind=snapshot_kind,
        )

    @staticmethod
    def _state_machine_model(
        state_machine: _QdlStateMachineCoverageView | None,
    ) -> QdlStateMachineCoverageModel | None:
        if state_machine is None:
            return None
        return QdlStateMachineCoverageModel(
            states=_count_statuses(state_machine.states),
            transitions=_count_statuses(state_machine.transitions),
            forbidden_states=_count_statuses(state_machine.forbidden_states),
            initial_states=tuple(state_machine.initial_states),
            reachable_states=tuple(state_machine.reachable_states),
            mismatches=len(state_machine.mismatches),
        )


def _count_statuses(items: Iterable[_CoverageStatusView]) -> QdlCoverageCounts:
    counts = Counter(item.status for item in items)
    return QdlCoverageCounts(
        total=sum(counts.values()),
        covered=counts["covered"],
        unresolved=counts["unresolved"],
        blind=counts["blind"],
        not_applicable=counts["not_applicable"],
    )


def _dedupe_by_id(items: Iterable[object], key) -> tuple[object, ...]:
    """Keep the first stable projection row for replayed domain objects."""

    seen: set[object] = set()
    unique: list[object] = []
    for item in items:
        item_key = key(item)
        if item_key in seen:
            continue
        seen.add(item_key)
        unique.append(item)
    return tuple(unique)


class _OwaspFindingView(Protocol):
    """Minimal taxonomy surface consumed by the OWASP read model."""

    @property
    def owasp(self) -> tuple[str, ...]: ...


def split_classification_deficits(
    findings: Iterable[Finding],
) -> tuple[tuple[Finding, ...], tuple[Finding, ...]]:
    """Separate security findings from classification-deficit diagnostics.

    A classification deficit means the catalog could not ground a violated
    norm in a vulnerability class.  It is diagnostic signal about the
    classification process, not a security finding, so the report read model
    keeps it out of the findings projection while preserving the finding
    verbatim for observability and provenance.
    """

    security_findings: list[Finding] = []
    diagnostics: list[Finding] = []
    seen: set[str] = set()
    for finding in findings:
        if finding.finding_id in seen:
            continue
        seen.add(finding.finding_id)
        if is_classification_deficit(finding.vulnerability_class):
            diagnostics.append(finding)
        else:
            security_findings.append(finding)
    return tuple(security_findings), tuple(diagnostics)


@dataclass(frozen=True, slots=True)
class OwaspSlice:
    """One OWASP API category in the findings distribution."""

    category: str
    count: int
    ring_fraction: float


@dataclass(frozen=True, slots=True)
class OwaspAxisScore:
    """Ground-truth recall for one OWASP API axis."""

    axis: str
    expected: int
    matched: int

    @property
    def recall(self) -> float:
        return self.matched / self.expected if self.expected else 0.0


def finding_summary(
    findings: Iterable[_FindingSummaryView],
) -> tuple[FindingSummaryGroup, ...]:
    """Group findings by class, CWE combination, and severity.

    A finding is counted once even when it carries several CWE identifiers.
    The CWE combination is normalized to sorted unique values, and groups are
    ordered by class, CWE, and descending severity.
    """

    counts: Counter[tuple[str, tuple[str, ...], Severity]] = Counter()
    for finding in findings:
        key = (
            finding.vulnerability_class,
            tuple(sorted(dict.fromkeys(finding.cwe))),
            finding.severity,
        )
        counts[key] += 1

    return tuple(
        FindingSummaryGroup(
            vulnerability_class=vulnerability_class,
            cwe=cwe,
            severity=severity,
            count=count,
        )
        for (
            vulnerability_class,
            cwe,
            severity,
        ), count in sorted(
            counts.items(),
            key=lambda item: (
                item[0][0],
                item[0][1],
                -severity_score(item[0][2]),
            ),
        )
    )


def owasp_distribution(
    findings: Iterable[_OwaspFindingView],
) -> tuple[OwaspSlice, ...]:
    """Aggregate findings into deterministic OWASP API Top 10 slices.

    A finding tagged with several categories is counted in every one of them,
    so ring fractions describe the distribution of classified occurrences
    rather than a partition of findings.  Findings without an OWASP tag land
    in ``unclassified``.  Ordering is deterministic: count descending, then
    category ascending.
    """

    counts: Counter[str] = Counter()
    for finding in findings:
        categories = tuple(dict.fromkeys(finding.owasp))
        if not categories:
            counts["unclassified"] += 1
        else:
            counts.update(categories)
    ring_total = sum(counts.values())
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return tuple(
        OwaspSlice(
            category=category,
            count=count,
            ring_fraction=count / ring_total if ring_total else 0.0,
        )
        for category, count in ordered
    )
