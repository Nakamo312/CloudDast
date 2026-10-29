from __future__ import annotations

from cloud_dast.model import (
    AccessOutcome,
    Check,
    HttpStatus,
    Observation,
)
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    input_field,
    reached,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding import MeasuredEvidencePolicy
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.verification.differential.report import DiffReport
from cloud_dast.verification.promotion import PromotionPolicy
from tests.grounding_owner import commit_variance, make_grounding


class FormalRepository:
    def __init__(self) -> None:
        self.saved: list[dict] = []

    def save(
        self,
        source_id: str,
        graph: QdlGraph,
        *,
        provenance: dict,
        adapter_version: str,
        mapping_report: dict,
    ) -> None:
        self.saved.append(
            {
                "source_id": source_id,
                "graph": graph,
                "provenance": provenance,
                "adapter_version": adapter_version,
                "mapping_report": mapping_report,
            }
        )

    def load(self, source_id: str) -> QdlGraph:
        return next(
            (
                item["graph"]
                for item in reversed(self.saved)
                if item["source_id"] == source_id
            ),
            QdlGraph(),
        )

    def load_merged(self, source_prefix: str) -> QdlGraph:
        merged = QdlGraph()
        for item in self.saved:
            if item["source_id"].startswith(source_prefix):
                merged = merge_graphs(merged, item["graph"])
        return merged


class ScriptedVarianceGrounding:
    def __init__(self, proposal: QdlGraph) -> None:
        self.proposal = proposal
        self.sources: list[QdlGraph] = []

    def ground_variance(self, source, action_id, **kwargs) -> AxisResult:
        self.sources.append(source)
        return AxisResult("variance", self.proposal, 0, 1)


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.CONTRACT,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def _source(*, declare_sink: bool = True) -> QdlGraph:
    action = Atom(value="action:get")
    query = input_field(action, Atom(value="query"))
    facts = [
        _fact("is", (action, Atom(value="Action"))),
        _fact("is", (query, Atom(value="Field"))),
    ]
    if declare_sink:
        sink = Atom(value="sink:sql")
        facts.extend(
            (
                _fact("is", (sink, Atom(value="interpreter"))),
                _fact("reaches", (query, sink)),
            )
        )
    return QdlGraph(facts=tuple(facts))


def _pair() -> tuple[Check, Check, Observation, Observation, DiffReport]:
    control_check = Check(
        invariant_id="norm:test",
        method_id="get",
        scenario_id="attacker",
        request=(("query", "benign"),),
        identities=("attacker",),
    )
    treatment_check = Check(
        invariant_id="norm:test",
        method_id="get",
        scenario_id="attacker",
        request=(("query", "'canary'"),),
        identities=("attacker",),
    )
    treatment = Observation(
        check_id=treatment_check.check_id,
        scenario_id="attacker",
        observed_outcome=AccessOutcome.ERROR,
        response_summary="request rejected",
        transport_status=HttpStatus(code=400),
        error_reason="unrecognized token: canary",
    )
    control = Observation(
        check_id=control_check.check_id,
        scenario_id="attacker",
        observed_outcome=AccessOutcome.ERROR,
        response_summary="request rejected",
        transport_status=HttpStatus(code=400),
        error_reason="unrecognized token: benign",
    )
    report = DiffReport(
        action_id="get",
        control_observation_id="control",
        treatment_observation_id="treatment",
        dimensions=("error",),
    )
    return control_check, treatment_check, control, treatment, report


def _reached_norm_proposal(sink: Atom) -> QdlGraph:
    action = Atom(value="action:get")
    norm = Atom(value="norm:no-sink-reach")
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (sink, Atom(value="interpreter")), Context.PROPOSAL),
            _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
            _fact(
                "prevents",
                (norm, reached(action, sink)),
                Context.PROPOSAL,
            ),
        )
    )


def test_canary_echo_is_runtime_structural_evidence() -> None:
    control_check, treatment_check, _control, treatment, report = _pair()

    graph = MeasuredEvidencePolicy().project(
        _source(declare_sink=False),
        "get",
        control_check=control_check,
        treatment_check=treatment_check,
        treatment=treatment,
        report=report,
    )

    assert graph.facts
    assert all(fact.context is Context.RUNTIME for fact in graph.facts)
    reach = next(fact for fact in graph.facts if fact.predicate.name == "reaches")
    sink = reach.args[1]
    assert str(sink.value).startswith("sink:canary-echo:query:")
    assert not any(fact.predicate.name == "prevents" for fact in graph.facts)
    assert not any(
        fact.predicate.name == "is" and fact.args == (sink, Atom(value="interpreter"))
        for fact in graph.facts
    )


def test_canary_echo_requires_a_source_action() -> None:
    control_check, treatment_check, _control, treatment, report = _pair()

    graph = MeasuredEvidencePolicy().project(
        QdlGraph(),
        "get",
        control_check=control_check,
        treatment_check=treatment_check,
        treatment=treatment,
        report=report,
    )

    assert graph.facts == ()


def test_grounding_persists_echo_but_does_not_promote_without_llm() -> None:
    repository = FormalRepository()
    repository.save(
        "contract:service",
        _source(declare_sink=False),
        provenance={"source_kind": "test"},
        adapter_version="test",
        mapping_report={"mapped": 0, "unmapped": 0},
    )
    axis = ScriptedVarianceGrounding(QdlGraph())
    grounding = make_grounding(
        repository,
        startup=axis,
        reactive=axis,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    control_check, treatment_check, control, treatment, report = _pair()

    result = commit_variance(
        grounding,
        "service",
        "get",
        control,
        treatment,
        report,
        control_check=control_check,
        treatment_check=treatment_check,
        llm=False,
    )

    assert result is None
    assert axis.sources == []
    measured = next(
        item
        for item in repository.saved
        if item["provenance"]["source_kind"] == "diff-measured-evidence"
    )
    assert all(fact.context is Context.RUNTIME for fact in measured["graph"].facts)
    assert not any(
        fact.predicate.name == "prevents" for fact in measured["graph"].facts
    )


def test_source_declared_sink_witness_can_promote_model_norm() -> None:
    repository = FormalRepository()
    repository.save(
        "contract:service",
        _source(),
        provenance={"source_kind": "test"},
        adapter_version="test",
        mapping_report={"mapped": 0, "unmapped": 0},
    )
    axis = ScriptedVarianceGrounding(_reached_norm_proposal(Atom(value="sink:sql")))
    grounding = make_grounding(
        repository,
        startup=axis,
        reactive=axis,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    control_check, treatment_check, control, treatment, report = _pair()

    result = commit_variance(
        grounding,
        "service",
        "get",
        control,
        treatment,
        report,
        control_check=control_check,
        treatment_check=treatment_check,
    )

    assert result is not None
    assert any(fact.predicate.name == "prevents" for fact in result.facts)
    assert axis.sources
    assert any(
        fact.context is Context.RUNTIME and fact.predicate.name == "reaches"
        for fact in axis.sources[0].facts
    )


def test_model_cannot_turn_measured_echo_into_interpreter_sink() -> None:
    repository = FormalRepository()
    repository.save(
        "contract:service",
        _source(declare_sink=False),
        provenance={"source_kind": "test"},
        adapter_version="test",
        mapping_report={"mapped": 0, "unmapped": 0},
    )
    action = Atom(value="action:get")
    query = input_field(action, Atom(value="query"))
    sink = Atom(value="sink:canary-echo:query:test")
    proposal = QdlGraph(
        facts=(
            _fact("is", (query, Atom(value="Field")), Context.PROPOSAL),
            _fact("reaches", (query, sink), Context.PROPOSAL),
            *_reached_norm_proposal(sink).facts,
        )
    )
    axis = ScriptedVarianceGrounding(proposal)
    grounding = make_grounding(
        repository,
        startup=axis,
        reactive=axis,
        promotion_policy=PromotionPolicy(enabled=True),
    )
    control_check, treatment_check, control, treatment, report = _pair()

    result = commit_variance(
        grounding,
        "service",
        "get",
        control,
        treatment,
        report,
        control_check=control_check,
        treatment_check=treatment_check,
    )

    assert result is None
    assert any(
        item["provenance"]["source_kind"] == "diff-measured-evidence"
        for item in repository.saved
    )
    assert not any(
        item["provenance"]["source_kind"] == "diff-campaign"
        for item in repository.saved
    )
