"""Explicit operator approval over parked proposal classifications."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cloud_dast.ports import ApprovalAuditRecord
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    canonical_json,
    output_field,
)
from cloud_dast.qdl.graph_ops import merge_graphs
from cloud_dast.runtime.grounding import AutoGroundingService
from cloud_dast.verification.promotion import (
    promote_proposal,
)


class Repository:
    def __init__(self, graphs: dict[str, QdlGraph]) -> None:
        self.graphs = dict(graphs)
        self.saved: list[tuple[str, QdlGraph]] = []

    def load(self, source_id: str) -> QdlGraph:
        return self.graphs.get(source_id, QdlGraph())

    def load_merged(self, source_prefix: str) -> QdlGraph:
        return merge_graphs(
            *(
                graph
                for source_id, graph in self.graphs.items()
                if source_id.startswith(source_prefix)
            )
        )

    def save(self, source_id: str, graph: QdlGraph, **_kwargs: object) -> None:
        self.saved.append((source_id, graph))
        self.graphs[source_id] = graph


class AuditLog:
    def __init__(self) -> None:
        self.records: list[ApprovalAuditRecord] = []

    def append(self, record: ApprovalAuditRecord) -> None:
        self.records.append(record)


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


def _source() -> QdlGraph:
    action = Atom(value="action:get")
    field = output_field(action, Atom(value="token"))
    return QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (field, Atom(value="OutputField"))),
        )
    )


def _repository() -> Repository:
    action = Atom(value="action:get")
    field = output_field(action, Atom(value="token"))
    classification = _fact(
        "has",
        (field, Atom(value="credential")),
        Context.PROPOSAL,
    )
    declaration = _fact(
        "is",
        (field, Atom(value="OutputField")),
        Context.PROPOSAL,
    )
    action_declaration = _fact(
        "is",
        (action, Atom(value="Action")),
        Context.PROPOSAL,
    )
    return Repository(
        {
            "contract:orders": _source(),
            "proposal:orders:roles:b0": QdlGraph(
                facts=(action_declaration, declaration, classification)
            ),
        }
    )


def test_approval_queue_reads_parked_sources_and_excludes_accepted_facts() -> None:
    repository = _repository()
    grounding = AutoGroundingService(repository)

    parked = grounding.load_parked_proposals("orders")
    queue = grounding.list_classification_approval_queue("orders")

    assert any(fact.predicate.name == "has" for fact in parked.facts)
    assert len(queue) == 1
    assert queue[0].fact_hash == next(
        fact.content_hash for fact in parked.facts if fact.predicate.name == "has"
    )
    assert queue[0].role == "credential"
    assert queue[0].action_id == "action:get"
    assert repository.saved == []


def test_operator_approval_promotes_only_the_reviewed_classification() -> None:
    repository = _repository()
    audit_log = AuditLog()
    grounding = AutoGroundingService(repository, approval_audit_log=audit_log)
    candidate = grounding.list_classification_approval_queue("orders")[0]

    result = grounding.promote_parked_classification(
        "orders",
        candidate.fact_hash,
        operator="ridrapsody",
        reason="Confirmed credential field with the service owner.",
    )

    assert result.fact_hash == candidate.fact_hash
    assert result.promoted_facts > 0
    assert repository.saved[0][0].startswith(
        f"accepted-batch:orders:operator-approval:{candidate.fact_hash}:"
    )
    accepted = repository.saved[0][1]
    assert all(fact.context is Context.ACCEPTED for fact in accepted.facts)
    assert any(
        fact.predicate.name == "has" and fact.args[1].value == "credential"  # type: ignore[attr-defined]
        for fact in accepted.facts
    )
    assert not any(fact.predicate.name == "prevents" for fact in accepted.facts)
    assert len(audit_log.records) == 1
    assert audit_log.records[0].fact_hash == candidate.fact_hash
    assert audit_log.records[0].operator == "ridrapsody"
    assert grounding.list_classification_approval_queue("orders") == ()


def test_operator_approval_requires_an_audit_log() -> None:
    repository = _repository()
    grounding = AutoGroundingService(repository)
    candidate = grounding.list_classification_approval_queue("orders")[0]

    with pytest.raises(RuntimeError, match="audit log"):
        grounding.promote_parked_classification(
            "orders",
            candidate.fact_hash,
            operator="ridrapsody",
            reason="Owner confirmed the classification.",
        )


def test_operator_approval_validates_audit_identity_before_persistence() -> None:
    repository = _repository()
    audit_log = AuditLog()
    grounding = AutoGroundingService(repository, approval_audit_log=audit_log)
    candidate = grounding.list_classification_approval_queue("orders")[0]

    with pytest.raises(ValidationError):
        grounding.promote_parked_classification(
            "orders",
            candidate.fact_hash,
            operator="not an operator",
            reason="Owner confirmed the classification.",
        )

    assert repository.saved == []
    assert audit_log.records == []


def test_operator_approval_cannot_make_a_hallucinated_action_executable() -> None:
    action = Atom(value="action:get")
    hallucinated = output_field(action, Atom(value="not_in_contract"))
    classification = _fact(
        "has",
        (hallucinated, Atom(value="credential")),
        Context.PROPOSAL,
    )
    declaration = _fact(
        "is",
        (hallucinated, Atom(value="OutputField")),
        Context.PROPOSAL,
    )
    action_declaration = _fact(
        "is",
        (action, Atom(value="Action")),
        Context.PROPOSAL,
    )
    repository = Repository(
        {
            "contract:orders": _source(),
            "proposal:orders:roles:b0": QdlGraph(
                facts=(action_declaration, declaration, classification)
            ),
        }
    )
    audit_log = AuditLog()
    grounding = AutoGroundingService(repository, approval_audit_log=audit_log)
    candidate = grounding.list_classification_approval_queue("orders")[0]

    with pytest.raises(ValueError, match="deterministic promotion"):
        grounding.promote_parked_classification(
            "orders",
            candidate.fact_hash,
            operator="ridrapsody",
            reason="Incorrectly trusted a model hallucination.",
        )

    assert repository.saved == []
    assert audit_log.records == []


def test_operator_provenance_override_is_scoped_to_one_fact_hash() -> None:
    action = Atom(value="action:get")
    approved_field = output_field(action, Atom(value="token"))
    unapproved_field = output_field(action, Atom(value="session"))
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (approved_field, Atom(value="OutputField"))),
            _fact("is", (unapproved_field, Atom(value="OutputField"))),
        )
    )
    approved = _fact(
        "has",
        (approved_field, Atom(value="credential")),
        Context.PROPOSAL,
    )
    unapproved = _fact(
        "has",
        (unapproved_field, Atom(value="sensitive")),
        Context.PROPOSAL,
    )

    result = promote_proposal(
        source,
        QdlGraph(
            facts=(
                _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
                _fact(
                    "is",
                    (approved_field, Atom(value="OutputField")),
                    Context.PROPOSAL,
                ),
                _fact(
                    "is",
                    (unapproved_field, Atom(value="OutputField")),
                    Context.PROPOSAL,
                ),
                approved,
                unapproved,
            )
        ),
        approved_classifications=frozenset((approved.content_hash,)),
    )

    assert any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "has"
        and canonical_json(fact.args) == canonical_json(approved.args)
        for fact in result.graph.facts
    )
    assert not any(
        fact.context is Context.ACCEPTED
        and fact.predicate.name == "has"
        and canonical_json(fact.args) == canonical_json(unapproved.args)
        for fact in result.graph.facts
    )
    assert result.parked_classifications is not None
    assert any(
        fact.content_hash == unapproved.content_hash
        for fact in result.parked_classifications.facts
    )
