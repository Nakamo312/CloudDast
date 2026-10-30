"""Explicit promotion of validated formal proposals into executable norms."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable, Collection, Mapping
from typing import TYPE_CHECKING

from cloud_dast.config import DEFAULT_MAX_PROMOTED_NORMS, MAX_SEMANTIC_FACTS
from cloud_dast.couplings import COUPLED_OPERATORS
from cloud_dast.model.events import normalize_action, normalize_principal
from cloud_dast.proposals import (
    ClassificationPromotionContext,
    LeadDescriptor,
    PayloadCorpusPromotionResult,
    ProposalPromotionRequest,
    ProposalPromotionResult,
)
from cloud_dast.qdl.graph import (
    CAUSAL_EFFECT_CONSTRUCTORS,
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    canonical_json,
    duration,
)
from cloud_dast.qdl.graph_ops import atom_value, merge_graphs
from cloud_dast.qdl.validation import (
    ValidationIssue,
    filter_declaration_closure,
)
from cloud_dast.verification.norms import (
    LEAD_NORM_PREFIX,
    NormCompiler,
    NormView,
)

if TYPE_CHECKING:
    from cloud_dast.contracts.payload_proposals import (
        PayloadCorpusDelta,
        PayloadCorpusGuardrail,
    )
    from cloud_dast.contracts.payloads import PayloadCorpus

_EXECUTABLE_CONTEXTS = frozenset({Context.CONTRACT, Context.ACCEPTED})
_CAUSAL_EFFECT_CONSTRUCTORS = frozenset(CAUSAL_EFFECT_CONSTRUCTORS)
_OWNERSHIP_EFFECT_CONSTRUCTORS = frozenset({"create", "remove"})
_REACH_SINK_TYPES = frozenset(
    {"interpreter", "filesystem", "business_flow", "external_net"}
)
_RUNTIME_EVIDENCE_REQUIRED_PREDICATES = frozenset({"requires", "targets", "refers_to"})
PROTECTED_CLASSIFICATION_ROLES = frozenset({"sensitive", "credential", "privileged"})
_DIRECT_SUPPORT_EFFECTS = frozenset({"reached", "has"})
_EXTRA_SEMANTIC_PREDICATES = frozenset(
    {"requires", "accepts", "binds", "required", "targets", "refers_to", "applies_to"}
)

logger = logging.getLogger("cloud_dast.verification.promotion")


def lead_descriptor(fact: Fact) -> LeadDescriptor | None:
    """Project one proposal fact onto stable lead coordinates.

    A fact without a subject term has no holder and therefore no lead
    identity.  The role is typed by the predicate so two different relations
    over the same subject never collapse into one lead.
    """

    if not fact.args:
        return None
    subject = fact.args[0]
    role_value = canonical_json(fact.args[1]) if len(fact.args) > 1 else ""
    return LeadDescriptor(
        action=_lead_action(subject),
        holder=canonical_json(subject),
        role=json.dumps(
            (fact.predicate.name, role_value),
            ensure_ascii=False,
            separators=(",", ":"),
        ),
        fact_key=canonical_json(fact),
        fact_hash=fact.content_hash,
        fact=fact,
    )


def _lead_action(subject: object) -> str:
    """Return the string carrier named by one lead subject term."""

    if isinstance(subject, Struct) and subject.args:
        value = atom_value(subject.args[0])
    else:
        value = atom_value(subject)
    return value if isinstance(value, str) else ""


def _requested_actions(
    action_ids: frozenset[str] | tuple[str, ...],
) -> frozenset[str] | None:
    if not action_ids:
        return None
    requested: set[str] = set()
    for action_id in action_ids:
        if not isinstance(action_id, str):
            continue
        requested.add(action_id)
        if action_id.startswith("action:"):
            requested.add(action_id.removeprefix("action:"))
        else:
            requested.add(f"action:{action_id}")
    return frozenset(requested)


def _expose_is_source_owned(
    fact: Fact,
    source_actions: frozenset[str],
    source_witnesses: set[str],
    source_output_fields: set[tuple[str, str]],
) -> bool:
    if len(fact.args) != 2:
        return False
    action = atom_value(fact.args[0])
    witness = fact.args[1]
    if action not in source_actions or not isinstance(witness, Struct):
        return False
    field_name = atom_value(witness.args[1]) if len(witness.args) == 2 else None
    return canonical_json(witness) in source_witnesses or (
        field_name is not None and (action, field_name) in source_output_fields
    )


def _source_output_fields(graph: QdlGraph) -> set[tuple[str, str]]:
    fields: set[tuple[str, str]] = set()
    for fact in graph.facts_for("is", contexts=_EXECUTABLE_CONTEXTS):
        if len(fact.args) != 2:
            continue
        entity = fact.args[0]
        if (
            isinstance(entity, Struct)
            and entity.name == "output_field"
            and len(entity.args) == 2
        ):
            action = atom_value(entity.args[0])
            field_name = atom_value(entity.args[1])
            if action is not None and field_name is not None:
                fields.add((action, field_name))
    for fact in graph.facts_for("exposes", contexts=_EXECUTABLE_CONTEXTS):
        if len(fact.args) != 2:
            continue
        action = atom_value(fact.args[0])
        witness = fact.args[1]
        if (
            action is not None
            and isinstance(witness, Struct)
            and witness.name == "field"
            and len(witness.args) == 2
        ):
            field_name = atom_value(witness.args[1])
            if field_name is not None:
                fields.add((action, field_name))
    return fields


def _response_fact_is_evidence_grounded(
    fact: Fact,
    allowed_actions: frozenset[str],
    source_targets: dict[str, set[str | None]],
    source_witnesses: set[str],
    evidence_fields: frozenset[str],
) -> bool:
    if len(fact.args) != 2:
        return False
    action = atom_value(fact.args[0])
    witness = fact.args[1]
    if action not in allowed_actions or not isinstance(witness, Struct):
        return False
    if witness.name != "field" or len(witness.args) != 2:
        return False
    resource = atom_value(witness.args[0])
    field_name = atom_value(witness.args[1])
    return field_name in evidence_fields and (
        canonical_json(witness) in source_witnesses
        or resource in source_targets.get(action, set())
    )


def _target_resources(graph: QdlGraph) -> dict[str, set[str | None]]:
    result: dict[str, set[str | None]] = {}
    for fact in graph.facts:
        if fact.context not in _EXECUTABLE_CONTEXTS:
            continue
        if fact.predicate.name != "targets" or len(fact.args) != 2:
            continue
        action = atom_value(fact.args[0])
        if action is None:
            continue
        result.setdefault(action, set()).add(atom_value(fact.args[1]))
    return result


def _source_declared_witnesses(graph: QdlGraph) -> set[str]:
    return {
        canonical_json(fact.args[0])
        for fact in graph.facts
        if fact.context in _EXECUTABLE_CONTEXTS
        and fact.predicate.name == "is"
        and fact.args
        and isinstance(fact.args[0], Struct)
        and fact.args[0].name in {"field", "output_field"}
    }


def _is_output_field_fact(fact: Fact) -> bool:
    if fact.predicate.name != "has" or len(fact.args) != 2:
        return False
    holder = fact.args[0]
    return isinstance(holder, Struct) and holder.name == "output_field"


def field_is_bound(
    entity: object,
    kind: str,
    owners: Collection[str | None],
    evidence_fields: Collection[str],
) -> bool:
    """Check a field's shape, owner, and observed name as one binding."""

    return (
        isinstance(entity, Struct)
        and entity.name == kind
        and len(entity.args) == 2
        and atom_value(entity.args[0]) in owners
        and atom_value(entity.args[1]) in evidence_fields
    )


def _source_exposed_witnesses(graph: QdlGraph) -> set[str]:
    return {
        canonical_json(fact.args[1])
        for fact in graph.facts
        if fact.context in _EXECUTABLE_CONTEXTS
        and fact.predicate.name == "exposes"
        and len(fact.args) == 2
        and isinstance(fact.args[1], Struct)
        and fact.args[1].name == "field"
    }


def _is_field_role_fact(fact: Fact) -> bool:
    if fact.predicate.name != "has" or len(fact.args) != 2:
        return False
    holder = fact.args[0]
    return isinstance(holder, Struct) and holder.name == "field"


def _field_role_witness(fact: Fact) -> str | None:
    holder = fact.args[0]
    return canonical_json(holder) if isinstance(holder, Struct) else None


def _is_response_declaration(fact: Fact) -> bool:
    if fact.predicate.name != "is" or not fact.args:
        return False
    entity = fact.args[0]
    return isinstance(entity, Struct) and entity.name in {"output_field", "field"}


def _response_declaration_is_grounded(
    fact: Fact,
    source_output_fields: set[tuple[str, str]],
    valid_witnesses: set[str],
    allowed_actions: frozenset[str],
    evidence_fields: frozenset[str],
) -> bool:
    entity = fact.args[0]
    if not isinstance(entity, Struct) or len(entity.args) != 2:
        return False
    if entity.name == "output_field":
        action = atom_value(entity.args[0])
        field_name = atom_value(entity.args[1])
        return (action, field_name) in source_output_fields or (
            action in allowed_actions and field_name in evidence_fields
        )
    return canonical_json(entity) in valid_witnesses


def _filter_response_semantics(
    graph: QdlGraph,
    source: QdlGraph,
    *,
    allowed_actions: frozenset[str] | None,
    evidence_fields: frozenset[str] | None,
    approved_classifications: frozenset[str] = frozenset(),
    classification_context: ClassificationPromotionContext | None = None,
) -> tuple[QdlGraph, tuple[ValidationIssue, ...]]:
    """Apply the response/evidence boundary to one accepted semantic graph."""

    source_actions = source.declared_identifiers(
        "Action", contexts=_EXECUTABLE_CONTEXTS
    )
    source_targets = _target_resources(source)
    source_witnesses = _source_declared_witnesses(source)
    source_output_fields = _source_output_fields(source)
    evidence = evidence_fields or frozenset()
    actions = allowed_actions or source_actions
    facts = list(graph.facts)
    issues: list[ValidationIssue] = []

    def keep_facts(
        candidates: list[Fact],
        is_valid: Callable[[Fact], bool],
        message: str,
    ) -> list[Fact]:
        kept: list[Fact] = []
        for fact in candidates:
            if is_valid(fact):
                kept.append(fact)
                continue
            issues.append(
                ValidationIssue(
                    code="response_grounding",
                    message=message,
                    path=f"facts[{canonical_json(fact)}]",
                )
            )
        return kept

    facts = keep_facts(
        facts,
        lambda fact: (
            fact.predicate.name != "exposes"
            or _expose_is_source_owned(
                fact,
                source_actions,
                source_witnesses,
                source_output_fields,
            )
            or _response_fact_is_evidence_grounded(
                fact,
                actions,
                source_targets,
                source_witnesses,
                evidence,
            )
        ),
        "exposure is not source-owned or evidence-grounded",
    )
    facts = keep_facts(
        facts,
        lambda fact: (
            not _is_output_field_fact(fact)
            or _classification_fact_is_trusted(
                fact,
                source,
                classification_context,
                actions,
                evidence_fields=evidence,
                approved_classifications=approved_classifications,
            )
            or (
                _field_action(fact.args[0]),
                atom_value(fact.args[0].args[1]),
            )
            in source_output_fields
            or field_is_bound(fact.args[0], "output_field", actions, evidence)
        ),
        "output-field role is not source-owned or evidence-grounded",
    )
    valid_witnesses = _source_exposed_witnesses(source)
    valid_witnesses.update(
        canonical_json(fact.args[1])
        for fact in facts
        if fact.predicate.name == "exposes" and len(fact.args) == 2
    )
    facts = keep_facts(
        facts,
        lambda fact: (
            not _is_field_role_fact(fact)
            or _classification_fact_is_trusted(
                fact,
                source,
                classification_context,
                actions,
                evidence_fields=evidence,
                approved_classifications=approved_classifications,
            )
            or _field_role_witness(fact) in valid_witnesses
        ),
        "field role is not exposed by the source or live evidence",
    )
    facts = keep_facts(
        facts,
        lambda fact: (
            not _is_response_declaration(fact)
            or _classification_fact_is_trusted(
                fact,
                source,
                classification_context,
                actions,
                evidence_fields=evidence,
                approved_classifications=approved_classifications,
            )
            or _response_declaration_is_grounded(
                fact,
                source_output_fields,
                valid_witnesses,
                actions,
                evidence,
            )
        ),
        "response declaration is not source-owned or evidence-grounded",
    )
    result = filter_declaration_closure(facts, graph.rules, issues=issues)
    if result.graph is None:
        return QdlGraph(), result.issues
    return result.graph, result.issues


def _parked_extra_semantics(
    proposal: QdlGraph,
    declarations: dict[str, Fact],
    promoted_keys: frozenset[str] = frozenset(),
) -> QdlGraph | None:
    """Park IAM, authentication, and dependency semantics for operator review."""

    graphs: list[QdlGraph] = []
    for fact in proposal.facts:
        if (
            fact.context is not Context.PROPOSAL
            or fact.predicate.name not in _EXTRA_SEMANTIC_PREDICATES
            or _fact_logical_key(fact) in promoted_keys
        ):
            continue
        facts: list[Fact] = []
        seen: set[str] = set()

        def add(item: Fact) -> None:
            parked_fact = item.model_copy(update={"context": Context.PROPOSAL})
            key = canonical_json(parked_fact)
            if key in seen:
                return
            seen.add(key)
            facts.append(parked_fact)

        add(fact)
        for term in fact.args:
            for declaration in _declarations_for_term(term, declarations):
                add(declaration)
        try:
            graphs.append(QdlGraph(facts=tuple(facts)))
        except ValueError:
            continue
    if not graphs:
        return None
    return merge_graphs(*graphs)


def _fact_logical_key(fact: Fact) -> str:
    return canonical_json(fact.model_copy(update={"context": Context.PROPOSAL}))


def park_proposal(
    source: QdlGraph,
    proposal: QdlGraph,
    *,
    evidence_fields: frozenset[str] | None = None,
) -> ProposalPromotionResult:
    facts = tuple(
        fact.model_copy(update={"context": Context.PROPOSAL})
        for fact in proposal.facts
        if fact.context is Context.PROPOSAL
    )
    try:
        parked = (
            QdlGraph(facts=facts, rules=proposal.rules)
            if facts or proposal.rules
            else None
        )
    except ValueError:
        parked = None
    unproven = _unproven_classifications(source, proposal, evidence_fields)
    declarations = _declarations(source, proposal, include_untrusted=True)
    return ProposalPromotionResult(
        graph=QdlGraph(),
        promoted_norms=(),
        rejected_norms=(),
        parked_classifications=_parked_classifications_graph(
            unproven,
            declarations,
            _lead_norm_bundles(source, proposal, unproven, declarations),
        ),
        parked_semantics=parked,
    )


def promote_proposal(
    request: ProposalPromotionRequest,
    *,
    max_norms: int | None = DEFAULT_MAX_PROMOTED_NORMS,
    max_semantic_facts: int = MAX_SEMANTIC_FACTS,
) -> ProposalPromotionResult:
    """Promote only graph-grounded, action-bound norms from a proposal.

    This is an explicit runtime policy, not automatic model trust.  A proposal
    norm is promoted only when its action is declared by the source graph, its
    effect has a deterministic primitive, and all references can be made
    self-contained in the accepted context.  Effects without an action argument
    (``has``, ``changed``, and ``transition``) use their validated supporting
    semantics for the action binding; directly proposed ``reached`` and ``has``
    effects additionally require merged graph support.  Protected role
    classifications and sink types must already be declared by the source graph;
    a proposal may bind them to source actions, but cannot introduce them.
    Response-witness roles are the one evidence-policy exception: when
    ``evidence_fields`` names fields the run actually observed in responses,
    the model may classify those observed fields, never invent new ones.
    ``max_norms`` selects the first valid norms and reports overflow norms as
    rejected.
    ``max_semantic_facts``
    bounds the accepted semantic bundle and reports overflow separately.
    ``action_ids`` narrows promotion to the actions requested by one reactive,
    alternatives, consultation, or variance call.  Measured runtime evidence is
    not a promotion bypass: an executable sink still has to be declared by the
    source graph.
    ``evidence_refs`` are durable observation identifiers inherited by every
    fact in one consultation proposal.  They establish live-measurement
    provenance for runtime-falsifiable facts, but never satisfy an
    evidence-gated classification or introduce a structural sink witness.
    ``runtime_evidence_exempt_predicates`` is an axis-scoped exception for
    contract typing facts (fixture ``refers_to``/``targets``); action binding
    and every other semantic validation still apply.
    ``approved_classifications`` names exact proposal facts reviewed by an
    operator.  Approval supplies missing role provenance only; action binding
    and every other semantic check still apply.
    A source ``may`` fact for the campaign attacker is expected policy.  A
    proposed ``prevents(N, allowed(A))`` that contradicts it is parked as a
    proposal-context lead for review rather than promoted or silently
    discarded.
    """

    normalized_action_ids = frozenset(request.action_ids)
    if max_norms is not None and max_norms <= 0:
        raise ValueError("max_norms must be positive or None")
    if max_semantic_facts <= 0:
        raise ValueError("max_semantic_facts must be positive")
    evidence_refs = frozenset(request.evidence_refs)
    classification_context = (
        request.classification_context.with_evidence_refs(evidence_refs)
        if request.classification_context is not None
        else None
    )

    declarations = _declarations(request.source, request.proposal)
    review_declarations = _declarations(
        request.source, request.proposal, include_untrusted=True
    )
    source_actions = request.source.declared_identifiers(
        "Action", contexts=_EXECUTABLE_CONTEXTS
    )
    allowed_actions = _requested_actions(normalized_action_ids)
    if allowed_actions is not None:
        source_actions &= allowed_actions
    compiler = NormCompiler()
    candidates = _norm_candidates(request.proposal)
    supported_effects: frozenset[str] = (
        _supported_semantic_effects(
            request.source,
            request.proposal,
            request.evidence_fields,
        )
        if any(
            len(fact.args) == 2
            and isinstance(fact.args[1], Struct)
            and fact.args[1].name in _DIRECT_SUPPORT_EFFECTS
            for facts in candidates.values()
            for fact in facts
        )
        else frozenset()
    )
    valid_norms: list[tuple[str, QdlGraph]] = []
    invalid_norms: list[str] = []
    attacker_may_actions = _attacker_may_actions(request.source)

    for norm_id, facts in candidates.items():
        if len(facts) != 1:
            invalid_norms.append(norm_id)
            continue
        if _norm_contradicts_attacker_policy(facts[0], attacker_may_actions):
            logger.info("norm_parked_policy_contradiction norm=%s", norm_id)
            continue
        graph = _validate_norm(
            facts[0],
            request=request,
            source_actions=source_actions,
            declarations=declarations,
            compiler=compiler,
            supported_effects=supported_effects,
        )
        if graph is None:
            invalid_norms.append(norm_id)
        else:
            valid_norms.append((norm_id, graph))

    selected = valid_norms if max_norms is None else valid_norms[:max_norms]
    overflow = valid_norms[len(selected) :]
    rejected_norms = tuple(
        dict.fromkeys(
            (
                *invalid_norms,
                *(norm_id for norm_id, _build_graph in overflow),
            )
        )
    )
    promoted = [graph for _norm_id, graph in selected]
    promoted_norms = [norm_id for norm_id, _build_graph in selected]
    promotion_issues: list[ValidationIssue] = [
        ValidationIssue(
            code="norm",
            message="proposal norm failed deterministic promotion",
            path=f"norms[{norm_id}]",
        )
        for norm_id in invalid_norms
    ]
    promotion_issues.extend(
        ValidationIssue(
            code="norm_budget",
            message="valid proposal norm exceeds the promotion budget",
            path=f"norms[{norm_id}]",
        )
        for norm_id, _build_graph in overflow
    )
    parked_norms = _parked_policy_norms(
        request.proposal,
        review_declarations,
        attacker_may_actions,
    )

    (
        semantic,
        rejected_semantic_facts,
        parked,
        semantic_issues,
    ) = _promote_semantic_facts(
        request,
        declarations,
        source_actions,
        max_semantic_facts=max_semantic_facts,
        evidence_refs=evidence_refs,
        classification_context=classification_context,
    )
    promotion_issues.extend(semantic_issues)
    filtered_semantic, response_issues = (
        _filter_response_semantics(
            semantic,
            request.source,
            allowed_actions=allowed_actions,
            evidence_fields=request.evidence_fields,
            approved_classifications=request.approved_classifications,
            classification_context=classification_context,
        )
        if semantic is not None
        else (None, ())
    )
    promotion_issues.extend(response_issues)
    promoted_graphs = [*promoted]
    if filtered_semantic is not None and filtered_semantic.facts:
        promoted_graphs.append(filtered_semantic)
    graph = merge_graphs(*promoted_graphs)
    promoted_semantic_keys = (
        frozenset(_fact_logical_key(fact) for fact in filtered_semantic.facts)
        if filtered_semantic is not None
        else frozenset()
    )
    parked_semantics = _parked_extra_semantics(
        request.proposal,
        review_declarations,
        promoted_semantic_keys,
    )

    return ProposalPromotionResult(
        graph=graph,
        promoted_norms=tuple(promoted_norms),
        rejected_norms=tuple(rejected_norms),
        promoted_semantic_facts=(
            len(filtered_semantic.facts)
            if filtered_semantic is not None and filtered_semantic.facts
            else 0
        ),
        rejected_semantic_facts=rejected_semantic_facts,
        parked_classifications=parked,
        parked_semantics=parked_semantics,
        parked_norms=parked_norms,
        issues=tuple(promotion_issues),
    )


def promote_payload_corpus_proposal(
    source: QdlGraph,
    proposal: PayloadCorpusDelta,
    *,
    action_id: str,
    base_corpus: PayloadCorpus,
    guardrail: PayloadCorpusGuardrail | None = None,
    max_items: int | None = None,
) -> PayloadCorpusPromotionResult:
    """Promote only source-grounded, bounded payload-corpus data.

    This is the payload-data analogue of the A15 promotion boundary.  The wire
    schema has no classification channel, and sink types and dialects must
    already be declared by the source graph.  A model can add terminals,
    dialect alternatives, and bounded repetition, but cannot introduce a new
    sink classification, a finding, or executable strategy code.
    """

    from cloud_dast.contracts.payload_proposals import (
        MAX_PAYLOAD_CORPUS_DELTA_ITEMS,
    )
    from cloud_dast.contracts.payload_proposals import (
        PayloadCorpusGuardrail as Guardrail,
    )

    if max_items is None:
        max_items = MAX_PAYLOAD_CORPUS_DELTA_ITEMS
    if max_items <= 0:
        return PayloadCorpusPromotionResult(
            "parked",
            proposal,
            reasons=("payload corpus promotion budget is exhausted",),
        )

    bounds = guardrail or Guardrail(max_items=max_items)
    reasons = list(bounds.rejection_reasons(proposal))
    if proposal.item_count > max_items:
        reasons.append("payload corpus promotion budget is exhausted")

    allowed_sink_types, allowed_dialects = _source_sink_grammar(source, action_id)
    if not allowed_sink_types:
        reasons.append("source graph declares no sink types")

    existing = {item.production_id: item for item in base_corpus.productions}
    promoted_productions: list[str] = []
    promoted_slots: list[str] = []
    for production in proposal.productions:
        unknown_sinks = (
            set(production.sink_types)
            if not set(production.sink_types).intersection(allowed_sink_types)
            else set()
        )
        unknown_dialects = (
            set(production.dialects)
            if not allowed_dialects
            or not set(production.dialects).intersection(allowed_dialects)
            else set()
        )
        if unknown_sinks:
            reasons.append(
                f"production {production.production_id} has source-undeclared "
                f"sink types: {', '.join(sorted(unknown_sinks))}"
            )
        if unknown_dialects:
            reasons.append(
                f"production {production.production_id} has source-undeclared "
                f"dialects: {', '.join(sorted(unknown_dialects))}"
            )
        if production.production_id in existing:
            reasons.append(
                f"payload production already exists: {production.production_id}"
            )
        if not unknown_sinks and not unknown_dialects:
            promoted_productions.append(production.production_id)

    for update in proposal.slot_alternatives:
        production = existing.get(update.production_id)
        if production is None:
            reasons.append(f"unknown payload production: {update.production_id}")
            continue
        unknown_sinks = (
            set(production.sink_types)
            if not set(production.sink_types).intersection(allowed_sink_types)
            else set()
        )
        unknown_dialects = (
            set(production.dialects)
            if not allowed_dialects
            or not set(production.dialects).intersection(allowed_dialects)
            else set()
        )
        if unknown_sinks or unknown_dialects:
            reasons.append(
                f"slot target has source-undeclared grammar: "
                f"{update.production_id}.{update.slot_name}"
            )
            continue
        if not any(slot.name == update.slot_name for slot in production.slots):
            reasons.append(
                f"unknown payload slot: {update.production_id}.{update.slot_name}"
            )
            continue
        promoted_slots.append(f"{update.production_id}.{update.slot_name}")

    reasons = list(dict.fromkeys(reasons))
    if reasons or not promoted_productions and not promoted_slots:
        return PayloadCorpusPromotionResult(
            "rejected",
            proposal,
            promoted_productions=(),
            promoted_slot_alternatives=(),
            promoted_items=0,
            reasons=tuple(reasons or ("empty payload delta",)),
        )
    return PayloadCorpusPromotionResult(
        "promoted",
        proposal,
        promoted_productions=tuple(promoted_productions),
        promoted_slot_alternatives=tuple(promoted_slots),
        promoted_items=len(promoted_productions) + len(promoted_slots),
        reasons=(),
    )


def _source_sink_grammar(
    source: QdlGraph,
    action_id: str,
) -> tuple[set[str], set[str]]:
    """Extract source-declared sink types and dialects for one action."""

    normalized = (
        action_id.removeprefix("action:")
        if action_id.startswith("action:")
        else action_id
    )
    actions = {action_id, normalized, f"action:{normalized}"}
    declarations: dict[str, str] = {}
    for fact in source.facts:
        if (
            fact.context not in _EXECUTABLE_CONTEXTS
            or fact.predicate.name != "is"
            or len(fact.args) != 2
        ):
            continue
        type_name = atom_value(fact.args[1])
        if isinstance(type_name, str):
            declarations[canonical_json(fact.args[0])] = type_name

    reached_sinks: set[str] = set()
    sink_types: set[str] = set()
    for fact in source.facts:
        if (
            fact.context not in _EXECUTABLE_CONTEXTS
            or fact.predicate.name != "reaches"
            or len(fact.args) != 2
            or _field_action(fact.args[0]) not in actions
        ):
            continue
        sink_key = canonical_json(fact.args[1])
        sink_type = declarations.get(sink_key)
        if sink_type is not None:
            reached_sinks.add(sink_key)
            sink_types.add(sink_type)

    dialects: set[str] = set()
    for fact in source.facts:
        if (
            fact.context not in _EXECUTABLE_CONTEXTS
            or fact.predicate.name != "dialect"
            or len(fact.args) != 2
            or canonical_json(fact.args[0]) not in reached_sinks
        ):
            continue
        dialect = atom_value(fact.args[1])
        if isinstance(dialect, str):
            dialects.add(dialect)
    return sink_types, dialects


def _promote_semantic_facts(
    request: ProposalPromotionRequest,
    declarations: dict[str, Fact],
    source_actions: frozenset[str],
    *,
    max_semantic_facts: int,
    evidence_refs: frozenset[str] = frozenset(),
    classification_context: ClassificationPromotionContext | None = None,
) -> tuple[QdlGraph | None, int, QdlGraph | None, tuple[ValidationIssue, ...]]:
    """Promote validated semantic grounding facts into the accepted context.

    Roles (``has``), couplings, dataflows, exposures, causal effects, state
    transitions, grammar facts, and their supporting declarations are the
    semantic layer the algebra runs on.  Every promoted fact is action-bound
    to the source graph;
    causal effects must be valid causal constructors.  Protected role
    classifications must originate in the source graph or, for response
    witnesses, in actually observed evidence fields; sink types must be
    source-declared.  Rejected classifications are parked, not lost: they come
    back as a proposal-context graph for operator review.  ``create`` and
    ``remove`` are semantic-only constructors and deliberately have no oracle
    primitive.  Without this explicit validation, LLM grounding could become
    executable merely by crossing the promotion boundary.
    Ownership effects are additionally evidence-bound: a proposal
    ``causes(Action, create(...))`` or ``causes(Action, remove(...))`` is
    promotable only when the call carries ``evidence_refs``, so an
    alternatives batch cannot mint a setup provider from an action name.
    Operator approval is provenance, not a bypass: action binding and every
    other semantic validation below still apply.
    """

    facts: list[Fact] = []
    parked_facts: list[Fact] = []
    issues: list[ValidationIssue] = []
    seen: set[str] = set()
    classification_declared_subjects: set[str] = set()

    def add(fact: Fact) -> None:
        key = canonical_json(fact)
        if key in seen:
            return
        seen.add(key)
        facts.append(fact.model_copy(update={"context": Context.ACCEPTED}))

    rejected_semantic_facts = 0
    overflow = False
    for fact in request.proposal.facts:
        if fact.context is not Context.PROPOSAL:
            continue
        if fact.predicate.name == "prevents":
            continue
        classification_anchored = _classification_fact_is_anchored(
            fact,
            request.source,
            classification_context,
            source_actions,
        )
        classification_untrusted = _classification_lacks_provenance(
            request.source,
            fact,
            request.evidence_fields,
            request.approved_classifications,
        )
        is_sink_classification = (
            fact.predicate.name == "is"
            and len(fact.args) == 2
            and atom_value(fact.args[1]) in _REACH_SINK_TYPES
        )
        is_protected_role = (
            fact.predicate.name == "has"
            and len(fact.args) == 2
            and atom_value(fact.args[1]) in PROTECTED_CLASSIFICATION_ROLES
        )
        rejection: tuple[str, str] | None = None
        if (
            classification_context is not None
            and (is_sink_classification or is_protected_role)
            and not classification_anchored
        ):
            rejection = (
                "classification_anchor",
                "classification fact is outside the exact obligation",
            )
        elif fact.predicate.name == "is":
            if classification_untrusted or (
                is_sink_classification
                and classification_anchored
                and _sink_type_declaration_lacks_provenance(request.source, fact)
            ):
                rejection = (
                    "classification_parked",
                    "sink type declaration lacks source provenance",
                )
            elif not is_sink_classification:
                continue
            elif classification_anchored:
                classification_declared_subjects.add(canonical_json(fact.args[0]))
        elif classification_untrusted:
            role = atom_value(fact.args[1]) if len(fact.args) == 2 else None
            holder = canonical_json(fact.args[0]) if fact.args else None
            logger.warning(
                "classification_parked_without_provenance role=%s holder=%s",
                role,
                holder,
            )
            rejection = (
                "classification_parked",
                "protected classification lacks trusted provenance",
            )
        if rejection is not None:
            parked_facts.append(fact)
            code, message = rejection
            issues.append(
                ValidationIssue(
                    code=code,
                    message=message,
                    path=f"facts[{canonical_json(fact)}]",
                )
            )
            continue
        if not classification_anchored and not _semantic_fact_is_promotable(
            request.source,
            request.proposal,
            fact,
            source_actions,
            request.evidence_fields,
            evidence_refs,
            request.approved_classifications,
            request.runtime_evidence_exempt_predicates,
        ):
            issues.append(
                ValidationIssue(
                    code="semantic",
                    message="semantic fact failed deterministic promotion",
                    path=f"facts[{canonical_json(fact)}]",
                )
            )
            continue
        if canonical_json(fact) in seen:
            continue
        if _self_contained_graph(fact, declarations=declarations) is None:
            issues.append(
                ValidationIssue(
                    code="closure",
                    message="semantic fact lacks trusted declaration closure",
                    path=f"facts[{canonical_json(fact)}]",
                )
            )
            continue
        if overflow:
            rejected_semantic_facts += 1
            issues.append(
                ValidationIssue(
                    code="semantic_budget",
                    message="semantic promotion budget is exhausted",
                    path=f"facts[{canonical_json(fact)}]",
                )
            )
            continue
        new_declarations = []
        for term in fact.args:
            for declaration in _declarations_for_term(term, declarations):
                if canonical_json(declaration) not in seen:
                    new_declarations.append(declaration)
        new_declarations = [
            declaration
            for declaration in new_declarations
            if canonical_json(declaration.args[0])
            not in classification_declared_subjects
        ]
        if fact.predicate.name == "is" and fact.args:
            # The proposal ``is`` fact is itself the declaration for its
            # subject; adding the source declaration again would create a
            # duplicate accepted fact after context normalization.
            subject_key = canonical_json(fact.args[0])
            new_declarations = [
                declaration
                for declaration in new_declarations
                if canonical_json(declaration.args[0]) != subject_key
            ]
        if len(facts) + len(new_declarations) + 1 > max_semantic_facts:
            rejected_semantic_facts += 1
            overflow = True
            issues.append(
                ValidationIssue(
                    code="semantic_budget",
                    message="semantic fact exceeds the promotion budget",
                    path=f"facts[{canonical_json(fact)}]",
                )
            )
            continue
        for declaration in new_declarations:
            add(declaration)
        add(fact)

    review_declarations = _declarations(
        request.source, request.proposal, include_untrusted=True
    )
    parked = _parked_classifications_graph(
        parked_facts,
        review_declarations,
        _lead_norm_bundles(
            request.source, request.proposal, parked_facts, review_declarations
        ),
    )
    result = filter_declaration_closure(facts, issues=issues)
    if not facts:
        return None, rejected_semantic_facts, parked, result.issues
    if result.graph is None or not result.graph.facts:
        return None, rejected_semantic_facts, parked, result.issues
    return result.graph, rejected_semantic_facts, parked, result.issues


def _norm_candidates(proposal: QdlGraph) -> dict[str, tuple[Fact, ...]]:
    candidates: dict[str, list[Fact]] = {}
    for fact in proposal.facts:
        if fact.context is not Context.PROPOSAL:
            continue
        if fact.predicate.name != "prevents":
            continue
        norm = fact.args[0] if fact.args else None
        norm_id = atom_value(norm)
        if norm_id is None:
            continue
        candidates.setdefault(norm_id, []).append(fact)
    return {norm_id: tuple(facts) for norm_id, facts in candidates.items()}


def _attacker_may_actions(source: QdlGraph) -> frozenset[str]:
    """Return source-declared actions the campaign attacker may perform."""

    attackers = _campaign_attacker_values(source)
    if not attackers:
        return frozenset()
    actions: set[str] = set()
    for fact in source.facts:
        if (
            fact.context not in _EXECUTABLE_CONTEXTS
            or fact.predicate.name != "may"
            or len(fact.args) != 3
            or normalize_principal(atom_value(fact.args[0])) not in attackers
        ):
            continue
        action = normalize_action(atom_value(fact.args[1]))
        if action is not None:
            actions.add(action)
    return frozenset(actions)


def _campaign_attacker_values(source: QdlGraph) -> frozenset[str]:
    """Resolve attacker principals from explicit graph facts or policy names."""

    explicit = {
        normalized
        for fact in source.facts
        if fact.context in _EXECUTABLE_CONTEXTS
        and fact.predicate.name == "attacker"
        and len(fact.args) == 1
        and (normalized := normalize_principal(atom_value(fact.args[0]))) is not None
    }
    if explicit:
        return frozenset(explicit)

    may_principals = {
        normalized
        for fact in source.facts
        if fact.context in _EXECUTABLE_CONTEXTS
        and fact.predicate.name == "may"
        and len(fact.args) == 3
        and (normalized := normalize_principal(atom_value(fact.args[0]))) is not None
    }
    return frozenset(
        principal for principal in may_principals if principal == "attacker"
    )


def _norm_contradicts_attacker_policy(
    fact: Fact,
    attacker_may_actions: frozenset[str],
) -> bool:
    """Return whether an allowed-effect norm denies expected policy behavior."""

    if (
        fact.context is not Context.PROPOSAL
        or fact.predicate.name != "prevents"
        or len(fact.args) != 2
        or not isinstance(fact.args[1], Struct)
        or fact.args[1].name != "allowed"
        or len(fact.args[1].args) != 1
    ):
        return False
    action = normalize_action(atom_value(fact.args[1].args[0]))
    return action is not None and action in attacker_may_actions


def _parked_policy_norms(
    proposal: QdlGraph,
    declarations: dict[str, Fact],
    attacker_may_actions: frozenset[str],
) -> QdlGraph | None:
    """Park policy-contradicting norms as proposal-context leads."""

    graphs = [
        _parked_policy_norm_graph(fact, declarations)
        for fact in proposal.facts
        if _norm_contradicts_attacker_policy(fact, attacker_may_actions)
    ]
    if not graphs:
        return None
    return merge_graphs(*graphs)


def _parked_policy_norm_graph(
    fact: Fact,
    declarations: dict[str, Fact],
) -> QdlGraph:
    """Keep one contradictory norm and its review lead self-contained."""

    norm, effect = fact.args
    facts: list[Fact] = []
    seen: set[str] = set()

    def add(item: Fact) -> None:
        proposal_fact = item.model_copy(update={"context": Context.PROPOSAL})
        key = canonical_json(proposal_fact)
        if key in seen:
            return
        seen.add(key)
        facts.append(proposal_fact)

    add(fact)
    for term in fact.args:
        for declaration in _declarations_for_term(term, declarations):
            add(declaration)

    digest = hashlib.sha256(canonical_json(fact).encode("utf-8")).hexdigest()[:12]
    lead = Atom(value=f"{LEAD_NORM_PREFIX}policy:{digest}")
    add(_proposal_fact("prevents", (lead, effect)))
    add(_proposal_fact("is", (lead, Atom(value="Norm"))))
    return QdlGraph(facts=tuple(facts))


def _validate_norm(
    fact: Fact,
    *,
    request: ProposalPromotionRequest,
    source_actions: frozenset[str],
    declarations: dict[str, Fact],
    compiler: NormCompiler,
    supported_effects: frozenset[str],
) -> QdlGraph | None:
    accepted_fact = fact.model_copy(update={"context": Context.ACCEPTED})
    try:
        compiled = compiler.compile(accepted_fact)
        view = NormView.from_compiled(compiled)
    except ValueError:
        return None
    if compiled.primitive == "unknown":
        return None
    if (
        view.effect.name in _DIRECT_SUPPORT_EFFECTS
        and canonical_json(view.effect) not in supported_effects
    ):
        return None
    if view.effect.name == "duration":
        calibrated = _calibrated_duration_effect(
            view.effect,
            request.source,
            request.duration_thresholds or {},
        )
        if calibrated is None:
            return None
        accepted_fact = accepted_fact.model_copy(
            update={"args": (fact.args[0], calibrated)}
        )

    if view.action_id is not None:
        actions = {view.action_id} & source_actions
    else:
        effect = view.effect
        actions = _semantic_effect_actions(
            request.source,
            request.proposal,
            effect,
            source_actions,
            request.evidence_fields,
        )
    if not actions:
        return None

    return _self_contained_graph(
        accepted_fact,
        declarations=declarations,
    )


def _calibrated_duration_effect(
    effect: Struct,
    source: QdlGraph,
    duration_thresholds: Mapping[str, int],
) -> Struct | None:
    """Return the runtime-calibrated bound for one proposed duration action."""

    action_id = atom_value(effect.args[0]) if effect.args else None
    if action_id is None:
        return None
    from cloud_dast.qdl.semantic_norm_compiler import duration_effects

    normalized = action_id.removeprefix("action:")
    for baseline_action, threshold in duration_thresholds.items():
        if baseline_action.removeprefix("action:") == normalized:
            return duration(effect.args[0], Atom(value=threshold))
    for candidate in duration_effects(source):
        candidate_id = atom_value(candidate.args[0]) if candidate.args else None
        if (
            candidate_id is not None
            and candidate_id.removeprefix("action:") == normalized
        ):
            return candidate
    return None


def _semantic_effect_actions(
    source: QdlGraph,
    proposal: QdlGraph,
    effect: Struct,
    source_actions: frozenset[str],
    evidence_fields: frozenset[str] | None = None,
) -> frozenset[str]:
    """Bind an effect without an action argument to source-declared actions."""

    effect_key = canonical_json(effect)
    supported = _supported_facts(source, proposal, evidence_fields)
    privileged_fields = _privileged_fields(supported)
    actions: set[str] = set()
    for fact in supported:
        if not fact.args:
            continue
        action_id = atom_value(fact.args[0])
        if action_id not in source_actions:
            continue
        match fact.predicate.name, fact.args, effect.name, effect.args:
            case "causes", (_, Struct() as caused), _, _:
                if canonical_json(caused) == effect_key:
                    actions.add(action_id)
            case "exposes", (_, witness), "has", (_, expected):
                if canonical_json(witness) == canonical_json(expected):
                    actions.add(action_id)
            case "transition", (_, before, after), "transition", (start, end):
                if canonical_json((before, after)) == canonical_json((start, end)):
                    actions.add(action_id)
            case "targets", (_, resource), "changed", (target, field_name) if (
                fact.context in _EXECUTABLE_CONTEXTS
            ):
                if (
                    canonical_json(resource) == canonical_json(target)
                    and (action_id, atom_value(field_name)) in privileged_fields
                ):
                    actions.add(action_id)
    return frozenset(actions)


def _supported_semantic_effects(
    source: QdlGraph,
    proposal: QdlGraph,
    evidence_fields: frozenset[str] | None = None,
) -> frozenset[str]:
    """Return directly proposed effects backed by merged graph semantics."""

    declarations = _declarations(source, proposal)
    graphs = []
    for fact in _supported_facts(source, proposal, evidence_fields):
        graph = _self_contained_graph(fact, declarations=declarations)
        if graph is not None:
            graphs.append(graph)
    if not graphs:
        return frozenset()
    graph = merge_graphs(*graphs)
    from cloud_dast.qdl.semantic_norm_compiler import (
        reached_effects,
        sensitive_exposure_effects,
    )

    effects = (*sensitive_exposure_effects(graph), *reached_effects(graph))
    return frozenset(canonical_json(effect) for effect in effects)


def _privileged_fields(facts: tuple[Fact, ...]) -> frozenset[tuple[str, str]]:
    fields: set[tuple[str, str]] = set()
    for fact in facts:
        if fact.predicate.name != "has" or len(fact.args) != 2:
            continue
        holder, role = fact.args
        if not isinstance(holder, Struct) or holder.name != "input_field":
            continue
        if len(holder.args) != 2 or atom_value(role) != "privileged":
            continue
        action_id = atom_value(holder.args[0])
        field_name = atom_value(holder.args[1])
        if action_id is not None and field_name is not None:
            fields.add((action_id, field_name))
    return frozenset(fields)


def _sink_type_declaration_lacks_provenance(source: QdlGraph, fact: Fact) -> bool:
    """Return whether a proposal introduces an evidence-gated sink type."""

    if len(fact.args) != 2:
        return False
    sink_type = atom_value(fact.args[1])
    if sink_type not in _REACH_SINK_TYPES:
        return False
    return sink_type not in _declared_types(source, fact.args[0])


def _classification_fact_is_anchored(
    fact: Fact,
    source: QdlGraph,
    classification_context: ClassificationPromotionContext | None,
    source_actions: frozenset[str],
) -> bool:
    """Return whether one proposal fact closes a named classification deficit.

    A classification consultation may introduce only the missing value for the
    exact term named by the violated norm, and only from the closed value
    alphabet derived from the catalog pre-image.  Action-shaped holders remain
    action-bound; all other terms must already be declared by the source graph.
    """

    if classification_context is None:
        return False
    term = classification_context.term
    values = classification_context.allowed_values
    if fact.predicate.name not in {"has", "is"} or len(fact.args) != 2:
        return False
    subject, value = fact.args
    if canonical_json(subject) != term:
        return False
    value_name = atom_value(value)
    if not isinstance(value_name, str):
        return False
    if fact.predicate.name == "has":
        if value_name not in values:
            return False
        if isinstance(subject, Struct) and subject.name in {
            "input_field",
            "output_field",
        }:
            action_id = _field_action(subject)
            return action_id is not None and (
                action_id in source_actions
                or f"action:{action_id}" in source_actions
                or action_id.removeprefix("action:") in source_actions
            )
        return bool(_declared_types(source, subject))
    return value_name in values


def _classification_fact_is_trusted(
    fact: Fact,
    source: QdlGraph,
    classification_context: ClassificationPromotionContext | None,
    source_actions: frozenset[str],
    *,
    evidence_fields: frozenset[str] | None = None,
    approved_classifications: frozenset[str] = frozenset(),
) -> bool:
    """Return whether an anchored classification also has trusted provenance."""

    return _classification_fact_is_anchored(
        fact,
        source,
        classification_context,
        source_actions,
    ) and not _classification_lacks_provenance(
        source,
        fact,
        evidence_fields,
        approved_classifications,
    )


def _semantic_fact_is_promotable(
    source: QdlGraph,
    proposal: QdlGraph,
    fact: Fact,
    source_actions: frozenset[str],
    evidence_fields: frozenset[str] | None = None,
    evidence_refs: frozenset[str] = frozenset(),
    approved_classifications: frozenset[str] = frozenset(),
    runtime_evidence_exempt_predicates: frozenset[str] = frozenset(),
) -> bool:
    if (
        fact.predicate.definition.verification_class == "runtime_falsifiable"
        and fact.predicate.name in _RUNTIME_EVIDENCE_REQUIRED_PREDICATES
        and fact.predicate.name not in runtime_evidence_exempt_predicates
        and not evidence_refs
    ):
        return False

    match fact.predicate.name, fact.args:
        case "has", (Struct(name=kind) as holder, Atom(value=str() as role)):
            if (
                role in PROTECTED_CLASSIFICATION_ROLES
                and _classification_lacks_provenance(
                    source, fact, evidence_fields, approved_classifications
                )
            ):
                return False
            if kind in {"input_field", "output_field"}:
                return _field_action(holder) in source_actions
            return kind == "field" and any(
                exposure.predicate.name == "exposes"
                and len(exposure.args) == 2
                and canonical_json(exposure.args[1]) == canonical_json(holder)
                and atom_value(exposure.args[0]) in source_actions
                for exposure in _supported_facts(source, proposal, evidence_fields)
            )
        case (("exposes" | "transition"), (action, *_)):
            return atom_value(action) in source_actions
        case "causes", (action, Struct(name=kind)):
            return (
                atom_value(action) in source_actions
                and kind in _CAUSAL_EFFECT_CONSTRUCTORS
                and not (kind in _OWNERSHIP_EFFECT_CONSTRUCTORS and not evidence_refs)
            )
        case (("requires" | "targets"), (action, _)):
            return atom_value(action) in source_actions
        case "refers_to", (holder, _):
            return _field_action(holder) in source_actions
        case "reaches", (holder, sink):
            return (
                _field_action(holder) in source_actions
                and _source_declares_field(source, holder)
                and bool(_declared_types(source, sink) & _REACH_SINK_TYPES)
            )
        case "coupled", (left, right, operator):
            return (
                _field_action(left) in source_actions
                and _field_action(right) in source_actions
                and atom_value(operator) in COUPLED_OPERATORS
            )
        case "format", (holder, format_name):
            return (
                _field_action(holder) in source_actions
                and atom_value(format_name) is not None
            )
        case "constraint", (holder, operator, Atom()):
            return (
                _field_action(holder) in source_actions
                and atom_value(operator) in COUPLED_OPERATORS
            )
        case "dialect", (sink, dialect):
            return (
                bool(_declared_types(source, sink) & _REACH_SINK_TYPES)
                and atom_value(dialect) is not None
            )
    return False


def _field_action(term: object) -> str | None:
    if not isinstance(term, Struct) or term.name not in {"input_field", "output_field"}:
        return None
    if len(term.args) != 2:
        return None
    action_id = atom_value(term.args[0])
    return action_id if isinstance(action_id, str) else None


def _source_declares_field(source: QdlGraph, term: object) -> bool:
    """Require the exact carrier and a source type matching its field kind."""

    if not isinstance(term, Struct):
        return False
    field_type = {"input_field": "InputField", "output_field": "OutputField"}.get(
        term.name
    )
    return field_type is not None and bool(
        _declared_types(source, term) & {"Field", field_type}
    )


def _declared_types(source: QdlGraph, term: object) -> frozenset[str]:
    """Return all types declared for the exact term by executable source facts."""

    term_key = canonical_json(term)
    types: set[str] = set()
    for fact in source.facts:
        if fact.context not in _EXECUTABLE_CONTEXTS:
            continue
        if fact.predicate.name != "is" or len(fact.args) != 2:
            continue
        if canonical_json(fact.args[0]) == term_key:
            type_name = atom_value(fact.args[1])
            if isinstance(type_name, str):
                types.add(type_name)
    return frozenset(types)


def _supported_facts(
    source: QdlGraph,
    proposal: QdlGraph,
    evidence_fields: frozenset[str] | None = None,
) -> tuple[Fact, ...]:
    return (
        *(fact for fact in source.facts if fact.context in _EXECUTABLE_CONTEXTS),
        *(
            fact
            for fact in proposal.facts
            if fact.context is Context.PROPOSAL
            and _proposal_fact_is_supported(source, fact, evidence_fields)
        ),
    )


def _proposal_fact_is_supported(
    source: QdlGraph,
    fact: Fact,
    evidence_fields: frozenset[str] | None = None,
) -> bool:
    """Keep proposal semantics that cannot introduce source classifications."""

    if fact.predicate.name == "reaches":
        if len(fact.args) != 2:
            return False
        action = _field_action(fact.args[0])
        return (
            action is not None
            and action
            in source.declared_identifiers("Action", contexts=_EXECUTABLE_CONTEXTS)
            and _source_declares_field(source, fact.args[0])
            and bool(_declared_types(source, fact.args[1]) & _REACH_SINK_TYPES)
        )
    if fact.predicate.name != "has" or len(fact.args) != 2:
        return True
    holder, role = fact.args
    role_name = atom_value(role)
    if (
        not isinstance(role_name, str)
        or role_name not in PROTECTED_CLASSIFICATION_ROLES
    ):
        return True
    return not _classification_lacks_provenance(source, fact, evidence_fields)


def _classification_lacks_provenance(
    source: QdlGraph,
    fact: Fact,
    evidence_fields: frozenset[str] | None,
    approved_classifications: frozenset[str] = frozenset(),
) -> bool:
    """Return whether a classification has no trusted origin.

    Exact classification anchors are intentionally absent from this helper:
    they constrain the alphabet, but never establish provenance.
    """

    if len(fact.args) != 2:
        return False
    if fact.content_hash in approved_classifications:
        return False
    holder, role = fact.args
    role_name = atom_value(role)
    if fact.predicate.name == "is":
        if not isinstance(role_name, str) or role_name not in _REACH_SINK_TYPES:
            return False
        return role_name not in _declared_types(source, holder)
    if fact.predicate.name != "has":
        return False
    if (
        not isinstance(role_name, str)
        or role_name not in PROTECTED_CLASSIFICATION_ROLES
    ):
        return False
    return not _source_declares_role(
        source, holder, role_name
    ) and not _evidence_grounded_role(holder, evidence_fields)


def _unproven_classifications(
    source: QdlGraph,
    proposal: QdlGraph,
    evidence_fields: frozenset[str] | None,
) -> list[Fact]:
    """Return every protected-role classification without a trusted origin."""

    return [
        fact
        for fact in proposal.facts
        if fact.context is Context.PROPOSAL
        and _classification_lacks_provenance(source, fact, evidence_fields)
    ]


def _lead_norm_bundles(
    source: QdlGraph,
    proposal: QdlGraph,
    parked: list[Fact],
    declarations: dict[str, Fact],
) -> dict[str, tuple[Fact, ...]]:
    """Build one proposal-context norm suspicion per parked classification.

    The deterministic policy may neither promote nor silently discard a
    protected role without provenance.  When the merged graph exposes the
    classified witness, the parked hypothesis receives the possession norm it
    would enable if an operator later accepted the classification.  Lead
    norms stay in the proposal context, so no planner can execute them.
    """

    if not parked:
        return {}
    from cloud_dast.qdl.semantic_norm_compiler import sensitive_exposure_effects

    try:
        exposed = {
            canonical_json(effect.args[1]): effect
            for effect in sensitive_exposure_effects(merge_graphs(source, proposal))
            if effect.name == "has" and len(effect.args) == 2
        }
    except ValueError as error:
        logger.warning("lead_norm_derivation_failed reason=%.200s", error)
        return {}

    bundles: dict[str, tuple[Fact, ...]] = {}
    for fact in parked:
        holder, role = fact.args
        role_name = atom_value(role)
        effect = exposed.get(canonical_json(holder))
        if role_name is None or effect is None:
            continue
        digest = hashlib.sha256(
            canonical_json((holder, role)).encode("utf-8")
        ).hexdigest()[:12]
        norm = Atom(value=f"{LEAD_NORM_PREFIX}{role_name}:{digest}")
        bundles[canonical_json(fact)] = (
            _proposal_fact("prevents", (norm, effect)),
            _proposal_fact("is", (norm, Atom(value="Norm"))),
            *_lead_effect_declarations(effect, declarations),
        )
    return bundles


def _lead_effect_declarations(
    effect: Struct,
    declarations: dict[str, Fact],
) -> tuple[Fact, ...]:
    """Declare the principal a lead possession effect references."""

    principal = effect.args[0]
    for declaration in _declarations_for_term(principal, declarations):
        return (declaration.model_copy(update={"context": Context.PROPOSAL}),)
    return (_proposal_fact("is", (principal, Atom(value="Principal"))),)


def _proposal_fact(predicate: str, args: tuple[Atom | Struct, ...]) -> Fact:
    return Fact(
        context=Context.PROPOSAL,
        predicate=Predicate.from_name(predicate),
        args=args,
    )


def _parked_classifications_graph(
    parked: list[Fact],
    declarations: dict[str, Fact],
    leads: Mapping[str, tuple[Fact, ...]] | None = None,
) -> QdlGraph | None:
    """Keep rejected classifications reviewable as a proposal-context graph."""

    graphs: list[QdlGraph] = []
    for fact in parked:
        facts: list[Fact] = []
        seen: set[str] = set()
        if fact.predicate.name != "is":
            for term in fact.args:
                for declaration in _declarations_for_term(term, declarations):
                    proposal_declaration = declaration.model_copy(
                        update={"context": Context.PROPOSAL}
                    )
                    key = canonical_json(proposal_declaration)
                    if key in seen:
                        continue
                    seen.add(key)
                    facts.append(proposal_declaration)
        facts.append(fact)
        for lead in (leads or {}).get(canonical_json(fact), ()):
            key = canonical_json(lead)
            if key in seen:
                continue
            seen.add(key)
            facts.append(lead)
        try:
            graphs.append(QdlGraph(facts=tuple(facts)))
        except ValueError:
            continue
    if not graphs:
        return None
    return merge_graphs(*graphs)


def _evidence_grounded_role(
    holder: object,
    evidence_fields: frozenset[str] | None,
) -> bool:
    """Return whether an observed response field carries the classified role."""

    if not evidence_fields or not isinstance(holder, Struct):
        return False
    if holder.name not in {"field", "output_field"} or len(holder.args) != 2:
        return False
    field_name = atom_value(holder.args[1])
    return field_name is not None and field_name in evidence_fields


def _source_declares_role(
    source: QdlGraph,
    holder: object,
    role_name: str,
) -> bool:
    holder_key = canonical_json(holder)
    return any(
        fact.context in _EXECUTABLE_CONTEXTS
        and fact.predicate.name == "has"
        and len(fact.args) == 2
        and canonical_json(fact.args[0]) == holder_key
        and atom_value(fact.args[1]) == role_name
        for fact in source.facts
    )


def _declarations(
    source: QdlGraph,
    proposal: QdlGraph,
    *,
    include_untrusted: bool = False,
) -> dict[str, Fact]:
    """Select trusted supporting declarations, retaining raw ones only for review.

    Dependency closure is a promotion boundary too: a model declaration cannot
    establish request schema or a sink classification merely by supporting an
    otherwise promotable fact. Response declarations retain the existing
    response/evidence filtering policy.
    """

    result: dict[str, Fact] = dict(source.declarations_for(_EXECUTABLE_CONTEXTS))
    for fact in proposal.facts:
        if fact.context is not Context.PROPOSAL:
            continue
        if fact.predicate.name != "is" or not fact.args:
            continue
        if not include_untrusted:
            subject = fact.args[0]
            if isinstance(subject, Struct) and subject.name == "input_field":
                continue
            if _sink_type_declaration_lacks_provenance(source, fact):
                continue
        result.setdefault(canonical_json(fact.args[0]), fact)
    return result


def _self_contained_graph(
    fact: Fact,
    *,
    declarations: dict[str, Fact],
) -> QdlGraph | None:
    facts: list[Fact] = []
    seen: set[str] = set()
    for term in fact.args:
        for declaration in _declarations_for_term(term, declarations):
            key = canonical_json(declaration)
            if key in seen:
                continue
            seen.add(key)
            facts.append(declaration.model_copy(update={"context": Context.ACCEPTED}))
    facts.append(fact)
    try:
        return QdlGraph(facts=tuple(facts))
    except ValueError:
        return None


def _declarations_for_term(term: object, declarations: dict[str, Fact]):
    if isinstance(term, Atom):
        declaration = declarations.get(canonical_json(term))
        return (declaration,) if declaration is not None else ()
    if not isinstance(term, Struct):
        return ()
    result = []
    declaration = declarations.get(canonical_json(term))
    if declaration is not None:
        result.append(declaration)
    for argument in term.args:
        result.extend(_declarations_for_term(argument, declarations))
    return tuple(result)


__all__ = [
    "LeadDescriptor",
    "PayloadCorpusPromotionResult",
    "ProposalPromotionRequest",
    "ProposalPromotionResult",
    "lead_descriptor",
    "promote_payload_corpus_proposal",
    "promote_proposal",
    "park_proposal",
    "field_is_bound",
]
