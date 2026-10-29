"""Concrete LLM consultation lifecycle.

This package owns prompt dispatch, model transport, structured wire schemas,
validation orchestration, provenance completion, and payload-seed
enrichment.  The core package supplies only the request/result contracts.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from pydantic import ValidationError

from cloud_dast.consultation import (
    CONSULTATION_INSTRUCTIONS,
    CONSULTATION_PREDICATES,
    ConsultationKind,
    ConsultationOutcome,
    ConsultationProvenance,
    ConsultationRequest,
    ConsultationTelemetry,
    SeedEnrichmentConsultationOutcome,
    current_consultation_telemetry,
    ownership_effect_is_proposable,
)
from cloud_dast.contracts.payload_proposals import (
    SeedEnrichmentModelWireOutput,
)
from cloud_dast.contracts.proposals import (
    FormalModelOutputValidator,
    FormalModelWireOutput,
    FormalUncertainty,
)
from cloud_dast.model.events import (
    ComponentInvoked,
    ComponentLifecycleEvent,
    ComponentOutput,
    ComponentSkipped,
    DownstreamDecision,
)
from cloud_dast.ports import ModelClient, ModelRequest
from cloud_dast.qdl.graph import (
    CAUSAL_EFFECT_CONSTRUCTORS,
    Atom,
    Fact,
    QdlGraph,
    Struct,
)

logger = logging.getLogger("cloud_dast_llm.consultation")
_ALTERNATIVE_EFFECT_CONSTRUCTORS = frozenset(CAUSAL_EFFECT_CONSTRUCTORS)


class ConsultationDispatcher:
    """Deterministic dispatcher for deficit-driven specialist calls.

    The dispatcher is the only component that talks to the model for a
    consultation.  It resolves the specialist prompt from the closed kind
    registry, enforces delegation depth, passes the shared model budget to
    the adapter, validates its structured response through the formal
    validator, narrows it to the
    kind's predicate whitelist, and returns either a proposal or an
    UNSCOREABLE outcome — never a verdict, never a side effect.
    """

    def __init__(
        self,
        client: ModelClient,
        *,
        validator: FormalModelOutputValidator | None = None,
    ) -> None:
        self._client = client
        self._validator = validator or FormalModelOutputValidator()

    def dispatch(
        self,
        request: ConsultationRequest,
        *,
        telemetry: ConsultationTelemetry | None = None,
    ) -> ConsultationOutcome:
        """Run one typed consultation and record its full provenance."""

        # The workflow binds reactive work-item telemetry through the
        # context (the grounding adapter owns request construction), so the
        # contextvar is the fallback when no explicit binding is passed.
        telemetry = telemetry or current_consultation_telemetry()
        if request.kind == "seed_enrichment":
            raise TypeError(
                "seed enrichment uses dispatch_seed_enrichment; the formal "
                "QDL dispatcher cannot validate payload-corpus data"
            )
        instruction = CONSULTATION_INSTRUCTIONS.get(request.kind)
        if instruction is None:
            return self._reject(request, "", "unknown consultation kind", telemetry)
        if not request.deficit_id:
            return self._reject(request, instruction, "missing deficit id", telemetry)
        if request.depth < 0 or request.depth > request.budget.max_depth:
            return self._reject(
                request,
                instruction,
                "delegation depth exceeded",
                telemetry,
            )
        if not request.slice.facts and not request.slice.rules:
            return self._reject(request, instruction, "empty graph slice", telemetry)

        # The slice is always the request's own slice: request context may
        # add bounded data, but the graph the model sees is exactly the
        # graph whose hash is recorded in provenance.
        context = dict(request.context)
        context["graph"] = request.slice.model_dump(mode="json")
        response_schema = json.dumps(
            FormalModelWireOutput.model_json_schema(), ensure_ascii=False
        )
        task = f"formal_grounding_{request.kind}"
        work_item_id, deficit_ids = _work_item_provenance(request, telemetry)
        provenance = ConsultationProvenance(
            deficit_id=request.deficit_id,
            kind=request.kind,
            model_version="",
            prompt_hash=_prompt_hash(task, instruction, context, response_schema),
            graph_slice_hash=request.slice.content_hash,
            input_tokens=0,
            cached_input_tokens=0,
            output_tokens=0,
            latency_ms=0.0,
            depth=request.depth,
            observation_ids=request.observation_ids,
            work_item_id=work_item_id,
            deficit_ids=deficit_ids,
        )
        self._publish_component(
            ComponentInvoked(
                component=_component_name(request),
                input_digest=provenance.prompt_hash,
                input_completeness=_input_completeness(request),
                invocation_id=_invocation_id(request, telemetry),
                correlation_id=_correlation_id(request, telemetry),
            ),
            telemetry,
        )
        logger.info(
            "consultation_dispatched kind=%s deficit=%s action=%s "
            "slice_facts=%d depth=%d",
            request.kind,
            request.deficit_id,
            request.action,
            len(request.slice.facts),
            request.depth,
        )
        model_request = ModelRequest(
            task=task,
            instruction=instruction,
            context=context,
            budget=request.budget,
        )
        started = time.perf_counter()
        try:
            response = self._client.complete(
                model_request,
                response_type=FormalModelWireOutput,
            )
        except Exception:
            self._publish_component(
                ComponentSkipped(
                    component=_component_name(request),
                    reason="model_exception",
                    input_digest=provenance.prompt_hash,
                    input_completeness=_input_completeness(request),
                    invocation_id=_invocation_id(request, telemetry),
                    correlation_id=_correlation_id(request, telemetry),
                ),
                telemetry,
            )
            raise
        latency_ms = (time.perf_counter() - started) * 1000.0
        provenance = replace(
            provenance,
            model_version=response.model_id,
            input_tokens=response.input_tokens,
            cached_input_tokens=response.cached_input_tokens,
            output_tokens=response.output_tokens,
            latency_ms=latency_ms,
        )

        if response.finish_reason == "token_budget_exceeded":
            return self._publish_output(
                ConsultationOutcome(
                    "unscoreable", None, provenance, reason="token budget exceeded"
                ),
                request,
                telemetry,
            )
        payload = (
            response.structured if isinstance(response.structured, Mapping) else {}
        )
        if not payload.get("facts") and not payload.get("rules"):
            logger.warning(
                "consultation_empty kind=%s deficit=%s raw_response=%.2000s",
                request.kind,
                request.deficit_id,
                response.content,
            )
            return self._publish_output(
                ConsultationOutcome(
                    "unscoreable",
                    None,
                    provenance,
                    reason="empty model proposal",
                    uncertainties=_uncertainty_items(payload),
                ),
                request,
                telemetry,
            )
        uncertainties = _uncertainty_items(payload)
        rule_grammar_issues = (
            _alternatives_rule_grammar_issues(payload)
            if request.kind == "alternatives"
            else 0
        )
        if rule_grammar_issues:
            logger.warning(
                "consultation_grammar_rejected kind=alternatives deficit=%s rules=%d",
                request.deficit_id,
                rule_grammar_issues,
            )
        result = self._validator.salvage(
            payload,
            background=request.background
            if request.background is not None
            else request.slice,
        )
        proposal = result.graph
        issue_count = len(result.issues) + rule_grammar_issues
        if proposal is not None:
            proposal, dropped = _filter_predicates(
                proposal,
                CONSULTATION_PREDICATES[request.kind],
                kind=request.kind,
                has_evidence=_request_has_evidence(request),
            )
            issue_count += dropped
        if proposal is None or not proposal.facts:
            logger.warning(
                "consultation_invalid kind=%s deficit=%s issues=%d "
                "raw_response=%.2000s",
                request.kind,
                request.deficit_id,
                issue_count,
                response.content,
            )
            return self._publish_output(
                ConsultationOutcome(
                    "unscoreable",
                    None,
                    provenance,
                    reason="proposal failed schema validation",
                    issue_count=issue_count,
                    uncertainties=uncertainties,
                ),
                request,
                telemetry,
            )
        logger.info(
            "consultation_completed kind=%s deficit=%s facts=%d "
            "latency_ms=%.1f input_tokens=%d output_tokens=%d",
            request.kind,
            request.deficit_id,
            len(proposal.facts),
            latency_ms,
            response.input_tokens,
            response.output_tokens,
        )
        return self._publish_output(
            ConsultationOutcome(
                "proposal",
                proposal,
                provenance,
                issue_count=issue_count,
                uncertainties=uncertainties,
            ),
            request,
            telemetry,
        )

    def _reject(
        self,
        request: ConsultationRequest,
        instruction: str,
        reason: str,
        telemetry: ConsultationTelemetry | None,
    ) -> ConsultationOutcome:
        """Publish one pre-model skip and return its provenance-bearing result."""

        self._publish_component(
            ComponentSkipped(
                component=_component_name(request),
                reason=reason,
                input_digest=_request_digest(request),
                input_completeness=_input_completeness(request),
                invocation_id=_invocation_id(request, telemetry),
                correlation_id=_correlation_id(request, telemetry),
            ),
            telemetry,
        )
        return rejected_outcome(request, instruction, reason)

    def _publish_output(
        self,
        outcome: ConsultationOutcome,
        request: ConsultationRequest,
        telemetry: ConsultationTelemetry | None,
    ) -> ConsultationOutcome:
        """Publish one consultation output and its validator decision."""

        self._publish_component(
            ComponentOutput(
                component=_component_name(request),
                summary=_output_summary(outcome),
                invocation_id=_invocation_id(request, telemetry),
                correlation_id=_correlation_id(request, telemetry),
            ),
            telemetry,
        )
        self._publish_component(
            DownstreamDecision(
                component=_component_name(request),
                consumed=not outcome.unscoreable,
                by="formal_validator",
                outcome=outcome.reason or outcome.status,
                invocation_id=_invocation_id(request, telemetry),
                correlation_id=_correlation_id(request, telemetry),
            ),
            telemetry,
        )
        return outcome

    def _publish_component(
        self,
        event: ComponentLifecycleEvent,
        telemetry: ConsultationTelemetry | None,
    ) -> None:
        """Publish one scoped component event through the existing bus."""

        if telemetry is None:
            return
        telemetry.publisher.publish(
            telemetry.scope.apply(event) if telemetry.scope is not None else event
        )

    def dispatch_seed_enrichment(
        self,
        request: ConsultationRequest,
    ) -> SeedEnrichmentConsultationOutcome:
        """Run the closed payload-data consultation at an entropy point."""

        instruction = CONSULTATION_INSTRUCTIONS["seed_enrichment"]
        if request.kind != "seed_enrichment":
            return self._seed_rejection(
                request,
                instruction,
                "request is not a seed-enrichment consultation",
            )
        if not request.deficit_id:
            return self._seed_rejection(request, instruction, "missing deficit id")
        if request.depth < 0 or request.depth > request.budget.max_depth:
            return self._seed_rejection(
                request,
                instruction,
                "delegation depth exceeded",
            )
        if not request.slice.facts and not request.slice.rules:
            return self._seed_rejection(
                request,
                instruction,
                "empty graph slice",
            )
        if not isinstance(request.context.get("saturated_history"), Mapping):
            return self._seed_rejection(
                request,
                instruction,
                "missing saturated history",
            )

        context = dict(request.context)
        context["graph"] = request.slice.model_dump(mode="json")
        response_schema = json.dumps(
            SeedEnrichmentModelWireOutput.model_json_schema(),
            ensure_ascii=False,
        )
        task = "payload_seed_enrichment"
        provenance = ConsultationProvenance(
            deficit_id=request.deficit_id,
            kind=request.kind,
            model_version="",
            prompt_hash=_prompt_hash(task, instruction, context, response_schema),
            graph_slice_hash=request.slice.content_hash,
            input_tokens=0,
            cached_input_tokens=0,
            output_tokens=0,
            latency_ms=0.0,
            depth=request.depth,
            observation_ids=request.observation_ids,
        )
        logger.info(
            "seed_enrichment_dispatched deficit=%s action=%s slice_facts=%d",
            request.deficit_id,
            request.action,
            len(request.slice.facts),
        )
        model_request = ModelRequest(
            task=task,
            instruction=instruction,
            context=context,
            budget=request.budget,
        )
        started = time.perf_counter()
        try:
            response = self._client.complete(
                model_request,
                response_type=SeedEnrichmentModelWireOutput,
            )
        except Exception as error:
            return SeedEnrichmentConsultationOutcome(
                "unscoreable",
                None,
                provenance,
                reason=f"model transport failed: {error}",
            )
        latency_ms = (time.perf_counter() - started) * 1000.0
        provenance = replace(
            provenance,
            model_version=response.model_id,
            input_tokens=response.input_tokens,
            cached_input_tokens=response.cached_input_tokens,
            output_tokens=response.output_tokens,
            latency_ms=latency_ms,
        )
        if response.finish_reason == "token_budget_exceeded":
            return SeedEnrichmentConsultationOutcome(
                "unscoreable", None, provenance, reason="token budget exceeded"
            )
        try:
            payload = SeedEnrichmentModelWireOutput.model_validate(response.structured)
        except ValidationError as error:
            return SeedEnrichmentConsultationOutcome(
                "unscoreable",
                None,
                provenance,
                reason="payload proposal failed schema validation",
                issue_count=error.error_count(),
            )
        uncertainties = tuple(
            FormalUncertainty.model_validate(item.model_dump())
            for item in payload.uncertainties
        )
        return SeedEnrichmentConsultationOutcome(
            "proposal",
            payload.to_delta(),
            provenance,
            uncertainties=uncertainties,
        )

    def _seed_rejection(
        self,
        request: ConsultationRequest,
        instruction: str,
        reason: str,
    ) -> SeedEnrichmentConsultationOutcome:
        context = dict(request.context)
        context["graph"] = request.slice.model_dump(mode="json")
        response_schema = json.dumps(
            SeedEnrichmentModelWireOutput.model_json_schema(),
            ensure_ascii=False,
        )
        return SeedEnrichmentConsultationOutcome(
            "unscoreable",
            None,
            ConsultationProvenance(
                deficit_id=request.deficit_id,
                kind="seed_enrichment",
                model_version="",
                prompt_hash=_prompt_hash(
                    "payload_seed_enrichment",
                    instruction,
                    context,
                    response_schema,
                ),
                graph_slice_hash=request.slice.content_hash,
                input_tokens=0,
                cached_input_tokens=0,
                output_tokens=0,
                latency_ms=0.0,
                depth=request.depth,
                observation_ids=request.observation_ids,
            ),
            reason=reason,
        )


def rejected_outcome(
    request: ConsultationRequest,
    instruction: str,
    reason: str,
) -> ConsultationOutcome:
    """Build an UNSCOREABLE outcome for a consultation that never ran.

    Rejections still carry provenance: the deficit id, the deterministic
    prompt hash (when the kind is known), and the graph-slice hash are
    recorded even though no model call was made.
    """

    context = dict(request.context)
    context["graph"] = request.slice.model_dump(mode="json")
    prompt_hash = (
        _prompt_hash(
            f"formal_grounding_{request.kind}",
            instruction,
            context,
            json.dumps(FormalModelWireOutput.model_json_schema(), ensure_ascii=False),
        )
        if instruction
        else ""
    )
    return ConsultationOutcome(
        "unscoreable",
        None,
        ConsultationProvenance(
            deficit_id=request.deficit_id,
            kind=request.kind,
            model_version="",
            prompt_hash=prompt_hash,
            graph_slice_hash=request.slice.content_hash,
            input_tokens=0,
            cached_input_tokens=0,
            output_tokens=0,
            latency_ms=0.0,
            depth=request.depth,
            observation_ids=request.observation_ids,
        ),
        reason=reason,
    )


def _component_name(request: ConsultationRequest) -> str:
    return f"consultation:{request.kind}"


def _work_item_provenance(
    request: ConsultationRequest,
    telemetry: ConsultationTelemetry | None,
) -> tuple[str, tuple[str, ...]]:
    """Return the S30 work-item identity bound to this consultation.

    Reactive work items bind their identity through the telemetry context
    (the grounding adapter owns request construction), so the
    workflow layer can coalesce many deficits into one call while the
    provenance still names every affected deficit.  Calls without a bound
    work item keep the request's own deficit id for traceability.
    """

    bound = telemetry or current_consultation_telemetry()
    if bound is None:
        return "", (request.deficit_id,)
    return bound.work_item_id, tuple(bound.deficit_ids) or (request.deficit_id,)


def _invocation_id(
    request: ConsultationRequest,
    telemetry: ConsultationTelemetry | None,
) -> str:
    deficit_id = (telemetry.deficit_id if telemetry is not None else "") or (
        request.deficit_id
    )
    return f"consultation:{deficit_id}:{request.depth}"


def _correlation_id(
    request: ConsultationRequest,
    telemetry: ConsultationTelemetry | None,
) -> str:
    if telemetry is not None and telemetry.deficit_id:
        return telemetry.deficit_id
    return request.deficit_id


def _input_completeness(request: ConsultationRequest) -> dict[str, int]:
    background = request.background if request.background is not None else request.slice
    return {
        "slice_facts": len(request.slice.facts),
        "slice_rules": len(request.slice.rules),
        "context_keys": len(request.context),
        "background_facts": len(background.facts),
        "observation_ids": len(request.observation_ids),
    }


def _request_digest(request: ConsultationRequest) -> str:
    payload = json.dumps(
        {
            "kind": request.kind,
            "deficit_id": request.deficit_id,
            "action": request.action,
            "slice_hash": request.slice.content_hash,
            "observation_ids": request.observation_ids,
            "context": dict(request.context),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _output_summary(outcome: ConsultationOutcome) -> dict[str, int]:
    proposal = outcome.proposal
    facts = tuple(proposal.facts) if proposal is not None else ()
    return {
        "candidates_produced": 1,
        "candidates_survived_prefilter": 1,
        "candidates_survived_guardrail": int(bool(facts)),
        "scored": 1,
        "witnesses": sum(fact.predicate.name == "exposes" for fact in facts),
        "proposals": int(bool(facts)),
        "facts": len(facts),
        "issues": outcome.issue_count,
        "uncertainties": len(outcome.uncertainties),
    }


def _prompt_hash(
    task: str,
    instruction: str,
    context: Mapping[str, Any],
    response_schema: str,
) -> str:
    """Hash the deterministic prompt payload of one consultation."""

    payload = json.dumps(
        {
            "task": task,
            "instruction": instruction,
            "context": context,
            "response_schema": response_schema,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _filter_predicates(
    graph: QdlGraph,
    allowed: frozenset[str],
    *,
    kind: ConsultationKind,
    has_evidence: bool,
) -> tuple[QdlGraph | None, int]:
    """Keep only the predicates owned by one consultation kind."""

    facts: list[Fact] = []
    dropped_by_predicate: dict[str, int] = {}
    dropped = 0
    for fact in graph.facts:
        if fact.predicate.name in allowed and _fact_is_kind_allowed(
            kind, fact, has_evidence=has_evidence
        ):
            facts.append(fact)
        else:
            predicate = fact.predicate.name
            dropped_by_predicate[predicate] = dropped_by_predicate.get(predicate, 0) + 1
            dropped += 1
    if dropped:
        predicates = ",".join(
            f"{predicate}={count}"
            for predicate, count in sorted(dropped_by_predicate.items())
        )
        logger.warning(
            "consultation_predicate_rejected kind=%s predicates=%s dropped=%d",
            kind,
            predicates,
            dropped,
        )
    if not facts:
        return None, dropped
    return QdlGraph(facts=facts, rules=graph.rules), dropped


def _fact_is_kind_allowed(
    kind: ConsultationKind,
    fact: Fact,
    *,
    has_evidence: bool,
) -> bool:
    """Apply predicate-shape limits owned by one consultation kind."""

    if kind == "alternatives" and not _alternatives_fact_is_allowed(fact):
        return False
    if fact.predicate.name != "causes":
        return True
    effect = fact.args[1] if len(fact.args) == 2 else None
    effect_name = effect.name if isinstance(effect, Struct) else None
    return ownership_effect_is_proposable(
        kind,
        effect_name,
        has_evidence=has_evidence,
    )


def _alternatives_fact_is_allowed(fact: Fact) -> bool:
    """Enforce the closed effect alphabet of one alternatives fact.

    The alternatives grammar admits effect witnesses only as struct
    constructors from the closed causal-effect alphabet.  A bare atom
    ``requires(Action, "read")`` — or an ``is`` declaration typing that atom
    as ``"Effect"`` — is an invented constructor name and is rejected before
    promotion, whatever the model calls it.
    """

    predicate = fact.predicate.name
    if predicate in {"causes", "requires"}:
        effect = fact.args[1] if len(fact.args) == 2 else None
        return (
            isinstance(effect, Struct)
            and effect.name in _ALTERNATIVE_EFFECT_CONSTRUCTORS
        )
    if predicate == "is" and len(fact.args) == 2:
        entity, declared_type = fact.args
        return not (
            isinstance(entity, Atom)
            and isinstance(declared_type, Atom)
            and declared_type.value == "Effect"
        )
    return True


def _alternatives_rule_grammar_issues(payload: Mapping[str, Any]) -> int:
    """Count rule entries outside the formal alternatives grammar.

    The alternatives kind asks for facts only.  Rule entries that are not
    mapping-shaped formal rules — natural-language strings above all — are
    rejected with one issue each instead of being silently discarded.
    """

    rules = payload.get("rules")
    if not isinstance(rules, list):
        return 0
    return sum(1 for rule in rules if not _is_rule_entry(rule))


def _is_rule_entry(rule: object) -> bool:
    """Return whether one rule entry normalizes into a formal QDL rule."""

    if not isinstance(rule, Mapping):
        return False
    body = rule.get("body")
    head = rule.get("head")
    if not isinstance(body, (list, tuple)) or not isinstance(head, (list, tuple)):
        return False
    literals = (*body, *head)
    if not literals:
        return False
    return all(_is_rule_literal(literal) for literal in literals)


def _is_rule_literal(literal: object) -> bool:
    if not isinstance(literal, Mapping):
        return False
    predicate = literal.get("predicate")
    if isinstance(predicate, Mapping):
        predicate = predicate.get("name")
    return isinstance(predicate, str) and bool(predicate.strip())


def _request_has_evidence(request: ConsultationRequest) -> bool:
    """Return whether one consultation carries bounded live evidence."""

    return bool(request.observation_ids) or isinstance(
        request.context.get("evidence"), Mapping
    )


def _uncertainty_items(
    payload: Mapping[str, Any],
) -> tuple[FormalUncertainty, ...]:
    """Decode self-reported model uncertainties without failing the call."""

    raw = payload.get("uncertainties") or ()
    if not isinstance(raw, (list, tuple)):
        return ()
    items: list[FormalUncertainty] = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            continue
        try:
            items.append(FormalUncertainty.model_validate(dict(entry)))
        except ValidationError:
            continue
    return tuple(items)


__all__ = ["ConsultationDispatcher", "rejected_outcome"]
