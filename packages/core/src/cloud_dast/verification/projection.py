"""Project runtime observations into QDL aggregates and grounded typed evidence.

Without trusted graph context the projector is syntax-only: it stores the raw response summary
and generic outcome as evidence.  It never interprets a protocol status as a
security verdict, and response field names never imply control-state
semantics.  A transition is projected only from the trace's explicit
``resource_state_before`` and ``resource_state_after`` channels; any other
state-like response shape remains an ordinary field plus an explicit unmapped
state deficit.

The default projection contains ``observed_*`` aggregates keyed by semantic
content alone: no observation id appears in fact arguments.  Projecting the
same observation twice—or two different observations carrying the same
meaning—therefore yields the same content-addressed fact, and merging the
per-observation projections (as the content-addressed repository does)
collapses the runtime graph to the set of distinct observed meanings.
Per-observation identity is not lost: the append-only projection layer keeps
one source per observation (``observation:<id>`` with check/scenario/method
provenance), the JSONL event log keeps the full stream, and refuting an
aggregate is expressed with the existing ``supersedes`` predicate rather than
by retracting history.
With bounded trusted graph context, safe declared typed output values are
retained independently of causal effects. Declared effects may additionally
be evidenced by those values or explicit trace channels. These
runtime is/has/part/evidence facts retain scoped instance identity and source
observations; they never introduce executable causes or security verdicts.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Sequence

import clingo
from pydantic import ValidationError

from cloud_dast.couplings import normalise_action
from cloud_dast.model import (
    AccessOutcome,
    Check,
    JsonValue,
    Observation,
    TraceStep,
)
from cloud_dast.ports import EvidenceChannel, EvidenceEvent
from cloud_dast.qdl.asp import decode_term, encode_atom, encode_term
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.field_roles import (
    FieldRolePolicy,
    declared_output_refs,
    resolve_field_roles,
)
from cloud_dast.qdl.graph import (
    CAUSAL_EFFECT_CONSTRUCTORS,
    STRUCT_SCHEMAS,
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    Struct,
    canonical_json,
    collect_references,
    source,
)
from cloud_dast.qdl.graph_ops import atom_value, merge_graphs
from cloud_dast.verification.evidence_facts import (
    has_observation,
    observation_source_fact,
)


class ObservationProjector:
    """Convert one runtime observation into idempotent QDL aggregates."""

    def __init__(self, oob_events: EvidenceChannel | None = None) -> None:
        self._oob_events = oob_events

    def project(
        self,
        observation: Observation,
        method_id: str,
        *,
        oob_events: Sequence[EvidenceEvent] | None = None,
        graph: QdlGraph | None = None,
        identities: tuple[str, ...] | None = None,
        scope: str | None = None,
        observed_at: float | None = None,
        check: Check | None = None,
    ) -> QdlGraph:
        action = Atom(value=f"action:{method_id}")
        facts: dict[str, Fact] = {}
        _add_fact(
            facts,
            _fact("is", (action, Atom(value="Action"))),
        )
        _add_fact(
            facts,
            _fact(
                "observed_response_status",
                (action, Atom(value=observation.response_summary)),
            ),
        )
        _add_fact(
            facts,
            _fact(
                "observed_outcome",
                (action, Atom(value=observation.observed_outcome.value)),
            ),
        )
        if observation.duration_ms is not None:
            _add_fact(
                facts,
                _fact(
                    "observed_duration",
                    (action, Atom(value=observation.duration_ms)),
                ),
            )
        if observation.transport_status is not None:
            token = observation.transport_status.token
            if token != observation.response_summary:
                _add_fact(
                    facts,
                    _fact(
                        "observed_response_status",
                        (action, Atom(value=token)),
                    ),
                )
        if observation.probe_marker is not None:
            _add_fact(
                facts,
                _fact(
                    "observed_marker",
                    (action, Atom(value=observation.probe_marker)),
                ),
            )
        if observation.auth_failed:
            _add_fact(
                facts,
                _fact(
                    "observed_error",
                    (action, Atom(value="auth_failure")),
                ),
            )
        if observation.error_reason is not None:
            error_reason_fact = _error_reason_fact(observation.error_reason, action)
            if error_reason_fact is not None:
                _add_fact(facts, error_reason_fact)
        _extend_facts(facts, _output_field_facts(observation, action))
        _extend_facts(facts, _trace_evidence_facts(observation, action))
        selected_oob_events = (
            oob_events if oob_events is not None else self._poll_oob_events(observation)
        )
        _extend_facts(
            facts,
            _oob_event_facts(observation, action, selected_oob_events),
        )
        observed_transition = _observed_transition(observation)
        if observed_transition is not None:
            state_before, state_after = observed_transition
            _extend_facts(
                facts,
                _transition_facts(action, state_before, state_after),
            )
        else:
            _add_fact(
                facts,
                _unmapped_fact(action, "state", "state_semantics_missing"),
            )
        if graph is not None:
            _, typed_facts = _effect_evidence(observation, action, graph, scope=scope)
            _extend_facts(facts, typed_facts)
        _extend_facts(
            facts,
            _provenance_facts(observation, action, identities, scope, observed_at),
        )
        if graph is not None and check is not None:
            _extend_facts(
                facts,
                _input_binding_facts(
                    observation, action, graph, check, identities, scope
                ),
            )
        if graph is not None and check is not None and scope is not None:
            _extend_facts(
                facts,
                _consume_inputs(
                    observation, action, graph, check, identities, scope, observed_at
                ),
            )
        return QdlGraph(facts=tuple(facts.values()))

    def verified_effects(
        self,
        observation: Observation,
        method_id: str,
        graph: QdlGraph,
    ) -> tuple[Struct, ...]:
        """Return declared effects proved by this observation, never a verdict."""

        effects, _ = _effect_evidence(
            observation, Atom(value=f"action:{method_id}"), graph
        )
        return effects

    def _poll_oob_events(self, observation: Observation) -> tuple[EvidenceEvent, ...]:
        """Read already-captured OOB evidence for this candidate."""

        if self._oob_events is None or observation.probe_marker is None:
            return ()
        event = self._oob_events.wait_for(
            observation.probe_marker,
            0.0,
            channel="oob",
        )
        return () if event is None else (event,)


def _consume_inputs(
    observation: Observation,
    action: Atom,
    graph: QdlGraph,
    check: Check,
    identities: tuple[str, ...] | None,
    scope: str,
    observed_at: float | None,
) -> list[Fact]:
    """Invalidate resource claims after a declared mutating execution.

    Removal consumes identity bindings; transitions consume only prior
    transition claims. Both apply even when mutation completion is uncertain,
    and neither is evidence of mutation success or a security verdict.
    """

    if (
        check.check_id != observation.check_id
        or check.scenario_id != observation.scenario_id
        or check.method_id != action.value.removeprefix("action:")
        or identities is None
        or check.identities != identities
        or observed_at is None
        or not math.isfinite(observed_at)
    ):
        return []
    try:
        declarations, _ = _read_declarations(graph, action)
    except ValidationError:
        return []
    roles = resolve_field_roles(declarations)
    inputs = tuple(
        " _executed(input_field({action},{field}),{value}).".format(
            action=encode_atom(action),
            field=encode_atom(Atom(value=name)),
            value=encode_atom(retained),
        )
        for name, value in check.request
        if (retained := _reference_value(value)) is not None
        and "object_ref" in roles.roles(action.value, name, direction="input")
        and roles.retains(action.value, name, direction="input")
    )
    if not inputs:
        return []
    retained_rows = read_observed_references(graph, scope=scope, identities=identities)
    retained = tuple(
        f"_retained({encode_atom(old)},{encode_term(witness)},"
        f"{encode_atom(resource_type)},{encode_atom(value)},{encode_atom(timestamp)})."
        for old, witness, resource_type, value, _, timestamp in retained_rows
    )
    query = """
    _source("contract"). _source("accepted"). _trusted("runtime").
    _trusted(C) :- _source(C).
    _revoked(Node) :- supersedes(C,_,Node), _trusted(C).
    _reference(W,T) :- refers_to(C,W,T), _source(C), not _revoked(W), not _revoked(replacement(W,T)).
    _ambiguous(W,T) :- _reference(W,T), _reference(W,Other), T != Other.
    _target(T,V) :- _executed(W,V), _reference(W,T), not _ambiguous(W,T).
    _removed(R) :- current_effect(C,{action},remove(R)), _source(C), not _revoked(remove(R)).
    _candidate(I,T,V,Old,Time) :- _target(T,V), _retained(Old,W,T,V,Time),
        evidence("runtime",Old,has(Old,replacement(W,I))), Old != {observation}.
    _consumed(I,T,V,Old,Time) :- _candidate(I,T,V,Old,Time), _removed(T).
    _consumed(I,T,V,Old,Time) :- _candidate(I,T,V,Old,Time), _removed(I).
    _consumed(I,T,V,Old,Time) :- _candidate(I,T,V,Old,Time), _removed(V).
    _consumed(I,T,V,Old,Time) :- _candidate(I,T,V,Old,Time), _removed(R),
        has(C,R,V), is(D,R,T), _trusted(C), _trusted(D).
    _old_effect(Old,E) :- evidence("runtime",Old,E),
        evidence("runtime",Old,source("action",A)), current_effect(C,A,E), _source(C),
        not _revoked(E), not _revoked(replacement(Old,E)).
    _expired(Old,E,Time) :- _consumed(_,_,_,Old,Time), _old_effect(Old,E).
    _expired(Old,transition(From,To),Time) :- _candidate(_,_,_,Old,Time),
        _old_effect(Old,transition(From,To)),
        current_effect(C,{action},transition(NextFrom,NextTo)), _source(C),
        not _revoked(transition(NextFrom,NextTo)).
    """.format(
        action=encode_atom(action),
        observation=encode_atom(Atom(value=observation.observation_id)),
    )
    view = QdlGraph(
        facts=tuple(
            {f.content_hash: f for f in (*graph.facts, *declarations.facts)}.values()
        ),
        rules=tuple(
            rule
            for rule in graph.rules
            if all(
                literal.context in {Context.CONTRACT, Context.ACCEPTED}
                for literal in (*rule.body, *rule.head)
            )
        ),
    )
    consumed_rows = []
    expired_rows = []
    obs = Atom(value=observation.observation_id)
    for solution in ClingoEngine().solve(
        view, closures={"chain_plus"}, query_rules=(*inputs, *retained, query)
    ):
        for atom in solution.atoms:
            symbol = clingo.parse_term(atom)
            if symbol.name not in {"_consumed", "_expired"}:
                continue
            args = tuple(decode_term(arg) for arg in symbol.arguments)
            if symbol.name == "_consumed":
                instance, resource_type, value, old_observation, timestamp = args
            else:
                old_observation, effect, timestamp = args
            try:
                prior_time = float(timestamp.value)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(prior_time) or prior_time > observed_at:
                continue
            if symbol.name == "_expired":
                expired_rows.append((old_observation, effect, timestamp))
                continue
            consumed_rows.append(
                (instance, resource_type, value, old_observation, timestamp)
            )

    consumed_instances = {
        (old_observation, resource_type, value)
        for _, resource_type, value, old_observation, _ in consumed_rows
    }
    facts = []
    for old_observation, effect, timestamp in expired_rows:
        if effect.name == "create" and len(effect.args) == 1:
            resource_type = effect.args[0]
            has_live_instance = any(
                old == old_observation
                and declared_type == resource_type
                and (old, declared_type, value) not in consumed_instances
                for old, _, declared_type, value, _, _ in retained_rows
            )
            if has_live_instance:
                continue
        link = Struct(name="replacement", args=(old_observation, effect))
        declaration = _fact("is", (effect, Atom(value="Effect")))
        references = collect_references(
            effect, declaration.predicate.definition.arguments[0]
        )
        facts.extend(
            _fact("is", fact.args)
            for fact in view.facts
            if fact.predicate.name == "is"
            and canonical_json(fact.args[0]) in references
        )
        facts.extend(
            (
                _fact("is", (obs, Atom(value="Observation"))),
                _fact("is", (old_observation, Atom(value="Observation"))),
                declaration,
                _fact("is", (link, Atom(value="Node"))),
                _fact("supersedes", (obs, link)),
            )
        )
    for instance, resource_type, value, old_observation, _ in consumed_rows:
        link = Struct(name="replacement", args=(old_observation, instance))
        facts.extend(
            (
                _fact("is", (obs, Atom(value="Observation"))),
                _fact("is", (instance, Atom(value="Resource"))),
                _fact("is", (instance, resource_type)),
                _fact("is", (value, Atom(value="Node"))),
                _fact("evidence", (obs, Struct(name="has", args=(instance, value)))),
                _fact("is", (old_observation, Atom(value="Observation"))),
                _fact("is", (link, Atom(value="Node"))),
                _fact("supersedes", (obs, link)),
            )
        )
    return facts


def _effect_evidence(
    observation: Observation,
    action: Atom,
    graph: QdlGraph,
    *,
    scope: str | None = None,
) -> tuple[tuple[Struct, ...], list[Fact]]:
    """Project bounded trusted declarations against actual response channels.

    Select trusted facts and rules with the core graph projection and use
    the existing Clingo current_* closure. Runtime and proposal declarations
    never participate in this evidence decision.
    """

    revoked = {
        canonical_json(f.args[1])
        for f in graph.facts
        if f.context in {Context.CONTRACT, Context.ACCEPTED, Context.RUNTIME}
        and f.predicate.name == "supersedes"
    }
    if canonical_json(Atom(value=observation.observation_id)) in revoked:
        return (), []
    successful = (
        observation.observed_outcome is AccessOutcome.ALLOWED
        and not observation.auth_failed
        and observation.error_reason is None
        and (
            observation.transport_status is None
            or not observation.transport_status.is_error()
        )
    )
    step = _trace_step(observation)
    if observation.trace is not None and (
        step is None
        or step.method_id != action.value.removeprefix("action:")
        or step.scenario_id != observation.scenario_id
    ):
        return (), []
    try:
        declarations, effects = _read_declarations(graph, action)
    except ValidationError:
        return (), []
    revoked.update(
        canonical_json(f.args[1])
        for f in declarations.facts
        if f.predicate.name == "supersedes"
    )
    if canonical_json(Atom(value=observation.observation_id)) in revoked:
        return (), []
    roles = resolve_field_roles(declarations)
    outputs = (
        _output_binding_facts(observation, action, declarations, roles, revoked, scope)
        if successful
        else {}
    )
    facts = [fact for bindings in outputs.values() for fact in bindings]
    verified: list[Struct] = []
    for effect in effects:
        if (
            canonical_json(effect) in revoked
            or canonical_json(
                Struct(
                    name="replacement",
                    args=(Atom(value=observation.observation_id), effect),
                )
            )
            in revoked
        ):
            continue
        evidence: list[Fact] = []
        if successful and effect.name == "create":
            evidence = outputs.get(effect.args[0], [])
        elif (
            successful
            and effect.name == "transition"
            and _observed_transition(observation)
            == tuple(arg.value for arg in effect.args if isinstance(arg, Atom))
        ):
            evidence = [
                _fact("is", (state, Atom(value="State"))) for state in effect.args
            ]
        elif effect.args == (action,) and (
            (
                effect.name == "allowed"
                and successful
                and observation.observed_outcome is AccessOutcome.ALLOWED
            )
            or (
                effect.name == "denied"
                and observation.observed_outcome is AccessOutcome.DENIED
            )
        ):
            evidence = [_fact("is", (action, Atom(value="Action")))]
        if not evidence:
            continue
        verified.append(effect)
        facts.extend(evidence)
        facts.append(_fact("is", (effect, Atom(value="Effect"))))
        facts.append(
            _fact("evidence", (Atom(value=observation.observation_id), effect))
        )
    if facts:
        facts.extend(_observation_sources(observation, action))
    return tuple(verified), facts


def _observation_sources(observation: Observation, action: Atom) -> list[Fact]:
    obs = Atom(value=observation.observation_id)
    return [
        _fact("is", (obs, Atom(value="Observation"))),
        observation_source_fact(observation.observation_id),
        *(
            _fact("evidence", (obs, source(Atom(value=kind), Atom(value=value))))
            for kind, value in (
                ("check", observation.check_id),
                ("scenario", observation.scenario_id),
                ("method", action.value.removeprefix("action:")),
                ("action", action.value),
            )
        ),
    ]


def _provenance_facts(
    observation: Observation,
    action: Atom,
    identities: tuple[str, ...] | None,
    scope: str | None,
    observed_at: float | None,
) -> list[Fact]:
    if identities is None or scope is None:
        return []
    obs = Atom(value=observation.observation_id)
    metadata = (("scope", scope), ("identity", _identity_value(identities)))
    if observed_at is not None and math.isfinite(observed_at):
        metadata += (("observed_at", str(observed_at)),)
    return [
        *_observation_sources(observation, action),
        *(
            _fact("evidence", (obs, source(Atom(value=kind), Atom(value=value))))
            for kind, value in metadata
        ),
    ]


def _read_declarations(
    graph: QdlGraph, action: Atom
) -> tuple[QdlGraph, tuple[Struct, ...]]:
    """Materialize trusted source rules with the existing Clingo engine."""

    selected = graph.select_contexts({Context.CONTRACT, Context.ACCEPTED})
    predicates = {
        fact.predicate.name: fact.predicate
        for fact in (
            *selected.facts,
            *(
                literal
                for rule in selected.rules
                for literal in (*rule.body, *rule.head)
            ),
        )
    }
    facts: dict[str, Fact] = {}
    effects: dict[str, Struct] = {}
    # chain_plus already includes the existing current_effect closure.
    for solution in ClingoEngine().solve(selected, closures={"chain_plus"}):
        for atom in solution.atoms:
            symbol = clingo.parse_term(atom)
            if (
                symbol.name == "current_effect"
                and decode_term(symbol.arguments[1]) == action
            ):
                effect = decode_term(symbol.arguments[2])
                if isinstance(effect, Struct):
                    effects[canonical_json(effect)] = effect
            if symbol.name in predicates:
                fact = Fact(
                    context=Context(symbol.arguments[0].string),
                    predicate=predicates[symbol.name],
                    args=tuple(decode_term(arg) for arg in symbol.arguments[1:]),
                )
                facts[fact.content_hash] = fact
    return QdlGraph(facts=tuple(facts.values())), tuple(effects.values())


def read_observed_effects(
    graph: QdlGraph,
    *,
    scope: str,
    identities: tuple[str, ...],
    method_id: str | None = None,
    bindings: tuple[tuple[Struct, Atom], ...] = (),
    references: tuple[tuple[Struct, Atom], ...] = (),
) -> tuple[tuple[Fact, Atom, Atom], ...]:
    """Return current (evidence, check, time) proofs bound to actual values.

    ``bindings`` requires exact source fields. ``references`` supplies consumer
    input fields and actual values: each field must currently declare one safe
    object_ref type. Values whose type is declared by the proof action's reference
    fields or a resource argument of its effect must occur in that same proof
    observation's current input or output bindings. Relevance comes from trusted
    declarations, never observed values. Unknown consumer typing fails closed.
    """

    rows = _query_observations(
        graph,
        scope,
        identities,
        method=method_id.removeprefix("action:") if method_id is not None else None,
        bindings=bindings,
        references=references,
    )
    return tuple(
        (_fact("evidence", (obs, effect)), check, timestamp)
        for name, (obs, effect, check, timestamp, *_) in rows
        if name == "_proof"
    )


def select_effect_witness(
    proofs: tuple[tuple[Fact, Atom, Atom], ...],
    *,
    required_effects: tuple[Struct, ...],
    outputs: Iterable[tuple[tuple[Atom, Atom, Atom, Atom], ...]],
) -> tuple[Fact, Atom, Atom] | None:
    """Select the latest complete effect proof joined to unambiguous outputs.

    Proofs must already be scoped by the canonical evidence reader. Every
    required effect and output must belong to the same observation; effect
    truth from separate occurrences cannot be combined.
    """

    required = set(required_effects)
    effects_by_observation: dict[object, set[object]] = {}
    for fact, _, _ in proofs:
        effects_by_observation.setdefault(fact.args[0], set()).add(fact.args[1])
    observations = {
        observation
        for observation, effects in effects_by_observation.items()
        if required <= effects
    }
    for rows in outputs:
        if len({value for _, value, _, _ in rows}) != 1:
            return None
        observations.intersection_update(obs for obs, _, _, _ in rows)
    return max(
        (row for row in proofs if row[0].args[0] in observations),
        key=lambda row: float(row[2].value),
        default=None,
    )


def read_live_outputs(
    check: Check,
    observation: Observation,
    *,
    scope: str,
    graph: QdlGraph | None,
) -> dict[str, JsonValue]:
    """Intersect live typed values with canonical, scoped output witnesses."""

    outputs = dict(observation.output.fields) if observation.output else {}
    if graph is None:
        return outputs
    typed = declared_output_refs(graph, check.method_id)
    if typed is None:
        return {}
    if not typed:
        return outputs
    observation_atom = Atom(value=observation.observation_id)
    if not has_observation(graph, observation.observation_id):
        # A query-local sentinel admits checker-only observations to the
        # output reader. It is never persisted or used as a causal proof.
        graph = merge_graphs(
            graph,
            ObservationProjector().project(
                observation,
                normalise_action(check.method_id),
                graph=graph,
                check=check,
                identities=check.identities,
                scope=scope,
                observed_at=0.0,
            ),
        )
    for endpoint in typed:
        name = atom_value(endpoint.args[1])
        if name in outputs and not any(
            source_observation == observation_atom
            and source_check == Atom(value=check.check_id)
            and value.value == outputs[name]
            and type(value.value) is type(outputs[name])
            for source_observation, value, source_check, _ in read_observed_outputs(
                graph,
                endpoint,
                scope=scope,
                identities=check.identities,
            )
        ):
            del outputs[name]
    return outputs


def read_observed_outputs(
    graph: QdlGraph,
    witness: Struct,
    *,
    scope: str,
    identities: tuple[str, ...],
) -> tuple[tuple[Atom, Atom, Atom, Atom], ...]:
    """Return current typed outputs with provenance, independently of effects."""

    method = (
        atom_value(witness.args[0]).removeprefix("action:")
        if len(witness.args) == 2 and isinstance(witness.args[0], Atom)
        else None
    )
    return tuple(
        (obs, value, check, timestamp)
        for obs, field, _, value, check, timestamp in read_observed_references(
            graph, scope=scope, identities=identities, method_id=method
        )
        if field == witness
    )


def read_observed_references(
    graph: QdlGraph,
    *,
    scope: str,
    identities: tuple[str, ...],
    method_id: str | None = None,
) -> tuple[tuple[Atom, Struct, Atom, Atom, Atom, Atom], ...]:
    """Return current (observation, field, type, value, check, time) bindings.

    Fields retain the exact source action and input/output direction. Bindings
    do not imply a causal effect: join proofs by observation before dropping
    provenance for a semantic signature. Row order is unspecified.
    """

    return tuple(
        args
        for name, args in _query_observations(
            graph,
            scope,
            identities,
            method=method_id.removeprefix("action:") if method_id is not None else None,
        )
        if name == "_binding"
    )


def _identity_value(identities: tuple[str, ...]) -> str:
    return canonical_json(tuple(Atom(value=value) for value in identities))


def _query_observations(
    graph: QdlGraph,
    scope: str,
    identities: tuple[str, ...],
    *,
    method: str | None = None,
    bindings: tuple[tuple[Struct, Atom], ...] = (),
    references: tuple[tuple[Struct, Atom], ...] = (),
):
    """Join canonical evidence and trusted current declarations in the core engine."""

    method_clause = (
        '        evidence("runtime",Obs,source("method",{method})),\n'.format(
            method=encode_atom(Atom(value=method))
        )
        if method is not None
        else ""
    )
    try:
        required_bindings = tuple(
            f"_required({encode_term(witness)},{encode_atom(value)})."
            for witness, value in bindings
        )
        required_references = tuple(
            f"_required_reference({encode_term(witness)},{encode_atom(value)})."
            for witness, value in references
        )
    except ValueError:
        return ()
    effect_arguments = []
    for schema in STRUCT_SCHEMAS:
        if schema.name not in CAUSAL_EFFECT_CONSTRUCTORS:
            continue
        variables = tuple(f"X{i}" for i in range(schema.arity))
        term = f"{schema.name}({','.join(variables)})"
        effect_arguments.extend(
            f"_effect_argument({term},{variables[i]}) :- "
            f"current_effect(C,_,{term}), _source(C)."
            for i, argument in enumerate(schema.arguments)
            if argument.reference
        )
    query = """
    _source("contract"). _source("accepted"). _trusted("runtime").
    _trusted(C) :- _source(C).
    _revoked(Node) :- supersedes(C,_,Node), _trusted(C).
    _scope(Obs,Check,Time,Action) :-
        is("runtime",Obs,"Observation"),
        evidence("runtime",Obs,source("scope",{scope})),
        evidence("runtime",Obs,source("identity",{identity})),
        evidence("runtime",Obs,source("check",Check)),
        evidence("runtime",Obs,source("action",Action)),
{method_clause}
        evidence("runtime",Obs,source("observed_at",Time)),
        not _revoked(Obs), not _revoked(Check), not _revoked(Action).
    _type(W,T) :- refers_to(C,W,T), _source(C),
        not _revoked(replacement(W,T)).
    _type(W,T) :- coupled(C,W,I,"eq"), refers_to(D,I,T), _source(C), _source(D),
        not _revoked(I), not _revoked(replacement(I,T)).
    _type(W,T) :- coupled(C,I,W,"eq"), refers_to(D,I,T), _source(C), _source(D),
        not _revoked(I), not _revoked(replacement(I,T)).
    _ambiguous_type(W,T) :- _type(W,T), _type(W,Other), T != Other.
    _redacted(W) :- current_has(C,W,"sensitive"), _source(C), not _revoked(replacement(W,"sensitive")).
    _redacted(W) :- current_has(C,W,"credential"), _source(C), not _revoked(replacement(W,"credential")).
    _typed(Obs,output_field(Action,Field),Instance,Value,T) :-
        _scope(Obs,_,_,Action),
        has("runtime",output_field(Action,Field),Instance),
        evidence("runtime",Obs,has(Obs,replacement(output_field(Action,Field),Instance))),
        is("runtime",Instance,T),
        evidence("runtime",Obs,has(Instance,Value)),
        current_has("runtime",Instance,Value),
        current_has(C,output_field(Action,Field),"object_ref"), _source(C),
        _type(output_field(Action,Field),T), not _ambiguous_type(output_field(Action,Field),T),
        not _redacted(output_field(Action,Field)),
        not _revoked(replacement(output_field(Action,Field),Instance)),
        not _revoked(Instance), not _revoked(Value), not _revoked(T),
        not _revoked(replacement(Obs,Instance)),
        not _revoked(output_field(Action,Field)),
        not _revoked(replacement(output_field(Action,Field),"object_ref")),
        not _revoked(replacement(Instance,Value)).
    _bound(Obs,W,V) :- _scope(Obs,_,_,_),
        evidence("runtime",Obs,has(Obs,replacement(W,I))),
        evidence("runtime",Obs,has(I,V)),
        _type(W,T), is("runtime",I,T), not _ambiguous_type(W,T),
        current_has(C,W,"object_ref"), _source(C), not _redacted(W),
        not _revoked(W), not _revoked(I), not _revoked(V),
        not _revoked(replacement(W,"object_ref")), not _revoked(replacement(Obs,I)).
    _missing_input(Obs) :- _scope(Obs,_,_,_), _required(W,V), not _bound(Obs,W,V).
    _binding(Obs,W,T,V,Check,Time) :- _scope(Obs,Check,Time,_),
        _typed(Obs,W,_,V,T), not _stale_input(Obs).
    _binding(Obs,input_field(Action,F),T,V,Check,Time) :- _scope(Obs,Check,Time,Action),
        _bound(Obs,input_field(Action,F),V),
        evidence("runtime",Obs,has(Obs,replacement(input_field(Action,F),I))),
        evidence("runtime",Obs,has(I,V)), is("runtime",I,T),
        _type(input_field(Action,F),T), current_has("runtime",I,V),
        not _revoked(T), not _revoked(replacement(I,V)),
        not _revoked(replacement(input_field(Action,F),I)), not _stale_input(Obs).
    _reference(Obs,T,V) :- _binding(Obs,_,T,V,_,_).
    _reference_role(W) :- current_has(C,W,"object_ref"), _source(C),
        not _redacted(W), not _revoked(W), not _revoked(replacement(W,"object_ref")).
    _reference_type(W,T) :- _reference_role(W), _type(W,T),
        not _ambiguous_type(W,T), _resource_type(T).
    _valid_reference(input_field(A,F)) :- _required_reference(input_field(A,F),_),
        _reference_type(input_field(A,F),_), not _revoked(A).
    _invalid_reference :- _required_reference(W,_), not _valid_reference(W).
    _declared_field(A,input_field(A,F)) :- is(C,input_field(A,F),"InputField"), _source(C).
    _declared_field(A,output_field(A,F)) :- is(C,output_field(A,F),"OutputField"), _source(C).
    _relevant_type(A,E,T) :- current_effect(C,A,E), _source(C),
        _declared_field(A,W), has(D,W,"object_ref"), _source(D),
        _type(W,T), not _revoked(T).
    _resource_type(T) :- is(C,T,"ResourceType"), _source(C), not _revoked(T).
    _resource_type(T) :- is(C,T,"Resource"), _source(C), not _revoked(T).
    _effect_type(E,T) :- _effect_argument(E,T), _resource_type(T).
    _effect_type(E,T) :- _effect_argument(E,R), is(C,R,T), _source(C),
        _resource_type(T), not _revoked(R).
    _relevant_type(A,E,T) :- current_effect(C,A,E), _source(C), _effect_type(E,T).
    _missing_reference(Obs,E) :- _base(Obs,E,_,_,Action), _required_reference(W,V),
        _reference_type(W,T), _relevant_type(Action,E,T), not _reference(Obs,T,V).
    _stale_input(Obs) :- evidence("runtime",Obs,has(Obs,replacement(input_field(A,F),I))),
        _revoked(replacement(Obs,I)).
    _base(Obs,E,Check,Time,Action) :- _scope(Obs,Check,Time,Action),
        evidence("runtime",Obs,E), current_effect(C,Action,E), _source(C),
        not _revoked(E), not _revoked(replacement(Obs,E)).
    _created(Obs,T) :- _typed(Obs,_,_,_,T).
    _invalid(Obs,create(T)) :- _base(Obs,create(T),_,_,_), not _created(Obs,T).
    _proof(Obs,E,Check,Time,Action) :- _base(Obs,E,Check,Time,Action), not _invalid(Obs,E), not _missing_input(Obs), not _invalid_reference, not _missing_reference(Obs,E), not _stale_input(Obs).
    """.format(
        scope=encode_atom(Atom(value=scope)),
        identity=encode_atom(Atom(value=_identity_value(identities))),
        method_clause=method_clause,
    )
    view = QdlGraph(
        facts=graph.facts,
        rules=tuple(
            rule
            for rule in graph.rules
            if all(
                literal.context in {Context.CONTRACT, Context.ACCEPTED}
                for literal in (*rule.body, *rule.head)
            )
        ),
    )
    rows = []
    for solution in ClingoEngine().solve(
        view,
        closures={"chain_plus", "current_has"},
        query_rules=(
            *required_bindings,
            *required_references,
            *effect_arguments,
            query,
        ),
    ):
        for atom in solution.atoms:
            symbol = clingo.parse_term(atom)
            if symbol.name not in {"_proof", "_binding"}:
                continue
            args = tuple(decode_term(arg) for arg in symbol.arguments)
            timestamp = args[3] if symbol.name == "_proof" else args[5]
            try:
                valid_time = math.isfinite(float(timestamp.value))
            except (TypeError, ValueError):
                valid_time = False
            if valid_time:
                rows.append((symbol.name, args))
    return tuple(rows)


def _output_binding_facts(
    observation: Observation,
    action: Atom,
    graph: QdlGraph,
    roles: FieldRolePolicy,
    revoked: set[str],
    scope: str | None,
) -> dict[Atom, list[Fact]]:
    """Retain actual typed values through declared safe outputs, without causes."""

    if observation.output is None:
        return {}
    facts: dict[Atom, list[Fact]] = {}
    for field_name, value in observation.output.fields:
        retained = _reference_value(value)
        if retained is None:
            continue
        field_roles = roles.roles(action.value, field_name, direction="output")
        if "object_ref" not in field_roles or not roles.retains(
            action.value, field_name, direction="output"
        ):
            continue
        witness = Struct(name="output_field", args=(action, Atom(value=field_name)))
        types = _reference_types(graph, witness, revoked)
        if canonical_json(witness) in revoked or len(types) != 1:
            continue
        resource_type = Atom.model_validate_json(next(iter(types)))
        if canonical_json(resource_type) in revoked or not _declares_resource_type(
            graph, resource_type
        ):
            continue
        facts.setdefault(resource_type, []).extend(
            _typed_binding_facts(
                observation,
                witness,
                resource_type,
                retained,
                scope,
                revoked,
            )
        )
    return facts


def _reference_value(value: JsonValue) -> Atom | None:
    """Admit retained references only when the core solver can represent them."""

    if not isinstance(value, str) or not value or value == "[REDACTED]":
        return None
    atom = Atom(value=value)
    try:
        encode_atom(atom)
    except ValueError:
        return None
    return atom


def _typed_binding_facts(
    observation: Observation,
    witness: Struct,
    resource_type: Atom,
    observed_value: Atom,
    scope: str | None,
    revoked: set[str],
) -> list[Fact]:
    """Correlate one retained typed field value with its actual observation."""

    instance_scope = Atom(
        value=scope if scope is not None else f"scenario:{observation.scenario_id}"
    )
    identity = canonical_json((resource_type, instance_scope, observed_value))
    instance = Atom(
        value=f"resource-instance:{hashlib.sha256(identity.encode()).hexdigest()}"
    )
    if canonical_json(instance) in revoked:
        return []
    obs = Atom(value=observation.observation_id)
    link = Struct(name="replacement", args=(witness, instance))
    return [
        _fact("is", (obs, Atom(value="Observation"))),
        _fact("is", (resource_type, Atom(value="ResourceType"))),
        _fact(
            "is",
            (
                witness,
                Atom(
                    value="InputField"
                    if witness.name == "input_field"
                    else "OutputField"
                ),
            ),
        ),
        _fact("is", (instance, Atom(value="Resource"))),
        _fact("is", (instance, resource_type)),
        _fact("is", (instance_scope, Atom(value="Scope"))),
        _fact("is", (observed_value, Atom(value="Node"))),
        _fact("is", (link, Atom(value="Node"))),
        _fact("part", (instance, instance_scope)),
        _fact("has", (witness, instance)),
        _fact("has", (instance, observed_value)),
        _fact("evidence", (obs, Struct(name="has", args=(instance, observed_value)))),
        _fact("evidence", (obs, Struct(name="has", args=(obs, link)))),
    ]


def _input_binding_facts(
    observation: Observation,
    action: Atom,
    graph: QdlGraph,
    check: Check,
    identities: tuple[str, ...] | None,
    scope: str | None,
) -> list[Fact]:
    """Retain only explicitly safe typed references from the executed request."""

    if (
        check.check_id != observation.check_id
        or check.scenario_id != observation.scenario_id
        or check.method_id != action.value.removeprefix("action:")
        or check.identities != identities
    ):
        return []
    try:
        declarations, _ = _read_declarations(graph, action)
    except ValidationError:
        return []
    roles = resolve_field_roles(declarations)
    revoked = {
        canonical_json(f.args[1])
        for f in (*graph.facts, *declarations.facts)
        if f.predicate.name == "supersedes"
        and f.context in {Context.CONTRACT, Context.ACCEPTED, Context.RUNTIME}
    }
    facts = []
    for name, value in check.request:
        retained = _reference_value(value)
        if (
            retained is None
            or "object_ref" not in roles.roles(action.value, name, direction="input")
            or not roles.retains(action.value, name, direction="input")
        ):
            continue
        witness = Struct(name="input_field", args=(action, Atom(value=name)))
        types = _reference_types(declarations, witness, revoked)
        if len(types) != 1 or canonical_json(witness) in revoked:
            continue
        resource_type = Atom.model_validate_json(next(iter(types)))
        if not _declares_resource_type(declarations, resource_type):
            continue
        facts.extend(
            _typed_binding_facts(
                observation, witness, resource_type, retained, scope, revoked
            )
        )
    return facts


def _declares_resource_type(graph: QdlGraph, resource_type: Atom) -> bool:
    """Accept both canonical resource-type and contract-target spellings.

    Formal adapters use ``ResourceType`` for the abstract fixture type.  The
    benchmark contract projection also uses ``Resource`` for a target class;
    its create effect and typed output still provide the same explicit
    declaration.  This compatibility is deliberately narrow: an ``is``
    declaration is still required, and the caller additionally requires a
    retained ``object_ref`` output with a matching ``refers_to`` fact.
    """

    return any(
        f.predicate.name == "is"
        and f.args == (resource_type, Atom(value=declared_type))
        for f in graph.facts
        for declared_type in ("ResourceType", "Resource")
    )


def _reference_types(graph: QdlGraph, witness: Struct, revoked: set[str]) -> set[str]:
    """Resolve direct output typing or the existing equal typed input binding."""

    holders = [witness]
    for fact in graph.facts:
        if fact.predicate.name != "coupled" or fact.args[2] != Atom(value="eq"):
            continue
        left, right, _ = fact.args
        candidate = right if left == witness else left if right == witness else None
        if isinstance(candidate, Struct) and candidate.name == "input_field":
            holders.append(candidate)
    return {
        canonical_json(fact.args[1])
        for fact in graph.facts
        if fact.predicate.name == "refers_to"
        and fact.args[0] in holders
        and canonical_json(Struct(name="replacement", args=fact.args)) not in revoked
        and canonical_json(fact.args[0]) not in revoked
    }


def _output_field_facts(
    observation: Observation,
    action: Atom,
) -> list[Fact]:
    """Project output field names without their values.

    Safe response values, the descriptor shape, the matching trace response,
    and the full response tree all contribute shape-only field evidence.  The
    full tree is especially important for protocols that retain nested or
    unknown response paths that are not whitelisted for workflow forwarding.
    """

    names: list[str] = []
    facts: list[Fact] = []
    if observation.output is not None:
        names.extend(
            name for name, _ in observation.output.fields if isinstance(name, str)
        )
        names.extend(
            name for name in observation.output.field_names if isinstance(name, str)
        )
    names.extend(
        path
        for path, _ in observation.response_tree
        if isinstance(path, str) and path != "__truncated__"
    )
    step = _trace_step(observation)
    if step is not None and step.response is not None:
        names.extend(name for name, _ in step.response.fields if isinstance(name, str))
        names.extend(
            name for name in step.response.field_names if isinstance(name, str)
        )

    emitted: set[object] = set()
    for field_name in names:
        fact = _field_fact(field_name, action)
        if fact is None or field_name in emitted:
            continue
        facts.append(fact)
        emitted.add(field_name)
    return facts


def _trace_evidence_facts(
    observation: Observation,
    action: Atom,
) -> list[Fact]:
    """Project every TraceStep evidence channel or mark it unavailable.

    Runtime trace fields use namespaced field paths (for example
    ``request.user_id``) so values remain outside the QDL graph while the
    presence of each evidence channel is still explicit.  Empty channels are
    represented by ``unmapped`` evidence rather than being silently omitted.
    """

    step = _trace_step(observation)
    if step is None:
        return [_unmapped_fact(action, "trace", "trace_not_available")]

    facts: list[Fact] = []
    facts.extend(_channel_field_facts(step.request_fields, "request", action))
    if not step.request_fields:
        facts.append(_not_available_fact("request_fields", action))

    response_available = (
        observation.output is not None
        or step.response is not None
        or bool(observation.response_tree)
    )
    if not response_available:
        facts.append(_not_available_fact("response", action))

    facts.extend(
        _channel_field_facts(
            (name for name, _ in step.resource_state_before),
            "state_before",
            action,
        )
    )
    if not step.resource_state_before:
        facts.append(_not_available_fact("resource_state_before", action))

    facts.extend(
        _channel_field_facts(
            (name for name, _ in step.resource_state_after),
            "state_after",
            action,
        )
    )
    if not step.resource_state_after:
        facts.append(_not_available_fact("resource_state_after", action))

    facts.extend(_channel_field_facts(step.permissions_checked, "permission", action))
    if not step.permissions_checked:
        facts.append(_not_available_fact("permissions_checked", action))

    facts.extend(_channel_field_facts(step.gates_passed, "gate", action))
    if not step.gates_passed:
        facts.append(_not_available_fact("gates_passed", action))

    facts.extend(_sink_facts(step.sinks_reached, action))
    if not step.sinks_reached:
        facts.append(_not_available_fact("sinks_reached", action))
    return facts


def _channel_field_facts(
    names: Iterable[object],
    prefix: str,
    action: Atom,
) -> list[Fact]:
    facts: list[Fact] = []
    for name in names:
        if not isinstance(name, str):
            continue
        fact = _field_fact(f"{prefix}.{name}", action)
        if fact is not None:
            facts.append(fact)
    return facts


def _sink_facts(names: Iterable[object], action: Atom) -> list[Fact]:
    """Project reached sinks as flat ``observed_reached`` aggregates."""

    facts: list[Fact] = []
    for name in names:
        if not isinstance(name, str):
            continue
        fact = _sink_fact(name, action)
        if fact is not None:
            facts.append(fact)
    return facts


def _sink_fact(sink_name: object, action: Atom) -> Fact | None:
    try:
        return _fact(
            "observed_reached",
            (action, Atom(value=sink_name)),
        )
    except ValidationError:
        return None


def _not_available_fact(
    channel: str,
    action: Atom,
) -> Fact:
    return _unmapped_fact(action, "trace", f"{channel}_not_available")


def _unmapped_fact(
    action: Atom,
    kind: str,
    reason: str,
) -> Fact:
    return _fact(
        "observed_unmapped",
        (
            action,
            Atom(value=kind),
            Atom(value=reason),
        ),
    )


def _oob_event_facts(
    observation: Observation,
    action: Atom,
    events: Sequence[EvidenceEvent],
) -> list[Fact]:
    """Project actual collaborator callbacks for this observation's marker."""

    if observation.probe_marker is None:
        return []
    markers = sorted(
        {
            event.correlation_id
            for event in events
            if event.correlation_id == observation.probe_marker
        }
    )
    return [
        _fact(
            "observed_external_call",
            (action, Atom(value=marker)),
        )
        for marker in markers
    ]


def _field_fact(
    field_name: object,
    action: Atom,
) -> Fact | None:
    """Build one shape-only field fact, skipping invalid names."""

    try:
        return _fact(
            "observed_field",
            (action, Atom(value=field_name)),
        )
    except ValidationError:
        return None


def _error_reason_fact(
    error_reason: str,
    action: Atom,
) -> Fact | None:
    """Build one error-channel fact from the redacted transport reason."""

    try:
        return _fact(
            "observed_error",
            (action, Atom(value=error_reason)),
        )
    except ValidationError:
        return None


def _observed_transition(
    observation: Observation,
) -> tuple[str, str] | None:
    """Extract an explicit before/after control-state pair.

    Only the matching trace step's dedicated resource-state channels are
    executable evidence.  Response fields and the response tree remain
    shape-only evidence; their names do not declare state semantics.
    """

    step = _trace_step(observation)
    if step is None:
        return None
    state_before = _state_value(step.resource_state_before)
    state_after = _state_value(step.resource_state_after)
    if state_before is None or state_after is None:
        return None
    return state_before, state_after


def _trace_step(observation: Observation) -> TraceStep | None:
    """Return the trace step that belongs to this observation."""

    if observation.trace is None:
        return None
    matches = tuple(
        step
        for step in observation.trace.steps
        if step.observation_id == observation.observation_id
    )
    if not matches or any(step != matches[0] for step in matches[1:]):
        return None
    return matches[0]


def _state_value(fields: tuple[tuple[str, JsonValue], ...]) -> str | None:
    """Return the sole string value in one explicit resource-state channel."""

    values = [value for _, value in fields if isinstance(value, str) and value]
    return values[0] if len(values) == 1 else None


def _transition_facts(
    action: Atom,
    state_before: str,
    state_after: str,
) -> list[Fact]:
    """Declare both states and emit grounded transition evidence."""

    facts = [
        _fact("is", (Atom(value=state), Atom(value="State")))
        for state in dict.fromkeys((state_before, state_after))
    ]
    facts.extend(
        (
            _fact(
                "transition",
                (action, Atom(value=state_before), Atom(value=state_after)),
            ),
            _fact(
                "observed_transition",
                (action, Atom(value=state_before), Atom(value=state_after)),
            ),
        )
    )
    return facts


def _add_fact(facts: dict[str, Fact], fact: Fact) -> None:
    facts.setdefault(fact.content_hash, fact)


def _extend_facts(facts: dict[str, Fact], additions: Iterable[Fact]) -> None:
    for fact in additions:
        _add_fact(facts, fact)


def _fact(predicate: str, args: tuple[object, ...]) -> Fact:
    return Fact(
        context=Context.RUNTIME,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )
