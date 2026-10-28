"""Compile Clingo-derived algebra threats into QDL norm facts."""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Sequence
from dataclasses import dataclass

import clingo

from cloud_dast.qdl.engine import ClingoEngine, ClingoSolution
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    QdlGraph,
    Rule,
    Struct,
    allowed,
    canonical_json,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.qdl.semantic_norm_compiler import (
    FormalCompilationError,
    duration_effects,
    external_call_effects,
    filter_executable_graph,
    privileged_change_effects,
    reached_effects,
    sensitive_exposure_effects,
    synthetic_norm_facts,
)

logger = logging.getLogger(__name__)

_THREAT_LETTERS = frozenset(
    {"elevation", "tampering", "spoofing", "disclosure", "denial"}
)
_THREAT_CORPUS = frozenset(
    {
        "owasp_api1_bola",
        "owasp_api3_mass_assignment",
        "owasp_api4_resource_consumption",
        "owasp_api5_function_authz",
        "owasp_api6_business_flows",
        "owasp_api7_ssrf",
        "owasp_api9_inventory",
        "owasp_api10_unsafe_consumption",
        "owasp_a01_access_control",
        "owasp_a02_crypto",
        "owasp_a03_injection",
        "owasp_a07_auth",
        "owasp_a08_integrity",
        "owasp_a10_ssrf",
    }
)
_RELEVANT_THREATS = _THREAT_LETTERS | _THREAT_CORPUS
_ALLOWED_CLASSES = frozenset(
    {
        "elevation",
        "owasp_api1_bola",
        "owasp_api5_function_authz",
        "owasp_api9_inventory",
        "owasp_a01_access_control",
    }
)
_DISCLOSURE_CLASSES = frozenset({"disclosure", "owasp_a02_crypto"})
_TAMPERING_CLASSES = frozenset({"tampering", "owasp_api3_mass_assignment"})
_INJECTION_CLASSES = frozenset({"owasp_a03_injection"})
_EXTERNAL_CALL_CLASSES = frozenset({"owasp_api7_ssrf", "owasp_a10_ssrf"})
_AVAILABILITY_CLASSES = frozenset({"denial", "owasp_api4_resource_consumption"})
_ATOM_NAME_RE = re.compile(r"^([a-z_][a-z0-9_]*)\(")
_EXECUTABLE_CONTEXTS = frozenset({Context.CONTRACT, Context.ACCEPTED})
_THREAT_SLICE_PREDICATES = frozenset(
    {
        "attacker",
        "targets",
        "causes",
        "transition",
        "supersedes",
        "may",
        "binding",
        "grants",
        "requires",
        "applies_to",
        "part",
        "owner",
    }
)
_THREAT_ACTION_POSITIONS: dict[str, tuple[int, ...]] = {
    "spoofing": (0,),
    "tampering": (0,),
    "disclosure": (1,),
    "elevation": (1,),
    "owasp_api1_bola": (0,),
    "owasp_api3_mass_assignment": (0,),
    "owasp_api5_function_authz": (0,),
    "owasp_api6_business_flows": (0,),
    "owasp_api7_ssrf": (0,),
    "owasp_api9_inventory": (0,),
    "owasp_api10_unsafe_consumption": (0,),
    "owasp_a01_access_control": (0,),
    "owasp_a02_crypto": (0, 1),
    "owasp_a03_injection": (0,),
    "owasp_a07_auth": (0,),
    "owasp_a08_integrity": (0,),
    "owasp_a10_ssrf": (0,),
}
_THREAT_RESOURCE_POSITIONS: dict[str, int] = {
    "denial": 1,
    "owasp_api4_resource_consumption": 1,
}


@dataclass(frozen=True, slots=True)
class _ThreatSignal:
    threat_class: str
    action_id: str | None
    resource_id: str | None = None


class ThreatIntentCompiler:
    """Turn algebra-derived threat atoms into evidence-backed norm facts."""

    def __init__(self, clingo: ClingoEngine | None = None) -> None:
        self._clingo = clingo or ClingoEngine()
        self._cache: dict[str, tuple[Fact, ...]] = {}
        self._cache_lock = threading.Lock()

    def compile_cached(self, graph: QdlGraph) -> tuple[Fact, ...]:
        """Compile and cache the planner threat layer by its relevant slice."""

        slice_ = self.threat_slice(graph)
        key = slice_.content_hash
        with self._cache_lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        facts = self.compile(slice_)
        with self._cache_lock:
            return self._cache.setdefault(key, facts)

    @staticmethod
    def threat_slice(graph: QdlGraph) -> QdlGraph:
        """Return the self-contained graph slice consumed by threat algebra."""

        executable = filter_executable_graph(graph)
        relevant_predicates = set(_THREAT_SLICE_PREDICATES)
        relevant_rules: set[str] = set()
        rules_by_head: dict[str, list[Rule]] = {}
        for rule in executable.rules:
            rules_by_head.setdefault(rule.head[0].predicate.name, []).append(rule)

        pending = list(relevant_predicates)
        while pending:
            predicate = pending.pop()
            for rule in rules_by_head.get(predicate, ()):
                rule_key = canonical_json(rule)
                if rule_key in relevant_rules:
                    continue
                relevant_rules.add(rule_key)
                for literal in rule.body:
                    if literal.predicate.name not in relevant_predicates:
                        relevant_predicates.add(literal.predicate.name)
                        pending.append(literal.predicate.name)

        relevant = tuple(
            fact
            for fact in executable.facts
            if fact.predicate.name in relevant_predicates
        )
        rules = tuple(
            rule for rule in executable.rules if canonical_json(rule) in relevant_rules
        )
        relevant_literals = (
            *relevant,
            *(literal for rule in rules for literal in (*rule.body, *rule.head)),
        )
        referenced = {
            canonical_json(term)
            for literal in relevant_literals
            for term in _walk_terms(literal.args)
        }
        declarations = tuple(
            fact
            for fact in executable.facts
            if fact.predicate.name == "is"
            and fact.args
            and canonical_json(fact.args[0]) in referenced
        )
        unique = {canonical_json(fact): fact for fact in (*declarations, *relevant)}
        return QdlGraph(
            facts=tuple(unique[key] for key in sorted(unique)),
            rules=rules,
        )

    def compile(self, graph: QdlGraph) -> tuple[Fact, ...]:
        """Return synthetic prevents facts for evidence-backed threats."""

        source = filter_executable_graph(graph)
        solution = self._solve(source)
        if solution is None:
            return ()
        threats = _extract_threats(solution)
        if not threats:
            return ()

        declared_actions = {
            atom_value(fact.args[0])
            for fact in source.facts
            if fact.predicate.name == "is"
            and len(fact.args) == 2
            and atom_value(fact.args[1]) == "Action"
            and atom_value(fact.args[0]) is not None
        }
        facts: dict[str, Fact] = {}
        seen_effects: set[str] = set()
        unsupported = 0
        for signal in threats:
            if (
                signal.action_id is not None
                and signal.action_id not in declared_actions
            ):
                continue
            effects = self._effects_for(source, signal, duration_graph=graph)
            if not effects:
                unsupported += 1
                continue
            for effect in effects:
                effect_key = canonical_json(effect)
                if effect_key in seen_effects:
                    continue
                seen_effects.add(effect_key)
                for fact in synthetic_norm_facts(source, effect):
                    facts.setdefault(canonical_json(fact), fact)

        logger.info(
            "threat_intent_compiled threats=%d norms=%d unsupported=%d",
            len(threats),
            len(seen_effects),
            unsupported,
        )
        return tuple(facts[key] for key in sorted(facts))

    def _effects_for(
        self,
        graph: QdlGraph,
        signal: _ThreatSignal,
        *,
        duration_graph: QdlGraph | None = None,
    ) -> tuple[Struct, ...]:
        """Select effects from graph evidence; never fall back to ``allowed``."""

        threat_class = signal.threat_class
        action_id = signal.action_id
        if threat_class in _ALLOWED_CLASSES:
            if action_id is None:
                return ()
            return (allowed(Atom(value=action_id)),)
        if threat_class in _DISCLOSURE_CLASSES:
            return (
                ()
                if action_id is None
                else sensitive_exposure_effects(graph, action_id)
            )
        if threat_class in _TAMPERING_CLASSES:
            return (
                () if action_id is None else privileged_change_effects(graph, action_id)
            )
        if threat_class in _INJECTION_CLASSES:
            return () if action_id is None else reached_effects(graph, action_id)
        if threat_class in _EXTERNAL_CALL_CLASSES:
            return () if action_id is None else external_call_effects(graph, action_id)
        if threat_class in _AVAILABILITY_CLASSES:
            return self._availability_effects(duration_graph or graph, signal)
        return ()

    @staticmethod
    def _availability_effects(
        graph: QdlGraph,
        signal: _ThreatSignal,
    ) -> tuple[Struct, ...]:
        """Join availability threats to actions with a latency baseline."""

        if signal.resource_id is None:
            return ()
        effects: set[Struct] = set()
        for fact in graph.facts:
            if fact.predicate.name != "targets" or len(fact.args) != 2:
                continue
            if fact.context not in _EXECUTABLE_CONTEXTS:
                continue
            action, resource = fact.args
            if atom_value(resource) != signal.resource_id:
                continue
            action_id = atom_value(action)
            if action_id is not None:
                effects.update(duration_effects(graph, action_id))
        return tuple(dict.fromkeys(sorted(effects, key=canonical_json)))

    def _solve(self, graph: QdlGraph) -> ClingoSolution | None:
        try:
            solutions = self._clingo.solve(graph, algebra=True)
            return solutions[0] if solutions else None
        except Exception as error:
            logger.error("threat_intent_solve_failed reason=%s", error)
            raise FormalCompilationError("threat-intent Clingo solve failed") from error


def _extract_threats(solution: ClingoSolution) -> tuple[_ThreatSignal, ...]:
    threats: set[_ThreatSignal] = set()
    for atom_repr in solution.atoms:
        match = _ATOM_NAME_RE.match(atom_repr)
        if match is None:
            continue
        name = match.group(1)
        if name not in _RELEVANT_THREATS:
            continue
        arguments = _atom_arguments(atom_repr)
        action_ids = _positioned_values(
            arguments,
            _THREAT_ACTION_POSITIONS.get(name, ()),
        )
        resource_id = _positioned_value(
            arguments,
            _THREAT_RESOURCE_POSITIONS.get(name),
        )
        if not action_ids and name not in _AVAILABILITY_CLASSES:
            continue
        if not action_ids and resource_id is None:
            continue
        for action_id in action_ids or (None,):
            threats.add(
                _ThreatSignal(
                    threat_class=name,
                    action_id=action_id,
                    resource_id=resource_id,
                )
            )
    return tuple(
        sorted(
            threats,
            key=lambda item: (
                item.threat_class,
                item.action_id or "",
                item.resource_id or "",
            ),
        )
    )


def _atom_arguments(atom_repr: str) -> tuple[str | int | None, ...]:
    try:
        symbol = clingo.parse_term(atom_repr)
    except RuntimeError:
        return _quoted_values(atom_repr)
    if symbol.type != clingo.SymbolType.Function:
        return ()
    return tuple(_scalar_value(argument) for argument in symbol.arguments)


def _scalar_value(symbol: clingo.Symbol) -> str | int | None:
    if symbol.type == clingo.SymbolType.String:
        return symbol.string
    if symbol.type == clingo.SymbolType.Number:
        return symbol.number
    if symbol.type == clingo.SymbolType.Function and not symbol.arguments:
        return symbol.name
    return None


def _positioned_values(
    arguments: Sequence[str | int | None],
    positions: tuple[int, ...],
) -> tuple[str, ...]:
    return tuple(
        arguments[position]
        for position in positions
        if position < len(arguments) and isinstance(arguments[position], str)
    )


def _positioned_value(
    arguments: Sequence[str | int | None],
    position: int | None,
) -> str | None:
    if position is None or position >= len(arguments):
        return None
    value = arguments[position]
    return value if isinstance(value, str) else None


def _quoted_values(atom_repr: str) -> tuple[str, ...]:
    return tuple(match.group(1) for match in re.finditer(r'"([^"]+)"', atom_repr))


def _walk_terms(terms: Sequence[object]) -> tuple[Atom | Struct, ...]:
    terms_out: list[Atom | Struct] = []
    for term in terms:
        if isinstance(term, Atom):
            terms_out.append(term)
        elif isinstance(term, Struct):
            terms_out.append(term)
            terms_out.extend(_walk_terms(term.args))
    return tuple(terms_out)


__all__ = [
    "ThreatIntentCompiler",
    "_AVAILABILITY_CLASSES",
    "_RELEVANT_THREATS",
    "_THREAT_ACTION_POSITIONS",
    "_THREAT_RESOURCE_POSITIONS",
]
