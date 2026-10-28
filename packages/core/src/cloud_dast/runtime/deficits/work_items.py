"""Deterministic work-item planning and merge projections."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from itertools import combinations
from typing import Any

from cloud_dast.graphs import wave_layers
from cloud_dast.model import Observation
from cloud_dast.qdl.graph import QdlGraph, Variable, canonical_json
from cloud_dast.runtime.consultation.axes import DETERMINISTIC_AXES, LLM_AXES

_EVIDENCE_CONTEXT_KEYS = (
    "clue_observation_id",
    "observation_id",
    "control",
    "treatment",
)
_MISSING_FACTS: Mapping[tuple[str, str], tuple[tuple[str, str], ...]] = {
    ("causes", "alternatives"): (("causes", "effect"), ("requires", "resource")),
    ("causes", "availability"): (("causes", "duration"),),
    ("reaches", "dataflows"): (("causes", "effect"), ("requires", "effect")),
    ("has", "roles"): (("has", "input_field"),),
    ("probe_carrier", "dataflows"): (("reaches", "path"),),
    ("may", "roles"): (("has", "input_field"),),
    ("exposes", "exposures"): (("exposes", "output_field"),),
    ("exposes", "response_semantics"): (
        ("exposes", "output_field"),
        ("has", "output_field"),
    ),
    ("prevents", "variance"): (
        ("prevents", "norm"),
        ("exposes", "output_field"),
        ("has", "output_field"),
        ("reaches", "path"),
    ),
    ("transition", "state"): (("transition", "state"),),
    ("refers_to", "fixture"): (
        ("refers_to", "resource_type"),
        ("targets", "resource_type"),
        ("causes", "create"),
    ),
    ("has", "classification"): (("has", "classification"),),
    ("is", "classification"): (("is", "classification"),),
}
_CONSULTATION_PRODUCES: Mapping[str, tuple[tuple[str, str], ...]] = {
    "roles": (("has", "input_field"), ("has", "output_field")),
    "dataflows": (("reaches", "path"), ("causes", "effect")),
    "exposures": (("exposes", "output_field"),),
    "fixture": (
        ("refers_to", "resource_type"),
        ("targets", "resource_type"),
        ("causes", "create"),
    ),
    "state": (("transition", "state"),),
    "alternatives": (("causes", "effect"), ("requires", "resource")),
    "response_semantics": (),
    "variance": (("prevents", "norm"),),
    "availability": (("causes", "duration"),),
    "classification": (("has", "classification"), ("is", "classification")),
}


def _context_value(deficit: Any, name: str) -> str | None:
    return next((value for key, value in deficit.context if key == name), None)


def _work_item_id(key: tuple[str, ...]) -> str:
    digest = hashlib.sha256("\x1f".join(key).encode("utf-8")).hexdigest()[:12]
    return f"wi:{key[0]}:{key[1]}:{digest}"


def _missing_fact_signature(deficit: Any) -> frozenset[str]:
    action = deficit.action
    facts = {
        f"{predicate}|{term}|{action}"
        for predicate, term in _MISSING_FACTS.get(
            (deficit.predicate_class, deficit.axis or ""), ()
        )
    }
    if deficit.predicate_class == "causes" and len(deficit.subgoal.args) > 1:
        effect_term = deficit.subgoal.args[1]
        if not isinstance(effect_term, Variable):
            effect = canonical_json(effect_term)
            facts.discard(f"causes|effect|{action}")
            facts.add(f"causes|effect|{action}|{effect}")
    return frozenset(facts)


def _produced_fact_signature(
    consultation_kind: str | None,
    action: str,
    effect_neighborhood: frozenset[str],
) -> frozenset[str]:
    if consultation_kind is None:
        return frozenset()
    produced = {
        f"{predicate}|{term}|{action}"
        for predicate, term in _CONSULTATION_PRODUCES.get(consultation_kind, ())
    }
    if consultation_kind == "alternatives" and len(effect_neighborhood) == 1:
        effect = next(iter(effect_neighborhood))
        produced.discard(f"causes|effect|{action}")
        produced.add(f"causes|effect|{action}|{effect}")
    return frozenset(produced)


def _effect_neighborhood(deficit: Any) -> frozenset[str]:
    if deficit.axis == "classification":
        classification_term = _context_value(deficit, "classification_term")
        return frozenset({classification_term}) if classification_term else frozenset()
    if deficit.predicate_class == "causes" and len(deficit.subgoal.args) > 1:
        effect_term = deficit.subgoal.args[1]
        if not isinstance(effect_term, Variable):
            return frozenset({canonical_json(effect_term)})
    if deficit.predicate_class == "prevents":
        fields = _context_value(deficit, "variance_fields") or ""
        return frozenset(field for field in fields.split(",") if field)
    return frozenset()


def _consultation_kind(axis: str | None) -> str | None:
    return axis if axis in LLM_AXES else None


def _evidence_signature(deficit: Any) -> frozenset[str]:
    return frozenset(
        f"{name}={value}"
        for name in _EVIDENCE_CONTEXT_KEYS
        if (value := _context_value(deficit, name))
    )


@dataclass(frozen=True, slots=True)
class WorkItem:
    """S30 v2 derived projection over one coalesced grounding task.

    A work item is not a source of truth: it is derived from pending
    ``Deficit`` entries at planning time and carries the immutable graph
    snapshot it was planned against.  One work item can close many
    deficits (path fan-out, per-field gaps), and its ``deficit_ids`` ride
    along in consultation provenance so one model call stays traceable to
    every affected deficit.
    """

    work_item_id: str
    predicate_class: str
    action: str
    axis: str | None
    consultation_kind: str | None
    missing_fact_signature: frozenset[str]
    effect_neighborhood: frozenset[str]
    evidence_signature: frozenset[str]
    deficit_ids: tuple[str, ...]
    deficits: tuple[Any, ...]
    graph_snapshot: str
    fan_out: int
    order: int
    attempts: int = 0
    saturated: bool = False
    max_attempts: int = 3

    @property
    def dispatch_key(self) -> tuple[str, ...]:
        """Return the consultation identity of this work item."""

        return self.representative.work_item_key

    @property
    def representative(self) -> Any:
        """Return the deterministic deficit used for prompt context."""

        return self.deficits[0]

    @property
    def structural_priority(self) -> tuple[int, int, str]:
        """Return the deterministic fallback order (lower first)."""

        return (-self.fan_out, self.order, self.work_item_id)

    @property
    def requires_model(self) -> bool:
        """Return whether this work item consumes a model consultation slot."""

        return self.axis is not None and self.axis not in DETERMINISTIC_AXES


@dataclass(frozen=True, slots=True)
class WorkItemResult:
    """Queue outcome of one committed work item."""

    work_item_id: str
    closed_deficit_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class WorkItemGrounding:
    """Committed grounding result with its observation and any error.

    The wave committer constructs this on the owner thread after admission.
    Workers return untrusted proposals; ``result`` carries accepted facts.
    Queue closure is evaluated separately against each deficit's semantics.
    """

    work_item_id: str
    result: QdlGraph | None = None
    observation: Observation | None = None
    error: BaseException | None = None

    @property
    def promoted(self) -> bool:
        """Return whether the grounding call produced accepted facts."""

        return self.result is not None and bool(self.result.facts)


@dataclass(frozen=True, slots=True)
class WorkItemMerge:
    """Deterministic merge decision for one committed wave."""

    applied_order: tuple[str, ...]
    supersedes: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class WorkItemPropagation:
    """S30 stage-5 classification of pending deficits after one promotion."""

    work_item_id: str
    closed_deficit_ids: tuple[str, ...]
    stale_deficit_ids: tuple[str, ...]
    unchanged_count: int


@dataclass(frozen=True, slots=True)
class WorkItemWavePropagation:
    """S30 v3 closure of pending deficits after one whole wave merges."""

    work_item_ids: tuple[str, ...]
    closed_deficit_ids: tuple[str, ...]
    stale_deficit_ids: tuple[str, ...]
    unchanged_count: int


class WorkItemGraph:
    """Deterministic work-item planning graph (S30 v2, stdlib only).

    The graph is a planning projection, never a second formal engine:
    relations are derived from missing-fact/effect/evidence signatures
    with plain dicts and sets, cycles collapse into SCC macro work items,
    and waves contain only work items whose promotions commute on one
    immutable graph snapshot: dependent and conflicting items are always
    ordered, while fresh co-factorable/complementary items are serialized
    until the higher-priority one has been probed once.  Stage 5 (closure
    propagation and stale invalidation after wave commit) lives in
    ``DeficitQueue``; stage 6 (Clingo-based set-cover and budget
    optimization) remains out of scope.
    """

    def __init__(
        self,
        items: Sequence[Any],
        *,
        supplies: Mapping[str, frozenset[str]],
        needs: Mapping[str, frozenset[str]],
        relations: Mapping[frozenset[str], str],
        conflicts: frozenset[frozenset[str]],
        waves: tuple[tuple[Any, ...], ...],
        supersedes: tuple[tuple[str, str], ...],
    ) -> None:
        self._items = tuple(sorted(items, key=lambda item: item.work_item_id))
        self._by_id = {item.work_item_id: item for item in self._items}
        self._supplies = {
            item.work_item_id: tuple(sorted(supplies.get(item.work_item_id, ())))
            for item in self._items
        }
        self._needs = {
            item.work_item_id: tuple(sorted(needs.get(item.work_item_id, ())))
            for item in self._items
        }
        self._relations = dict(relations)
        self._conflicts = frozenset(conflicts)
        self._waves = waves
        self._supersedes = supersedes

    @classmethod
    def build(
        cls,
        items: Iterable[Any],
        *,
        dispatch_order: Sequence[str] = (),
    ) -> WorkItemGraph:
        """Derive relations, the dependency DAG, and parallel waves.

        ``dispatch_order`` carries the queue's dispatch priority (work-item
        ids, best first).  It orients serialization edges, SCC member
        order, and conflict supersedes decisions; without it the graph
        falls back to structural priority (fan-out, arrival, stable id).
        """

        ordered = tuple(sorted(items, key=lambda item: item.work_item_id))
        position = {
            work_item_id: index for index, work_item_id in enumerate(dispatch_order)
        }

        def orientation_rank(item: Any) -> tuple[int, ...]:
            if position:
                return (position.get(item.work_item_id, len(position)),)
            return (-item.fan_out, item.order, 0)

        produced = {
            item.work_item_id: _produced_fact_signature(
                item.consultation_kind,
                item.action,
                item.effect_neighborhood,
            )
            for item in ordered
        }
        supplies: dict[str, set[str]] = {item.work_item_id: set() for item in ordered}
        needs: dict[str, set[str]] = {item.work_item_id: set() for item in ordered}
        conflicts: set[frozenset[str]] = set()
        conflict_supersedes: list[tuple[str, str]] = []
        relations: dict[frozenset[str], str] = {}
        # Wave-ordering edges: ``a -> b`` schedules b strictly after a.
        blocking: dict[str, set[str]] = {item.work_item_id: set() for item in ordered}

        for first, second in combinations(ordered, 2):
            first_id = first.work_item_id
            second_id = second.work_item_id
            first_supplies = bool(produced[first_id] & second.missing_fact_signature)
            second_supplies = bool(produced[second_id] & first.missing_fact_signature)
            if first_supplies:
                supplies[first_id].add(second_id)
                needs[second_id].add(first_id)
                blocking[first_id].add(second_id)
            if second_supplies:
                supplies[second_id].add(first_id)
                needs[first_id].add(second_id)
                blocking[second_id].add(first_id)
            duplicate = first.dispatch_key == second.dispatch_key
            co_factorable_pair = bool(
                first.missing_fact_signature & second.missing_fact_signature
            )
            conflict_pair = (
                first.action == second.action
                and first.axis == second.axis
                and not duplicate
            )
            complementary_pair = bool(
                first.evidence_signature
                and first.evidence_signature == second.evidence_signature
            )
            pair = frozenset((first_id, second_id))
            dependent = first_supplies or second_supplies
            relations[pair] = _work_item_relation(
                duplicate=duplicate,
                co_factorable=co_factorable_pair,
                dependent=dependent,
                conflict=conflict_pair,
                complementary=complementary_pair,
            )
            if conflict_pair or co_factorable_pair or complementary_pair:
                winner, loser = sorted((first, second), key=orientation_rank)
                if conflict_pair:
                    conflicts.add(pair)
                    conflict_supersedes.append(
                        (winner.work_item_id, loser.work_item_id)
                    )
                # Dependencies already orient the pair. Otherwise conflicts
                # serialize it; shared unknowns/evidence serialize only until
                # the priority item has been probed once.
                if not dependent and (conflict_pair or winner.attempts == 0):
                    blocking[winner.work_item_id].add(loser.work_item_id)

        by_id = {item.work_item_id: item for item in ordered}
        layers = wave_layers(
            [item.work_item_id for item in ordered],
            blocking,
            lambda item_id: orientation_rank(by_id[item_id]),
        )
        waves = tuple(tuple(by_id[node] for node in layer) for layer in layers)
        return cls(
            ordered,
            supplies=supplies,
            needs=needs,
            relations=relations,
            conflicts=frozenset(conflicts),
            waves=waves,
            supersedes=tuple(sorted(conflict_supersedes)),
        )

    @property
    def items(self) -> tuple[Any, ...]:
        """Return every planned work item in stable id order."""

        return self._items

    @property
    def waves(self) -> tuple[tuple[Any, ...], ...]:
        """Return parallel waves; only wave members are independent."""

        return self._waves

    @property
    def supersedes(self) -> tuple[tuple[str, str], ...]:
        """Return deterministic conflict resolutions as id pairs."""

        return self._supersedes

    @property
    def conflict_pairs(self) -> tuple[frozenset[str], ...]:
        """Return work-item id pairs with potentially clashing outputs."""

        return tuple(sorted(self._conflicts, key=sorted))

    def relation(self, first_id: str, second_id: str) -> str:
        """Return the derived relation between two planned work items."""

        if first_id == second_id:
            return "duplicate"
        return self._relations.get(frozenset((first_id, second_id)), "independent")

    def supplies(self, work_item_id: str) -> tuple[str, ...]:
        """Return work items whose missing facts this item can produce."""

        return self._supplies.get(work_item_id, ())

    def needs(self, work_item_id: str) -> tuple[str, ...]:
        """Return work items whose outputs this item requires."""

        return self._needs.get(work_item_id, ())

    def first_wave(self) -> tuple[Any, ...]:
        """Return the first parallel wave of independent work items."""

        return self._waves[0] if self._waves else ()


def merge_work_item_results(
    work_items: Sequence[Any],
    outcomes: Mapping[str, Any],
    *,
    conflicts: Iterable[frozenset[str]] = (),
) -> Any:
    """Return the deterministic merge decision for one committed wave.

    Wave workers complete in arbitrary order; the campaign thread applies
    their outcomes by structural priority (fan-out first, then stable id),
    so queue state never depends on thread scheduling.  When conflicting
    work items both produced output, the structurally higher-priority item
    is authoritative and supersedes the other — a deterministic policy,
    never an LLM arbitration.
    """

    present = [item for item in work_items if item.work_item_id in outcomes]
    ordered = sorted(present, key=lambda item: item.structural_priority)
    conflict_pairs = {frozenset(pair) for pair in conflicts}
    supersedes = tuple(
        (winner.work_item_id, loser.work_item_id)
        for winner, loser in combinations(ordered, 2)
        if frozenset((winner.work_item_id, loser.work_item_id)) in conflict_pairs
        and outcomes[winner.work_item_id].promoted
        and outcomes[loser.work_item_id].promoted
    )
    return WorkItemMerge(
        tuple(item.work_item_id for item in ordered),
        supersedes,
    )


def _work_item_relation(
    *,
    duplicate: bool,
    co_factorable: bool,
    dependent: bool,
    conflict: bool,
    complementary: bool,
) -> str:
    """Classify one work-item pair by relation precedence."""

    if duplicate:
        return "duplicate"
    if conflict:
        return "conflict"
    if dependent:
        return "dependent"
    if co_factorable:
        return "co_factorable"
    if complementary:
        return "complementary"
    return "independent"


def single_deficit_work_item(
    deficit: Any,
    *,
    graph_snapshot: str = "",
) -> Any:
    """Wrap one deficit as a single-member work item.

    Compatibility projection for callers that hold one deficit outside the
    queue (for example direct grounding helpers and tests); the work-item
    id matches the id the queue derives for the same consultation, so
    recording results through this item reaches every queue entry that
    shares the deficit's consultation identity.
    """

    return WorkItem(
        work_item_id=_work_item_id(deficit.work_item_key),
        predicate_class=deficit.predicate_class,
        action=deficit.action,
        axis=deficit.axis,
        consultation_kind=_consultation_kind(deficit.axis),
        missing_fact_signature=_missing_fact_signature(deficit),
        effect_neighborhood=_effect_neighborhood(deficit),
        evidence_signature=_evidence_signature(deficit),
        deficit_ids=(deficit.consultation_id,),
        deficits=(deficit,),
        graph_snapshot=graph_snapshot,
        fan_out=1,
        order=0,
        attempts=0,
    )
