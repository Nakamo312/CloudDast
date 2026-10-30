"""Application contracts and selection rules for differential discovery."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal, Protocol, get_args

from cloud_dast.model import (
    Check,
    MethodSpec,
    Observation,
    ScenarioPosition,
    ScenarioProfile,
)
from cloud_dast.model.events import action_aliases
from cloud_dast.qdl.field_roles import FieldRolePolicy
from cloud_dast.qdl.graph import Context, QdlGraph, Struct
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.verification.differential.modes import (
    MUTABLE_INPUT_ROLES,
)

ProfileFactor = Literal[
    "scope_relation",
    "binding_level",
    "endpoint_layer",
    "resource_state",
    "identity_class",
    "addressing_mode",
]

_PROFILE_FACTORS: tuple[ProfileFactor, ...] = get_args(ProfileFactor)


@dataclass(frozen=True, slots=True)
class Spec:
    """A control/treatment scenario pair varying exactly one profile factor.

    The stands may differ in the parts the factor governs — another principal
    for ``identity_class``, another resource for ``resource_state`` — so only
    the six profile factors are validated component by component.
    """

    control: ScenarioPosition
    treatment: ScenarioPosition

    def __post_init__(self) -> None:
        differing = self._differing_factors()
        if not differing:
            raise ValueError(
                "differential scenarios must differ in exactly one profile "
                "factor; the profiles are equivalent"
            )
        if len(differing) > 1:
            raise ValueError(
                "differential scenarios must differ in exactly one profile "
                f"factor; found {len(differing)}: {', '.join(differing)}"
            )

    @property
    def factor(self) -> ProfileFactor:
        """The single profile factor that differs between the two legs."""

        return self._differing_factors()[0]

    def _differing_factors(self) -> tuple[ProfileFactor, ...]:
        return tuple(
            factor
            for factor, control, treatment in zip(
                _PROFILE_FACTORS,
                _profile_factors(self.control.profile),
                _profile_factors(self.treatment.profile),
                strict=True,
            )
            if control != treatment
        )


def _profile_factors(profile: ScenarioProfile) -> tuple[object, ...]:
    """Return dimensions relevant to one differential comparison."""

    return tuple(getattr(profile, factor) for factor in _PROFILE_FACTORS)


@dataclass(frozen=True, slots=True)
class PayloadPairSpec:
    """A baseline/mutated-payload pair for one method and scenario.

    Unlike :class:`Spec` the legs do not vary a scenario
    profile factor: both run the same method, as the same principal,
    against the same stand — only the request payload differs.  The class
    validates the pairing contract (one method, one scenario, identical
    identities, different requests); how the treatment payload is produced
    is the job of :meth:`from_baseline`.
    """

    method: MethodSpec
    scenario: ScenarioPosition
    baseline: Check
    treatment: Check

    def __post_init__(self) -> None:
        for role, candidate in (
            ("baseline", self.baseline),
            ("treatment", self.treatment),
        ):
            if candidate.method_id != self.method.method_id:
                raise ValueError(f"{role} check does not belong to the paired method")
            if candidate.scenario_id != self.scenario.scenario_id:
                raise ValueError(f"{role} check does not belong to the paired scenario")
        if self.baseline.identities != self.treatment.identities:
            raise ValueError(
                "payload pair legs must run as the same identities; "
                "identity variation belongs to factor pairs"
            )
        if self.baseline.request == self.treatment.request:
            raise ValueError("payload pair legs must differ in request")

    @classmethod
    def from_baseline(
        cls,
        method: MethodSpec,
        scenario: ScenarioPosition,
        baseline: Check,
        *,
        canary: str,
        mutable_fields: Iterable[str],
    ) -> PayloadPairSpec:
        """Build the pair by materializing payload fields on both legs.

        Mutable fields come from role-resolved selection: the caller passes
        the fields chosen from explicit ``payload`` / ``mutable_input`` facts.
        They receive a benign, unquoted value on the baseline leg and the
        canary wrapped in single quotes on the treatment leg — the same
        literal-breaking form the marker generator uses, so interpreter
        grammars (SQL, templates, expression languages) surface the canary
        through their error channel while storage sinks echo it verbatim.
        Fields without a mutable role are never mutated: the pair varies what
        the request carries, not what it addresses.
        """

        fields = {field.name: field for field in method.request_schema.fields}
        mutable = set(mutable_fields)
        benign: list[tuple[str, object]] = []
        mutated: list[tuple[str, object]] = []
        for name, value in baseline.request:
            field = fields.get(name)
            if field is not None and name in mutable:
                benign.append((name, f"benign-{canary}"))
                mutated.append((name, f"'{canary}'"))
            else:
                benign.append((name, value))
                mutated.append((name, value))
        return cls(
            method=method,
            scenario=scenario,
            baseline=baseline.model_copy(update={"request": tuple(benign)}),
            treatment=baseline.model_copy(
                update={
                    "request": tuple(mutated),
                    "generator": "fuzzing",
                    "probe_marker": canary,
                },
            ),
        )


@dataclass(frozen=True, slots=True)
class IsolatedStandPolicy:
    """Explicit policy for a write leg against an isolated stand.

    The deployment must guarantee that the addressed stand is disposable.  The
    marker requirement keeps an unmarked shared-stand write from entering the
    read-back boundary by accident.
    """

    def validate_write_check(self, check: Check) -> None:
        if check.probe_marker is None:
            raise ValueError("isolated read-back requires a marked write check")


@dataclass(frozen=True, slots=True)
class ReadBackSpec:
    """One write/read-back pairing over a shared resource type.

    ``write_method`` is the create/update-like action whose state effect
    is measured; ``read_method`` is the non-mutating action used to read
    the resource back; ``resource_binding`` is the read request field that
    carries the resource id (for example ``order_id``).  See
    :func:`select_read_method` for how the read method is chosen.
    """

    write_method: MethodSpec
    read_method: MethodSpec
    resource_binding: str
    mutable_fields: tuple[str, ...]
    read_resource_types: tuple[tuple[str, str], ...] = ()
    """Grounded (field, resource type) pairs carried by the read legs."""

    def __post_init__(self) -> None:
        if self.write_method.method_id == self.read_method.method_id:
            raise ValueError("read-back write and read methods must differ")
        if self.resource_binding not in {
            field.name for field in self.read_method.request_schema.fields
        }:
            raise ValueError(
                "read-back resource binding must be a field of the read method"
            )


@dataclass(frozen=True, slots=True)
class ReadBackResult:
    """Executed legs of one read-before / write / read-after triple.

    The checks are the executed (possibly output-forwarded) variants; the
    read-after check carries the resource id resolved from the write
    response.
    """

    write_check: Check
    read_before_check: Check
    read_after_check: Check
    write: Observation
    read_before: Observation
    read_after: Observation


@dataclass(frozen=True, slots=True)
class ConcurrencyResult:
    """Executed read-before / parallel probes / read-after evidence."""

    read_before: tuple[Check, Observation] | None
    read_after: tuple[Check, Observation] | None
    probes: tuple[tuple[Check, Observation], ...]


class EvidenceView(Protocol):
    """Read-only evidence boundary consumed by verification decisions."""

    def iter_readbacks(
        self,
    ) -> Iterable[tuple[tuple[str, ...], ReadBackResult]]: ...

    def get_concurrency(
        self,
        key: tuple[str, ...],
    ) -> ConcurrencyResult | None: ...


def payload_fields(
    method: MethodSpec,
    field_roles: FieldRolePolicy,
) -> tuple[str, ...]:
    """Return input fields explicitly declared as mutable payload.

    Mutation is a closed role decision: only a contract or accepted
    ``has(input_field(action, field), payload | mutable_input)`` fact makes a
    field mutable, so a pair varies what the request carries only when the
    graph says so.  A field without any role fact is unknown — it is never
    mutated, and the caller reports a typed deficit instead of guessing from
    names, types, or values.
    """

    return tuple(
        field.name
        for field in method.request_schema.fields
        if field_roles.roles(
            method.method_id,
            field.name,
            direction="input",
        )
        & MUTABLE_INPUT_ROLES
    )


def payload_canary(method_id: str) -> str:
    """Return the deterministic payload canary for one action.

    The canary is stable across runs so re-measuring the same action
    produces the same variance signature and deficit deduplication key.
    It is a single token without separators so interpreters that quote the
    offending token in error messages (for example SQLite) echo the whole
    canary back instead of truncating at the first separator.
    """

    digest = hashlib.sha256(method_id.encode("utf-8")).hexdigest()[:12]
    return f"dastpayload{digest}"


_READBACK_ROLE = "readback"
_RESOURCE_REF_ROLE = "object_ref"
_EXECUTABLE_CONTEXTS = frozenset({Context.CONTRACT, Context.ACCEPTED})
_MUTATING_EFFECTS = frozenset({"changed", "create", "remove"})


def select_read_method(
    write_method: MethodSpec,
    methods: Iterable[MethodSpec],
    *,
    graph: QdlGraph,
) -> MethodSpec | None:
    """Select the non-mutating read-back method for one write action.

    Selection contract (RFC §9.1 before/after read-back):

    1. A candidate carries the explicit ``has(action, readback)`` role.
    2. A candidate is excluded when the QDL graph declares
       ``causes(action, changed|create|remove)`` for it.
    3. The write and candidate share a resource declared by
       ``targets(action, resource)``, and the candidate's request field is
       grounded by both ``has(input_field(action, field), object_ref)`` and
       ``refers_to(input_field(action, field), resource)``.
    4. A read candidate that exposes more of the write's mutable fields is
       preferred.  This keeps a general resource reader ahead of an
       alphabetically earlier specialized reader (for example, a notification
       getter ahead of the order reader that exposes ``total``/``note``).
    5. Candidates are ordered by exposure and then method id, so selection is
       deterministic.
    """

    readback_actions = _readback_actions(graph)
    mutating = _mutating_actions(graph)
    candidates = [
        method
        for method in methods
        if method.method_id != write_method.method_id
        and action_aliases(method.method_id) & readback_actions
        and not (action_aliases(method.method_id) & mutating)
        and read_resource_binding(write_method, method, graph=graph) is not None
    ]
    return next(
        iter(
            sorted(
                candidates,
                key=lambda method: (
                    -_exposed_write_field_overlap(write_method, method, graph),
                    method.method_id,
                ),
            )
        ),
        None,
    )


def _readback_actions(graph: QdlGraph) -> frozenset[str]:
    actions: set[str] = set()
    for fact in graph.facts_for("has", contexts=_EXECUTABLE_CONTEXTS):
        if len(fact.args) != 2:
            continue
        action = atom_value(fact.args[0])
        role = atom_value(fact.args[1])
        if action is not None and role == _READBACK_ROLE:
            actions.update(action_aliases(action))
    return frozenset(actions)


def _action_targets(graph: QdlGraph, method_id: str) -> frozenset[str]:
    aliases = action_aliases(method_id)
    targets: set[str] = set()
    for fact in graph.facts_for("targets", contexts=_EXECUTABLE_CONTEXTS):
        if len(fact.args) != 2:
            continue
        action = atom_value(fact.args[0])
        resource = atom_value(fact.args[1])
        if action in aliases and isinstance(resource, str):
            targets.add(resource)
    return frozenset(targets)


def _object_ref_fields(graph: QdlGraph, method_id: str) -> frozenset[str]:
    aliases = action_aliases(method_id)
    fields: set[str] = set()
    for fact in graph.facts_for("has", contexts=_EXECUTABLE_CONTEXTS):
        if len(fact.args) != 2:
            continue
        term, role = fact.args
        if atom_value(role) != _RESOURCE_REF_ROLE or not isinstance(term, Struct):
            continue
        if term.name != "input_field" or len(term.args) != 2:
            continue
        action = atom_value(term.args[0])
        field = atom_value(term.args[1])
        if action in aliases and isinstance(field, str):
            fields.add(field)
    return frozenset(fields)


def _exposed_write_field_overlap(
    write_method: MethodSpec,
    read_method: MethodSpec,
    graph: QdlGraph,
) -> int:
    """Count write fields observable through one read candidate."""

    write_fields = {
        field.name.rsplit(".", 1)[-1] for field in write_method.request_schema.fields
    }
    read_action = f"action:{read_method.method_id}"
    exposed: set[str] = set()
    for fact in graph.facts_for("exposes", contexts=_EXECUTABLE_CONTEXTS):
        if len(fact.args) != 2:
            continue
        action, witness = fact.args
        if action.value not in {read_method.method_id, read_action}:
            continue
        if not isinstance(witness, Struct) or witness.name != "field":
            continue
        if len(witness.args) != 2:
            continue
        name = witness.args[1].value
        if isinstance(name, str):
            exposed.add(name.rsplit(".", 1)[-1])
    return len(write_fields & exposed)


def read_resource_binding(
    write_method: MethodSpec,
    read_method: MethodSpec,
    *,
    graph: QdlGraph,
) -> str | None:
    """Return the read field grounded as a reference to the shared resource."""

    reference = read_resource_reference(write_method, read_method, graph=graph)
    return None if reference is None else reference[0]


def read_resource_reference(
    write_method: MethodSpec,
    read_method: MethodSpec,
    *,
    graph: QdlGraph,
) -> tuple[str, str] | None:
    """Return the read field and its grounded shared resource type."""

    shared_resources = _action_targets(graph, write_method.method_id) & (
        _action_targets(graph, read_method.method_id)
    )
    object_refs = _object_ref_fields(graph, read_method.method_id)
    field_names = {field.name for field in read_method.request_schema.fields}
    read_aliases = action_aliases(read_method.method_id)
    for resource in sorted(shared_resources):
        for field in sorted(object_refs & field_names):
            if _refers_to_resource(graph, read_aliases, field, resource):
                return field, resource.removeprefix("resource:")
    return None


def _refers_to_resource(
    graph: QdlGraph,
    action_aliases: frozenset[str],
    field: str,
    resource: str,
) -> bool:
    for fact in graph.facts_for("refers_to", contexts=_EXECUTABLE_CONTEXTS):
        if len(fact.args) != 2:
            continue
        field_term, target = fact.args
        if not isinstance(field_term, Struct):
            continue
        if field_term.name != "input_field" or len(field_term.args) != 2:
            continue
        action = atom_value(field_term.args[0])
        field_name = atom_value(field_term.args[1])
        target_resource = atom_value(target)
        if (
            action in action_aliases
            and field_name == field
            and target_resource == resource
        ):
            return True
    return False


def _mutating_actions(graph: QdlGraph) -> frozenset[str]:
    mutating: set[str] = set()
    for fact in graph.facts_for("causes", contexts=_EXECUTABLE_CONTEXTS):
        if len(fact.args) != 2:
            continue
        action = atom_value(fact.args[0])
        effect = fact.args[1]
        if action is None or not isinstance(effect, Struct):
            continue
        if effect.name not in _MUTATING_EFFECTS:
            continue
        mutating.update(action_aliases(action))
    return frozenset(mutating)
