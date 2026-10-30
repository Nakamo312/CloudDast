"""Interpret accepted and proposal QDL norms for deterministic verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from cloud_dast.model import AccessOutcome
from cloud_dast.qdl.graph import Atom, Context, Fact, Struct
from cloud_dast.qdl.norms import (
    EFFECT_PRIMITIVES,
    ORACLE_EFFECT_PRIMITIVES,
    Primitive,
)

if TYPE_CHECKING:
    from cloud_dast.contracts.plan import InvariantProjection


@dataclass(frozen=True, slots=True)
class NormCompilation:
    """One compiled `prevents(norm, effect)` fact."""

    primitive: Primitive
    evidence: tuple[str, ...]
    verdict_policy: str
    norm_fact: Fact

    @property
    def norm(self) -> Atom:
        return cast(Atom, self.norm_fact.args[0])

    @property
    def effect(self) -> Struct:
        return cast(Struct, self.norm_fact.args[1])


class NormCompiler:
    """Map a formal norm to the deterministic evidence it requires."""

    def compile(self, fact: Fact) -> NormCompilation:
        if fact.predicate.name != "prevents":
            raise ValueError("norm fact must use the prevents predicate")
        if fact.context is not Context.ACCEPTED:
            raise ValueError("norm fact must be in the accepted context")
        if len(fact.args) != 2:
            raise ValueError("prevents norm must have exactly two arguments")
        norm, effect = fact.args
        if not isinstance(norm, Atom):
            raise ValueError("norm identifier must be an atom")
        if not isinstance(effect, Struct):
            raise ValueError("norm effect must be a structural term")
        primitive, evidence = _compile_effect(effect)
        return NormCompilation(
            norm_fact=fact,
            primitive=primitive,
            evidence=evidence,
            verdict_policy=(
                "deterministic" if primitive != "unknown" else "unscoreable"
            ),
        )


def _compile_effect(effect: Struct) -> tuple[Primitive, tuple[str, ...]]:
    evidence: dict[str, tuple[str, ...]] = {
        "allowed": ("observed_outcome", "expected_outcome"),
        "changed": ("response_diff", "read_back"),
        "completed": ("trace", "flow_state"),
        "denied": ("observed_outcome", "expected_outcome"),
        "duration": ("duration_ms",),
        "external_call": ("oob_callback",),
        "has": ("response_field",),
        "identity": ("observed_outcome", "identity_binding"),
        "reached": ("trace", "sink_evidence"),
        "transition": ("trace", "state_before", "state_after"),
    }
    primitive = EFFECT_PRIMITIVES.get(effect.name, "unknown")
    if primitive == "unknown":
        return primitive, ("unsupported_effect",)
    return primitive, evidence[effect.name]


LEAD_NORM_PREFIX = "norm:lead:"


@dataclass(frozen=True, slots=True)
class NormView:
    """A compiled norm plus the terms needed by primitive oracles."""

    compiled: NormCompilation
    action_id: str | None
    expected_outcome: AccessOutcome | None
    forbidden_field: str | None
    marker: str | None
    duration_ms: float | None
    resource_id: str | None
    lead: bool = False

    @property
    def from_state(self) -> str | None:
        if self.effect_name != "transition" or len(self.effect.args) != 2:
            return None
        return _atom_text(self.effect.args[0])

    @property
    def to_state(self) -> str | None:
        if self.effect_name != "transition" or len(self.effect.args) != 2:
            return None
        return _atom_text(self.effect.args[1])

    @classmethod
    def from_invariant(
        cls,
        invariant: InvariantProjection,
        *,
        compiler: NormCompiler | None = None,
    ) -> NormView | None:
        if invariant.norm_fact is None:
            return None
        compiled = (compiler or NormCompiler()).compile(invariant.norm_fact)
        return cls.from_compiled(compiled)

    @classmethod
    def from_compiled(
        cls, compiled: NormCompilation, *, lead: bool = False
    ) -> NormView:
        effect = compiled.effect
        return cls(
            compiled=compiled,
            action_id=_action_id(effect),
            expected_outcome=_expected_outcome(effect),
            forbidden_field=_forbidden_field(effect),
            marker=_marker(effect),
            duration_ms=_duration_ms(effect),
            resource_id=_resource_id(effect),
            lead=lead,
        )

    @classmethod
    def from_lead_fact(cls, fact: Fact) -> NormView:
        """Compile one proposal-context norm suspicion for lead evaluation."""

        if fact.context is not Context.PROPOSAL:
            raise ValueError("lead norm fact must be in the proposal context")
        if fact.predicate.name != "prevents" or len(fact.args) != 2:
            raise ValueError("lead norm fact must be a two-argument prevents fact")
        norm, effect = fact.args
        if not isinstance(norm, Atom) or not isinstance(norm.value, str):
            raise ValueError("norm identifier must be a string atom")
        if not norm.value.startswith(LEAD_NORM_PREFIX):
            raise ValueError("norm identifier must use the lead prefix")
        if not isinstance(effect, Struct):
            raise ValueError("compiled norm effect must be a structural term")
        return cls.from_compiled(
            NormCompilation(
                primitive=ORACLE_EFFECT_PRIMITIVES.get(effect.name, "unknown"),
                evidence=("classification_provenance",),
                verdict_policy="unscoreable",
                norm_fact=fact,
            ),
            lead=True,
        )

    @property
    def primitive(self) -> Primitive:
        return ORACLE_EFFECT_PRIMITIVES.get(self.effect_name, self.compiled.primitive)

    @property
    def effect(self) -> Struct:
        return self.compiled.effect

    @property
    def effect_name(self) -> str:
        return self.effect.name


def _action_id(effect: Struct) -> str | None:
    if effect.name == "identity":
        return None
    if effect.name in {"allowed", "denied", "duration", "external_call", "reached"}:
        return _atom_text(effect.args[0])
    return None


def _expected_outcome(effect: Struct) -> AccessOutcome | None:
    if effect.name in {"allowed", "identity"}:
        return AccessOutcome.DENIED
    if effect.name == "denied":
        return AccessOutcome.ALLOWED
    return None


def _forbidden_field(effect: Struct) -> str | None:
    if effect.name == "changed":
        return _atom_text(effect.args[1])
    if effect.name != "has":
        return None
    value = effect.args[1]
    if isinstance(value, Struct) and value.name == "field":
        return _atom_text(value.args[1])
    return _atom_text(value)


def _marker(effect: Struct) -> str | None:
    if effect.name in {"external_call", "reached"}:
        return _atom_text(effect.args[1])
    return None


def _duration_ms(effect: Struct) -> float | None:
    if effect.name != "duration":
        return None
    value = effect.args[1]
    if not isinstance(value, Atom) or not isinstance(value.value, int):
        return None
    return float(value.value)


def _resource_id(effect: Struct) -> str | None:
    if effect.name == "changed":
        return _atom_text(effect.args[0])
    if effect.name != "has":
        return None
    value = effect.args[1]
    if isinstance(value, Struct) and value.name == "field":
        return _atom_text(value.args[0])
    return None


def _atom_text(term: object) -> str | None:
    if isinstance(term, Atom) and isinstance(term.value, str):
        return term.value
    return None


__all__ = [
    "EFFECT_PRIMITIVES",
    "ORACLE_EFFECT_PRIMITIVES",
    "NormCompilation",
    "NormCompiler",
    "Primitive",
    "LEAD_NORM_PREFIX",
    "NormView",
]
