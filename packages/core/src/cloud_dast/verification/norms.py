"""Compile formal norms into deterministic oracle requirements."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from cloud_dast.qdl.graph import Atom, Context, Fact, Struct
from cloud_dast.qdl.norms import (
    EFFECT_PRIMITIVES,
    ORACLE_EFFECT_PRIMITIVES,
    Primitive,
)


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


__all__ = [
    "EFFECT_PRIMITIVES",
    "ORACLE_EFFECT_PRIMITIVES",
    "NormCompilation",
    "NormCompiler",
    "Primitive",
]
