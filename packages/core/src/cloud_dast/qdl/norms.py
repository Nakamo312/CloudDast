"""Primitive vocabulary for executable QDL norms."""

from typing import Literal

Primitive = Literal[
    "outcome",
    "response_field",
    "differential",
    "oob_event",
    "latency_bound",
    "marker",
    "sequence",
    "unknown",
]

EFFECT_PRIMITIVES: dict[str, Primitive] = {
    "allowed": "outcome",
    "changed": "marker",
    "completed": "sequence",
    "denied": "outcome",
    "duration": "latency_bound",
    "external_call": "oob_event",
    "has": "response_field",
    "identity": "outcome",
    "reached": "marker",
    "transition": "sequence",
}

ORACLE_EFFECT_PRIMITIVES: dict[str, Primitive] = {
    **EFFECT_PRIMITIVES,
    "changed": "differential",
}

__all__ = ["EFFECT_PRIMITIVES", "ORACLE_EFFECT_PRIMITIVES", "Primitive"]
