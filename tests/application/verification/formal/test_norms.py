from __future__ import annotations

import pytest

from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    allowed,
    changed,
    completed,
    denied,
    duration,
    external_call,
    has,
    identity,
    reached,
    transition,
)
from cloud_dast.verification.norms import NormCompiler


def prevents(effect) -> Fact:
    return Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name("prevents"),
        args=(Atom(value="norm:test"), effect),
    )


@pytest.mark.parametrize(
    ("effect", "primitive"),
    [
        (allowed(Atom(value="action:a")), "outcome"),
        (changed(Atom(value="resource:r"), Atom(value="role")), "marker"),
        (completed(Atom(value="flow:f")), "sequence"),
        (denied(Atom(value="action:a")), "outcome"),
        (duration(Atom(value="action:a"), Atom(value=100)), "latency_bound"),
        (external_call(Atom(value="action:a"), Atom(value="marker:m")), "oob_event"),
        (has(Atom(value="principal:p"), Atom(value="secret")), "response_field"),
        (identity(Atom(value="attacker"), Atom(value="victim")), "outcome"),
        (reached(Atom(value="action:a"), Atom(value="sink:s")), "marker"),
        (transition(Atom(value="created"), Atom(value="approved")), "sequence"),
    ],
)
def test_norm_compiler_maps_supported_effects(effect, primitive) -> None:
    compilation = NormCompiler().compile(prevents(effect))

    assert compilation.primitive == primitive
    assert compilation.verdict_policy == "deterministic"
    assert compilation.evidence


def test_norm_compiler_requires_complete_transition_state_evidence() -> None:
    compilation = NormCompiler().compile(
        prevents(transition(Atom(value="created"), Atom(value="approved")))
    )

    assert compilation.primitive == "sequence"
    assert compilation.evidence == ("trace", "state_before", "state_after")
    assert compilation.verdict_policy == "deterministic"


def test_norm_compiler_rejects_non_prevents_fact() -> None:
    fact = Fact(
        context=Context.ACCEPTED,
        predicate=Predicate.from_name("requires"),
        args=(Atom(value="action:a"), Atom(value="permission:p")),
    )

    with pytest.raises(ValueError, match="prevents predicate"):
        NormCompiler().compile(fact)


def test_norm_compiler_rejects_non_accepted_context() -> None:
    fact = Fact(
        context=Context.PROPOSAL,
        predicate=Predicate.from_name("prevents"),
        args=(Atom(value="norm:n"), changed(Atom(value="r"), Atom(value="f"))),
    )

    with pytest.raises(ValueError, match="accepted context"):
        NormCompiler().compile(fact)
