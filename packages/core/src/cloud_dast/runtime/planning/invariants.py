"""Compile accepted QDL norms into executable invariant views."""

from __future__ import annotations

from cloud_dast.qdl.graph import Context, QdlGraph, canonical_json
from cloud_dast.qdl.reasoning import QdlInvariant
from cloud_dast.verification.norms import NormCompiler


def compile_invariants(
    graph: QdlGraph,
    compiler: NormCompiler,
) -> tuple[QdlInvariant, ...]:
    """Compile accepted ``prevents`` facts into executable oracle views."""

    invariants: list[QdlInvariant] = []
    for fact in graph.facts:
        if fact.context is not Context.ACCEPTED:
            continue
        if fact.predicate.name != "prevents":
            continue

        compilation = compiler.compile(fact)
        invariants.append(
            QdlInvariant(
                norm=compilation.norm.value,
                effect=compilation.effect,
                primitive=compilation.primitive,
                required_evidence=compilation.evidence,
                verdict_policy=compilation.verdict_policy,
                fact=fact,
            )
        )

    return tuple(
        sorted(
            invariants,
            key=lambda invariant: (
                invariant.norm,
                canonical_json(invariant.effect),
            ),
        )
    )
