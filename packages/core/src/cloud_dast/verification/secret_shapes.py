"""Deterministic verification leads for secret-shaped response values.

The promotion policy keeps protected classifications out of LLM hands: a role
like ``credential`` must come from the source graph or from an actually
observed response field.  This module is the strongest form of that evidence
policy: when a response value *looks like* a secret by shape — a JWT, a PEM
private key, an argon2/bcrypt hash, an AWS access key — the classification is
compiled deterministically as a **lead**: a parked proposal fact for operator
review.  Shape matches are hypotheses, not verified classifications — under
the deterministic oracle an auto-promoted noisy sensor would fabricate
findings — so secret shapes never auto-promote.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    canonical_json,
    output_field,
)
from cloud_dast.verification.evidence import View

_SECRET_SHAPES: tuple[re.Pattern[str], ...] = (
    re.compile(r"^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\."),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"^\$argon2(id|i|d)\$"),
    re.compile(r"^\$2[aby]\$"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


def secret_shape_graph(
    action_ids: tuple[str, ...],
    evidence: View | None,
) -> QdlGraph | None:
    """Produce proposal leads from single-action values matching secret shapes."""

    if evidence is None or len(action_ids) != 1:
        return None
    action_id = action_ids[0]
    action = action_id if action_id.startswith("action:") else f"action:{action_id}"
    facts: list[Fact] = [
        Fact(
            context=Context.PROPOSAL,
            predicate=Predicate.from_name("is"),
            args=(Atom(value=action), Atom(value="Action")),
        )
    ]
    seen: set[str] = set()
    for path, value in _response_leaf_values(evidence.data):
        if not isinstance(value, str):
            continue
        if not any(shape.search(value) for shape in _SECRET_SHAPES):
            continue
        holder = output_field(Atom(value=action), Atom(value=path))
        facts.append(
            Fact(
                context=Context.PROPOSAL,
                predicate=Predicate.from_name("is"),
                args=(holder, Atom(value="OutputField")),
            )
        )
        fact = Fact(
            context=Context.PROPOSAL,
            predicate=Predicate.from_name("has"),
            args=(holder, Atom(value="credential")),
        )
        key = canonical_json(fact)
        if key in seen:
            continue
        seen.add(key)
        facts.append(fact)
    if len(facts) == 1:
        return None
    return QdlGraph(facts=tuple(facts))


def _response_leaf_values(data: Mapping[str, Any]) -> list[tuple[str, Any]]:
    """Collect every response leaf as an observed ``(path, value)`` pair."""

    leaves: list[tuple[str, Any]] = []
    _collect_leaf_values(data, leaves)
    return leaves


def _collect_leaf_values(
    value: object,
    leaves: list[tuple[str, Any]],
) -> None:
    if isinstance(value, Mapping):
        candidate = value.get("leaves")
        if isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes)):
            for leaf in candidate:
                if (
                    isinstance(leaf, Mapping)
                    and isinstance(leaf.get("path"), str)
                    and "value" in leaf
                ):
                    leaves.append((leaf["path"], leaf["value"]))
        for child in value.values():
            _collect_leaf_values(child, leaves)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for child in value:
            _collect_leaf_values(child, leaves)
