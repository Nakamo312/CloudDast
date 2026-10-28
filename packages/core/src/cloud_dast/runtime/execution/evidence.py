"""Evidence-derived identity for one executable QDL path."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

from cloud_dast.binding import scenario_scope
from cloud_dast.candidates import resolve_check_identities
from cloud_dast.couplings import normalise_action
from cloud_dast.qdl.graph import (
    CAUSAL_EFFECT_CONSTRUCTORS,
    Context,
    QdlGraph,
    Struct,
    canonical_json,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.runtime.execution.contracts import QdlExecutionPath
from cloud_dast.runtime.planning import derive_requirements
from cloud_dast.verification.projection import (
    read_observed_effects,
    read_observed_references,
)


class PathSignature:
    """Fingerprint currently usable witnesses while preserving joint bindings."""

    def __init__(
        self,
        observed_graph: Callable[[QdlExecutionPath], QdlGraph],
    ) -> None:
        self._observed_graph = observed_graph
        self._queries: dict[tuple[str, tuple[str, ...]], tuple] = {}

    def build(self, path: QdlExecutionPath) -> str | None:
        """Return a stable identity for evidence relevant to ``path``."""

        if not any(step.evidence_graph is not None for step in path.steps):
            return None
        graph = self._observed_graph(path)
        actions = {step.method.method_id for step in path.steps}
        required = {
            term
            for action, term in derive_requirements(
                graph, contexts={Context.CONTRACT, Context.ACCEPTED}
            )
            if (identifier := atom_value(action)) is not None
            and normalise_action(identifier) in actions
            and isinstance(term, Struct)
            and term.name in CAUSAL_EFFECT_CONSTRUCTORS
        }
        fields = set()
        for step in path.steps:
            required.update(step.required_effects)
            norm = step.invariant.norm_fact
            if norm is not None and isinstance(norm.args[1], Struct):
                required.add(norm.args[1])
            fields.update(
                endpoint
                for left, right, _ in step.plan.couplings
                for endpoint in (left, right)
            )
        contexts, records = set(), []
        for step in path.steps:
            try:
                identities = resolve_check_identities(step.plan, step.scenario)
            except ValueError:
                return None
            scope = scenario_scope(step.scenario)
            context = (scope, identities)
            if context in contexts:
                continue
            contexts.add(context)
            by_observation = {}
            cached = self._queries.get(context)
            if cached is not None and cached[0] == graph.content_hash:
                _, references, proofs = cached
            else:
                try:
                    references = read_observed_references(
                        graph,
                        scope=scope,
                        identities=identities,
                    )
                    proofs = read_observed_effects(
                        graph,
                        scope=scope,
                        identities=identities,
                    )
                except RuntimeError:
                    return None
                self._queries[context] = (
                    graph.content_hash,
                    references,
                    proofs,
                )
            for obs, witness, resource_type, value, _, _ in references:
                by_observation.setdefault(obs, set()).add(
                    (witness, resource_type, value)
                )
            values = {
                tuple(sorted(canonical_json(row) for row in rows if row[0] in fields))
                for rows in by_observation.values()
            } - {()}
            effects = {
                (
                    canonical_json(fact.args[1]),
                    tuple(
                        sorted(
                            {
                                canonical_json((resource_type, value))
                                for _, resource_type, value in by_observation.get(
                                    fact.args[0], ()
                                )
                            }
                        )
                    ),
                )
                for fact, _, _ in proofs
                if fact.args[1] in required
            }
            records.append((*context, sorted(values), sorted(effects)))
        payload = json.dumps(sorted(records), ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()


__all__ = ["PathSignature"]
