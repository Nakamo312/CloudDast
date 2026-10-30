"""Deterministic verdicts for parked classification lead norms."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_dast.model import PolicyVerdict, VerdictStatus
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    QdlGraph,
    Struct,
    canonical_json,
)
from cloud_dast.qdl.graph_ops import atom_value
from cloud_dast.verification.norms import (
    LEAD_NORM_PREFIX,
    NormView,
)


@dataclass(frozen=True, slots=True)
class Lead:
    """One parked classification suspicion with its deterministic verdict."""

    norm_id: str
    role: str
    effect: str
    verdict: PolicyVerdict

    @property
    def verdict_status(self) -> str:
        return self.verdict.status.value

    @property
    def rationale(self) -> str:
        return self.verdict.rationale


def evaluate(graph: QdlGraph | None) -> tuple[Lead, ...]:
    """Evaluate every lead norm carried by a runtime QDL graph."""

    if graph is None:
        return ()
    leads: list[Lead] = []
    for fact in graph.facts:
        if fact.context is not Context.PROPOSAL or fact.predicate.name != "prevents":
            continue
        norm_id = atom_value(fact.args[0]) if fact.args else None
        if norm_id is None or not norm_id.startswith(LEAD_NORM_PREFIX):
            continue
        try:
            view = NormView.from_lead_fact(fact)
        except ValueError:
            continue
        leads.append(
            Lead(
                norm_id=norm_id,
                role=read_role(view),
                effect=render_term(view.effect),
                verdict=PolicyVerdict(
                    status=VerdictStatus.UNSCOREABLE,
                    confidence=1.0,
                    rationale=(
                        f"protected role {read_role(view)!r} has no provenance; "
                        "the classification is parked as a lead for operator review"
                    ),
                    model_id="classification-lead",
                    deterministic=True,
                    grounded=False,
                ),
            )
        )
    return tuple(sorted(leads, key=lambda lead: lead.norm_id))


def read_role(norm: NormView) -> str:
    """Return the protected role encoded in one lead norm identifier."""

    norm_id = atom_value(norm.compiled.norm_fact.args[0])
    parts = (norm_id or "").split(":")
    if len(parts) == 4 and parts[2]:
        return parts[2]
    return "unknown"


def render_term(term: object) -> str:
    """Render one QDL term in the compact report notation."""

    if isinstance(term, Atom):
        return str(term.value)
    if isinstance(term, Struct):
        return f"{term.name}({', '.join(render_term(arg) for arg in term.args)})"
    return canonical_json(term)
