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
from cloud_dast.verification.norm_view import (
    LEAD_NORM_PREFIX,
    NormView,
)


@dataclass(frozen=True, slots=True)
class ClassificationLead:
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


class ClassificationLeadOracle:
    """Score classification suspicions without executing or promoting them."""

    def evaluate(self, norm: NormView) -> PolicyVerdict:
        """Return the deterministic verdict for one lead norm."""

        if not norm.lead:
            return self._unscoreable("norm is not a classification lead")
        return self._unscoreable(
            f"protected role {lead_role(norm)!r} has no provenance; "
            "the classification is parked as a lead for operator review"
        )

    @staticmethod
    def _unscoreable(rationale: str) -> PolicyVerdict:
        return PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=1.0,
            rationale=rationale,
            model_id="classification-lead",
            deterministic=True,
            grounded=False,
        )


def evaluate_classification_leads(
    graph: QdlGraph | None,
    *,
    oracle: ClassificationLeadOracle | None = None,
) -> tuple[ClassificationLead, ...]:
    """Evaluate every lead norm carried by a runtime QDL graph."""

    if graph is None:
        return ()
    lead_oracle = oracle or ClassificationLeadOracle()
    leads: list[ClassificationLead] = []
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
            ClassificationLead(
                norm_id=norm_id,
                role=lead_role(view),
                effect=term_text(view.effect),
                verdict=lead_oracle.evaluate(view),
            )
        )
    return tuple(sorted(leads, key=lambda lead: lead.norm_id))


def lead_role(norm: NormView) -> str:
    """Return the protected role encoded in one lead norm identifier."""

    norm_id = atom_value(norm.compiled.norm_fact.args[0])
    parts = (norm_id or "").split(":")
    if len(parts) == 4 and parts[2]:
        return parts[2]
    return "unknown"


def term_text(term: object) -> str:
    """Render one QDL term in the compact report notation."""

    if isinstance(term, Atom):
        return str(term.value)
    if isinstance(term, Struct):
        return f"{term.name}({', '.join(term_text(arg) for arg in term.args)})"
    return canonical_json(term)
