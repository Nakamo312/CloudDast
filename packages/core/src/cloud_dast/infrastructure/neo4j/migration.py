"""Migration of the pre-QDL threat-model data left in the graph store.

The old STRIDE/ThreatGraph pipeline was removed from the codebase, but its
nodes remained in Neo4j.  This service makes that legacy explicit: report
it, mark it with a ``Legacy`` label, or purge it.  Nothing in the current
engine reads or writes these labels.
"""

from __future__ import annotations

LEGACY_LABELS: tuple[str, ...] = (
    "ThreatGraph",
    "Goal",
    "Path",
    "Step",
    "Threat",
    "Invariant",
    "Version",
    "DfdElement",
    "StrideAnnotation",
    "Finding",
)


class LegacyThreatModelMigration:
    """Report, mark, or purge old-world threat-model nodes."""

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    def report(self) -> dict[str, int]:
        """Count legacy nodes per label without changing anything."""

        counts: dict[str, int] = {}
        with self._session_factory() as session:
            for label in LEGACY_LABELS:
                result = session.run(f"MATCH (n:{label}) RETURN count(n) AS count")
                counts[label] = result.single()["count"]
        return counts

    def mark_legacy(self) -> dict[str, int]:
        """Label every legacy node with ``Legacy`` (reversible)."""

        counts = self.report()
        with self._session_factory() as session:
            for label in LEGACY_LABELS:
                if counts[label]:
                    session.run(
                        f"MATCH (n:{label}) WHERE NOT n:Legacy SET n:Legacy"
                    ).consume()
        return counts

    def purge_legacy(self) -> dict[str, int]:
        """Detach and delete every node marked ``Legacy`` (destructive)."""

        counts = self.report()
        with self._session_factory() as session:
            session.run("MATCH (n:Legacy) DETACH DELETE n").consume()
        return counts
