from __future__ import annotations

from cloud_dast.contracts.plan import InvariantProjection
from cloud_dast.model import (
    Observation,
    OracleDeficit,
    PolicyVerdict,
    ScenarioPosition,
    VerdictStatus,
)
from cloud_dast.qdl.graph import Atom
from cloud_dast.verification.norms import NormView
from cloud_dast.verification.oracles.action_alignment import (
    explain_mismatch,
)
from cloud_dast.verification.oracles.trace import ObservationTrace
from cloud_dast.verification.witness import response_is_incomplete


class Oracle:
    """Primitive P2: compare full response fields with a QDL visibility norm."""

    def evaluate_policy(
        self,
        invariant: InvariantProjection,
        trace: ObservationTrace,
        *,
        scenario: ScenarioPosition | None = None,
        method_id: str | None = None,
    ) -> PolicyVerdict:
        norm = NormView.from_invariant(invariant)
        if norm is None or norm.primitive != "response_field":
            return self._unscoreable("invariant is not a response-field QDL norm")
        mismatch = explain_mismatch(norm.action_id, method_id)
        if mismatch is not None:
            return self._unscoreable(mismatch)
        # Principal scoping follows alignment: an inapplicable method must not
        # become a vacuous PASS merely because the probe ran as another principal.
        if norm.forbidden_field is None:
            return self._unscoreable("response-field QDL norm has no field")
        if not trace:
            return self._unscoreable("response-field QDL norm has no observation")

        scoped_to = _possession_holder(norm.effect)
        if scoped_to is not None:
            if scenario is None:
                return self._unscoreable(
                    "possession norm requires a scenario to resolve its principal scope",
                    deficits=(
                        OracleDeficit(
                            kind="principal_scope",
                            action_id=norm.action_id,
                            context=(
                                ("principal", scoped_to),
                                ("field", norm.forbidden_field),
                            ),
                            rationale="scenario principal scope is unavailable",
                        ),
                    ),
                )
            if not _scenario_runs_principal(scenario, scoped_to):
                rationale = (
                    "possession norm is scoped to principal "
                    f"{scoped_to!r}; this probe runs as another principal"
                )
                return self._unscoreable(
                    rationale,
                    deficits=(
                        OracleDeficit(
                            kind="principal_scope",
                            action_id=norm.action_id,
                            context=(
                                ("principal", scoped_to),
                                ("field", norm.forbidden_field),
                            ),
                            rationale=rationale,
                        ),
                    ),
                )

        observation = trace[-1]
        if response_is_incomplete(observation):
            return self._unscoreable("target returned incomplete response evidence")

        exposed = _exposed_response_paths(observation, norm.forbidden_field)
        if exposed:
            return PolicyVerdict(
                status=VerdictStatus.FAIL,
                confidence=0.5,
                rationale=(
                    "forbidden response fields are present at paths: "
                    + ", ".join(exposed)
                ),
                evidence_refs=(observation.observation_id,),
                model_id="field-exposure",
                deterministic=True,
                grounded=True,
            )
        if not observation.response_tree:
            rationale = (
                "target returned no complete full-response tree for the forbidden field"
            )
            return self._unscoreable(
                rationale,
                deficits=(
                    OracleDeficit(
                        kind="incomplete_negative_scope",
                        action_id=norm.action_id,
                        context=(("field", norm.forbidden_field),),
                        rationale="safe output projection cannot prove field absence",
                    ),
                ),
            )
        return PolicyVerdict(
            status=VerdictStatus.PASS,
            confidence=0.5,
            rationale="no forbidden response field is present",
            evidence_refs=(observation.observation_id,),
            model_id="field-exposure",
            negative_scope=("response_tree",),
            deterministic=True,
            grounded=True,
        )

    @staticmethod
    def _unscoreable(
        rationale: str,
        *,
        deficits: tuple[OracleDeficit, ...] = (),
    ) -> PolicyVerdict:
        return PolicyVerdict(
            status=VerdictStatus.UNSCOREABLE,
            confidence=0.0,
            rationale=rationale,
            evidence_refs=(),
            model_id="field-exposure",
            deterministic=True,
            grounded=False,
            deficits=deficits,
        )


def _possession_holder(effect: object) -> str | None:
    """Return the principal a ``has(P, field)`` norm is scoped to."""

    holder = getattr(effect, "args", ())[:1]
    if not holder or not isinstance(holder[0], Atom):
        return None
    value = holder[0].value
    if not isinstance(value, str) or not value.startswith("principal:"):
        return None
    return value.removeprefix("principal:")


def _exposed_response_paths(
    observation: Observation, forbidden_field: str
) -> tuple[str, ...]:
    """Return full-response paths carrying ``forbidden_field``.

    ``Observation.output.fields`` is a safe dataflow projection and can omit
    exactly the field a visibility norm forbids.  The full response tree is
    retained for oracle evidence, so it is the primary source; safe fields are
    still included for targets that do not populate the full tree.
    """

    paths: set[str] = set()
    if observation.output is not None:
        paths.update(name for name, _ in observation.output.fields)
    paths.update(path for path, _ in observation.response_tree)
    return tuple(
        sorted(path for path in paths if _path_ends_with_field(path, forbidden_field))
    )


def _path_ends_with_field(path: str, forbidden_field: str) -> bool:
    """Match a norm field to a response path by name or path suffix.

    Protobuf response paths are dotted.  Repeated-field indices are runtime
    positions, not schema names, and therefore do not participate in the
    deterministic field mapping.
    """

    field_segments = _schema_segments(forbidden_field)
    if not field_segments:
        return False
    path_segments = _schema_segments(path)
    return path_segments[-len(field_segments) :] == field_segments


def _schema_segments(path: str) -> tuple[str, ...]:
    return tuple(
        segment for segment in path.split(".") if segment and not segment.isdigit()
    )


def _scenario_runs_principal(scenario: ScenarioPosition, principal_id: str) -> bool:
    """Return whether the scenario's stand includes the principal."""

    return any(
        principal.principal_id == principal_id
        for principal in scenario.stand.principals
    )
