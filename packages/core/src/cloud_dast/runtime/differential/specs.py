"""Resolve binding and prerequisites for differential probes."""

from __future__ import annotations

import logging
from collections.abc import Mapping

from cloud_dast.api import LiveRequest
from cloud_dast.model import MethodSpec, ScenarioPosition
from cloud_dast.ports import ScenarioRepository
from cloud_dast.qdl.field_roles import resolve_field_roles
from cloud_dast.qdl.graph import Context, QdlGraph
from cloud_dast.runtime.deficits import missing_role_deficit
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.execution.contracts import QdlExecutionStep
from cloud_dast.verification.differential.contracts import (
    DifferentialSpec,
    ReadBackSpec,
    payload_fields,
    read_resource_reference,
    select_read_method,
)

logger = logging.getLogger("cloud_dast.runtime.differential.specs")
_EXECUTABLE_CONTEXTS = frozenset({Context.CONTRACT, Context.ACCEPTED})


class SpecResolver:
    """Resolve executable prerequisites without invoking the target."""

    def __init__(
        self, *, scenario_repository: ScenarioRepository | None = None
    ) -> None:
        self._scenario_repository = scenario_repository

    def readback_spec(
        self,
        step: QdlExecutionStep,
        graph: QdlGraph,
        method_pool: Mapping[str, MethodSpec],
        deficits: DeficitQueue,
    ) -> ReadBackSpec | None:
        """Resolve the read method and binding for one write step."""

        if not step.plan.resource_params:
            self.record_missing_role(
                deficits,
                step.method.method_id,
                "object_ref",
            )
            return None
        mutable_fields = self.payload_fields(step, graph, deficits)
        if not mutable_fields:
            return None
        read_method = select_read_method(
            step.method,
            method_pool.values(),
            graph=graph,
        )
        if read_method is None:
            self.record_missing_role(deficits, step.method.method_id, "readback")
            return None
        reference = read_resource_reference(step.method, read_method, graph=graph)
        if reference is None:
            self.record_missing_role(deficits, step.method.method_id, "readback")
            return None
        try:
            return ReadBackSpec(
                write_method=step.method,
                read_method=read_method,
                resource_binding=reference[0],
                read_resource_types=(reference,),
            )
        except ValueError as error:
            logger.debug(
                "diff_readback_rejected action=%s reason=%s",
                step.method.method_id,
                error,
            )
            return None

    def payload_fields(
        self,
        step: QdlExecutionStep,
        graph: QdlGraph,
        deficits: DeficitQueue,
    ) -> tuple[str, ...]:
        """Return fields explicitly declared as mutable payload.

        Every input field without any role fact is a typed deficit: the
        campaign cannot know whether it is safe to mutate, so it never is
        until grounding promotes a role.
        """

        action = step.method.method_id
        field_roles = resolve_field_roles(graph)
        for gap in field_roles.deficits(
            action,
            (field.name for field in step.method.request_schema.fields),
            direction="input",
        ):
            self.record_missing_role(
                deficits,
                action,
                "payload",
                field=gap.field,
            )
        return payload_fields(step.method, field_roles)

    @staticmethod
    def record_missing_role(
        deficits: DeficitQueue,
        action: str,
        coverage: str,
        *,
        resource: str | None = None,
        field: str | None = None,
    ) -> None:
        context = (("coverage", coverage),)
        if resource is not None:
            context = (*context, ("resource", resource))
        if field is not None:
            context = (*context, ("field", field))
        deficit = missing_role_deficit(action, context, field=field)
        if deficits.add((deficit,)):
            logger.info(
                "deficit_detected kind=missing_role action=%s coverage=%s field=%s",
                action,
                coverage,
                field or "-",
            )

    def differential_spec(
        self,
        request: LiveRequest,
        step: QdlExecutionStep,
        graph: QdlGraph,
        deficits: DeficitQueue,
    ) -> DifferentialSpec | None:
        """Build a one-factor control/treatment pair for one step.

        The treatment is the request's own scenario — in a DAST campaign
        that is the attacker position from the profile.  The control is the
        subject declared by an explicit owner fact; a missing or ambiguous
        fact becomes a role deficit.  ``DifferentialSpec`` itself enforces
        that exactly one profile factor differs.
        """

        treatment = step.scenario
        if treatment.profile.identity_class != "attacker":
            return None
        control = self.control_position(request, step, treatment, graph, deficits)
        if control is None:
            return None
        try:
            return DifferentialSpec(control=control, treatment=treatment)
        except ValueError:
            logger.debug(
                "diff_pair_rejected action=%s reason=not-one-factor",
                step.method.method_id,
            )
            return None

    def control_position(
        self,
        request: LiveRequest,
        step: QdlExecutionStep,
        treatment: ScenarioPosition,
        graph: QdlGraph,
        deficits: DeficitQueue,
    ) -> ScenarioPosition | None:
        """Resolve the legitimate baseline position for one action.

        The owner is selected only from an executable ``owner(resource,
        subject)`` fact.  A missing or ambiguous fact is recorded as a role
        deficit; no principal or resource identifier is used as a fallback.
        """

        if self._scenario_repository is None:
            return None
        owner = self.owner_principal(graph, request.resource_id)
        if owner is None:
            self.record_missing_role(
                deficits,
                step.method.method_id,
                "owner",
                resource=request.resource_id,
            )
            return None
        return self._scenario_repository.get_scenario(
            owner,
            request.resource_id,
            method=step.method,
            identity_class="owner",
        )

    @staticmethod
    def owner_principal(
        graph: QdlGraph,
        resource_id: str,
    ) -> str | None:
        """Return the subject explicitly declared as the resource owner."""

        resource = f"resource:{resource_id}"
        owners: set[str] = set()
        for fact in graph.facts:
            if fact.context not in _EXECUTABLE_CONTEXTS:
                continue
            if fact.predicate.name != "owner" or len(fact.args) != 2:
                continue
            fact_resource = fact.args[0].value
            subject = fact.args[1].value
            if fact_resource != resource or not isinstance(subject, str):
                continue
            if subject.startswith("subject:"):
                owners.add(subject.removeprefix("subject:"))
        return next(iter(owners)) if len(owners) == 1 else None


__all__ = ["SpecResolver"]
