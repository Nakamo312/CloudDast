"""Wave planning and worker execution for reactive consultations."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from cloud_dast.contracts.execution import LiveRequest
from cloud_dast.model.events import EventScope
from cloud_dast.ports import GroundingRunner
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.consultation.calls import Invoker, PlannedItem
from cloud_dast.runtime.consultation.commit import Committer
from cloud_dast.runtime.consultation.context import (
    WaveContext,
    WaveExecution,
)
from cloud_dast.runtime.consultation.evidence import (
    key as make_key,
)
from cloud_dast.runtime.consultation.evidence import (
    observation_for_work_item,
)
from cloud_dast.runtime.consultation.outcomes import OutcomePolicy
from cloud_dast.runtime.deficits.queue import DeficitQueue
from cloud_dast.runtime.deficits.work_items import WorkItem
from cloud_dast.runtime.differential.results import VarianceRecord
from cloud_dast.runtime.execution.state import CampaignAccumulator
from cloud_dast.runtime.grounding.source import Loader
from cloud_dast.runtime.observation_matching import action_matches
from cloud_dast.verification.evidence import (
    build_evidence_view,
    build_paired_evidence_view,
)
from cloud_dast.verification.oracles.latency import LatencyOracle
from cloud_dast.verification.slices import (
    build_sibling_action_slice,
)

logger = logging.getLogger("cloud_dast.runtime.consultation")


class Coordinator:
    """Schedule waves, pin their inputs and admit ordered owner-thread results."""

    def __init__(
        self,
        *,
        grounding_runner: GroundingRunner | None,
        batch_timeout: float,
        reactive_max_workers: int,
        latency_oracle: LatencyOracle | None,
        policy: OutcomePolicy,
        invoker: Invoker,
        committer: Committer,
        source: Loader | None,
    ) -> None:
        self._grounding_runner = grounding_runner
        self._batch_timeout = batch_timeout
        self._reactive_max_workers = reactive_max_workers
        self._latency_oracle = latency_oracle
        self._consultation_outcomes = policy
        self._invoker = invoker
        self._committer = committer
        self._source = source

    @property
    def consultation_outcomes(self) -> OutcomePolicy:
        return self._consultation_outcomes

    def work_item_ready(
        self,
        service: str,
        work_item: WorkItem,
        accumulator: CampaignAccumulator,
    ) -> bool:
        """Return whether this evidence signature can consume a model slot."""

        observation = observation_for_work_item(work_item, accumulator)
        identity = make_key(service, work_item, observation)
        return self._consultation_outcomes.should_dispatch(identity)

    def _require_grounding_runner(self) -> GroundingRunner:
        if self._grounding_runner is None:
            raise RuntimeError("reactive grounding runner is unavailable")
        return self._grounding_runner

    def run_wave(
        self,
        request: LiveRequest,
        wave: Sequence[WorkItem],
        deficits: DeficitQueue,
        accumulator: CampaignAccumulator,
        *,
        variance_records: dict[tuple[str, ...], VarianceRecord] | None = None,
        scope: EventScope | None = None,
        base_graph: QdlGraph | None = None,
        active_path_ids: frozenset[str] | None = None,
    ) -> WaveExecution:
        """Execute one planned wave of work items.

        Deterministic baseline repairs run inline; model work items run
        through the grounding runner — concurrently when the wave holds
        more than one independent item, sequentially otherwise.
        """

        promoted = 0
        model_items: list[WorkItem] = []
        for work_item in wave:
            if not work_item.requires_model:
                promoted += self._ground_latency_work_item(
                    request,
                    work_item,
                    deficits,
                    accumulator,
                )
            else:
                model_items.append(work_item)
        if not model_items:
            return WaveExecution(promoted, base_graph)
        execution = self._run_parallel_work_items(
            request,
            model_items,
            deficits,
            accumulator,
            variance_records=variance_records,
            scope=scope,
            base_graph=base_graph,
            active_path_ids=active_path_ids,
        )
        return WaveExecution(promoted + execution.promoted, execution.graph)

    def _ground_latency_work_item(
        self,
        request: LiveRequest,
        work_item: WorkItem,
        deficits: DeficitQueue,
        accumulator: CampaignAccumulator,
    ) -> int:
        """Close a latency work item when its baseline can now be measured."""

        latency_oracle = self._latency_oracle
        baseline_ready = False
        if latency_oracle is not None:
            action = work_item.representative.action
            baseline_ready = latency_oracle.has_baseline(action)
            if not baseline_ready:
                observations = tuple(
                    observation
                    for observation in accumulator.observations
                    if action_matches(observation, action)
                )
                baseline_ready = latency_oracle.update_baseline_from_observations(
                    action,
                    observations,
                )
        if baseline_ready:
            deficits.record_work_item_success(work_item)
            return 1
        # An unmet runtime prerequisite remains pending, but unchanged
        # evidence cannot dispatch the same deterministic repair again.
        deficits.defer_work_item(work_item)
        logger.info(
            "latency_baseline_deferred service=%s action=%s",
            request.service,
            work_item.action,
        )
        return 0

    def _run_parallel_work_items(
        self,
        request: LiveRequest,
        work_items: Sequence[WorkItem],
        deficits: DeficitQueue,
        accumulator: CampaignAccumulator,
        *,
        variance_records: dict[tuple[str, ...], VarianceRecord] | None = None,
        scope: EventScope | None = None,
        base_graph: QdlGraph | None = None,
        active_path_ids: frozenset[str] | None = None,
    ) -> WaveExecution:
        """Run independent wave members concurrently, then merge deterministically.

        Workers only perform the grounding calls; every queue mutation and
        promotion decision is applied on the campaign thread in the canonical
        merge order, so the resulting campaign state never depends on thread
        completion order.
        """

        grounding_runner = self._require_grounding_runner()
        lifecycle_revision = grounding_runner.lifecycle_revision
        # The campaign binds one immutable source and all evidence before dispatch.
        # A worker never reloads a source, promotes, parks, or persists its output.
        loader = self._source
        revision = (
            loader.load(request.service, failure_log="reactive_grounding_load_failed")
            if loader is not None
            else None
        )
        if revision is None:
            for work_item in work_items:
                deficits.record_work_item_failure(work_item)
            return WaveExecution(0, base_graph)
        source = base_graph if base_graph is not None else revision
        planned = self._plan_work_items(
            request,
            work_items,
            deficits,
            accumulator,
            source=source,
            variance_records=variance_records,
            scope=scope,
        )
        if not planned:
            return WaveExecution(0, base_graph)
        proposals = self._run_wave_tasks(
            request,
            planned,
            source=source,
            grounding_runner=grounding_runner,
            scope=scope,
        )
        # Reject a stale wave before even consulting the shared promotion caps.
        current_revision = loader.load(
            request.service,
            failure_log="reactive_grounding_load_failed",
        )
        if current_revision != revision:
            proposals.clear()
        return self._committer.commit(
            WaveContext(
                request=request,
                planned=planned,
                proposals=proposals,
                source=source,
                current_revision=current_revision,
                lifecycle_revision=lifecycle_revision,
                grounding_runner=grounding_runner,
                deficits=deficits,
                base_graph=base_graph,
                active_path_ids=active_path_ids,
                scope=scope,
            )
        )

    def _plan_work_items(
        self,
        request: LiveRequest,
        work_items: Sequence[WorkItem],
        deficits: DeficitQueue,
        accumulator: CampaignAccumulator,
        *,
        source: QdlGraph,
        variance_records: dict[tuple[str, ...], VarianceRecord] | None,
        scope: EventScope | None,
    ) -> tuple[PlannedItem, ...]:
        """Pin evidence and build worker inputs before any task starts."""

        planned: list[PlannedItem] = []
        for work_item in work_items:
            observation = observation_for_work_item(work_item, accumulator)
            identity = make_key(request.service, work_item, observation)
            if not self._consultation_outcomes.should_dispatch(identity):
                deficits.record_work_item_failure(work_item)
                continue
            gated, observation, check = self._committer.plan_observation(
                request,
                work_item,
                deficits,
                accumulator,
                scope=scope,
            )
            if gated:
                continue
            record = (
                next(
                    (
                        variance_records[d.work_item_key]
                        for d in work_item.deficits
                        if d.work_item_key in (variance_records or {})
                    ),
                    None,
                )
                if work_item.axis == "variance"
                else None
            )
            evidence = (
                build_paired_evidence_view(
                    control_check=record.control_check,
                    control=record.control,
                    treatment_check=record.treatment_check,
                    treatment=record.treatment,
                    report=record.report,
                )
                if record is not None
                else build_evidence_view(
                    check=check,
                    observation=observation,
                    label="response_semantics"
                    if work_item.axis == "response_semantics"
                    else "reactive",
                )
                if check is not None or observation is not None
                else None
            )
            siblings = (
                build_sibling_action_slice(source, action=work_item.action)
                if work_item.axis == "alternatives"
                else None
            )
            planned.append(
                PlannedItem(
                    work_item=work_item,
                    observation=observation,
                    check=check,
                    evidence=evidence,
                    siblings=siblings,
                    variance=record,
                )
            )
        return tuple(planned)

    def _run_wave_tasks(
        self,
        request: LiveRequest,
        planned: Sequence[PlannedItem],
        *,
        source: QdlGraph,
        grounding_runner: GroundingRunner,
        scope: EventScope | None,
    ) -> dict[int, Any]:
        """Run only model calls; queue and promotion stay on the owner thread."""

        tasks = [
            lambda item=item: self._invoker.invoke(
                request,
                item,
                source=source,
                scope=scope,
            )
            for item in planned
        ]
        return dict(
            grounding_runner.run_tasks(
                tasks,
                max_workers=min(len(tasks), self._reactive_max_workers),
                timeout=self._batch_timeout,
            )
        )
