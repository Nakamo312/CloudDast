"""Bounded task scheduling for axis-grounding batches."""

from __future__ import annotations

import logging
import math
from collections.abc import Callable, Iterator, Sequence

from cloud_dast.ports import GroundingRunner
from cloud_dast.qdl.graph import QdlGraph
from cloud_dast.runtime.grounding.results import AxisResult
from cloud_dast.verification.evidence import EvidenceView

logger = logging.getLogger("cloud_dast.runtime.grounding.scheduler")

AxisTask = tuple[str, tuple[str, ...]]
GroundBatch = Callable[
    [str, tuple[str, ...], QdlGraph, QdlGraph, EvidenceView | None], AxisResult
]


class AxisTaskScheduler:
    """Run grounding batches sequentially or through the injected runner."""

    def __init__(
        self,
        ground_batch: GroundBatch,
        *,
        task_runner: GroundingRunner | None,
        max_workers: int,
        axis_timeout: float | None,
    ) -> None:
        self._ground_batch = ground_batch
        self._task_runner = task_runner
        self._max_workers = max_workers
        self._axis_timeout = axis_timeout

    @property
    def max_workers(self) -> int:
        """Return the configured parallelism for telemetry."""

        return self._max_workers

    def stream(
        self,
        tasks: Sequence[AxisTask],
        graph: QdlGraph,
        cache_source: QdlGraph,
        *,
        evidence: EvidenceView | None,
    ) -> Iterator[tuple[str, tuple[str, ...], AxisResult]]:
        """Yield results as batches complete, isolating task failures."""

        def task(axis: str, batch: tuple[str, ...]) -> Callable[[], AxisResult]:
            def run() -> AxisResult:
                try:
                    return self._ground_batch(
                        axis,
                        batch,
                        graph,
                        cache_source,
                        evidence,
                    )
                except Exception:  # noqa: BLE001 - grounding is best-effort
                    logger.warning(
                        "axis_grounding_task_failed axis=%s batch=%d",
                        axis,
                        len(batch),
                    )
                    return AxisResult(axis, None, 1, len(batch))

            return run

        task_calls = [task(axis, batch) for axis, batch in tasks]
        if self._task_runner is None:
            for (axis, batch), task_call in zip(tasks, task_calls, strict=True):
                yield axis, batch, task_call()
            return

        completed: set[int] = set()
        for index, result in self._task_runner.run_tasks(
            task_calls,
            max_workers=self._max_workers,
            timeout=self._phase_timeout(len(task_calls)),
        ):
            completed.add(index)
            axis, batch = tasks[index]
            yield axis, batch, result

        pending = [
            (axis, batch)
            for index, (axis, batch) in enumerate(tasks)
            if index not in completed
        ]
        if pending:
            logger.warning(
                "axis_grounding_phase_timed_out axis_timeout=%s pending=%d",
                self._axis_timeout,
                len(pending),
            )
            for axis, batch in pending:
                yield axis, batch, AxisResult(axis, None, 1, len(batch))

    def _phase_timeout(self, task_count: int) -> float | None:
        """Give every worker wave the full configured per-axis timeout."""

        if self._axis_timeout is None or task_count == 0:
            return None
        waves = max(1, math.ceil(task_count / self._max_workers))
        return self._axis_timeout * waves


__all__ = ["AxisTaskScheduler"]
