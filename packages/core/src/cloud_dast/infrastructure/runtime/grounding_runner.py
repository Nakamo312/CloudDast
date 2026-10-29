"""Threaded runtime adapter for the application grounding runner port."""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import contextmanager
from enum import StrEnum
from typing import Generic, TypeVar

from cloud_dast.ports import (
    GroundingBatch,
    GroundingEnrichmentStatus,
    GroundingHandle,
    GroundingSink,
)

__all__ = [
    "GroundingPersistenceStatus",
    "GroundingTaskStatus",
    "ThreadedGroundingHandle",
    "ThreadedGroundingRunner",
    "ThreadedGroundingTask",
]

logger = logging.getLogger("cloud_dast.infrastructure.grounding")

_GROUNDING_THREAD_NAME = "cloud-dast-grounding"
_GROUNDING_TASK_THREAD_NAME = "cloud-dast-grounding-task"
_T = TypeVar("_T")


class ThreadedGroundingHandle:
    """Concrete ``GroundingHandle`` backed by one worker thread."""

    def __init__(self) -> None:
        self._queue: queue.Queue[GroundingBatch | None] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._error: BaseException | None = None
        self._promoted_facts = 0
        self._finished = threading.Event()
        self._finish_lock = threading.Lock()
        self._enrichment_status: GroundingEnrichmentStatus = "not_started"

    def bind(self, thread: threading.Thread) -> None:
        self._thread = thread

    def publish(self, batch: GroundingBatch) -> None:
        with self._finish_lock:
            if self._finished.is_set():
                # A detached enrichment task completed after the campaign
                # stream closed. Its facts are already persisted outside
                # the stream; dropping the live notification is the sink
                # contract, not an error.
                logger.info(
                    "grounding_batch_dropped_after_finish axis=%s batch=%s facts=%d",
                    batch.axis,
                    batch.batch_key,
                    batch.fact_count,
                )
                return
            self._promoted_facts += batch.fact_count
            # Publishing under the finish lock guarantees no batch can be
            # queued after the finish sentinel.
            self._queue.put(batch)

    def finish(self, error: BaseException | None = None) -> None:
        with self._finish_lock:
            if self._finished.is_set():
                return
            self._error = error
            self._finished.set()
        self._queue.put(None)

    def mark_enrichment(self, status: GroundingEnrichmentStatus) -> None:
        """Record detached enrichment without reopening the campaign stream."""

        with self._finish_lock:
            if self._enrichment_status in {"committed", "failed", "discarded"}:
                return
            self._enrichment_status = status

    def wait_batch(self, timeout: float | None = None) -> GroundingBatch | None:
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("grounding batch wait timed out") from None

    @property
    def done(self) -> bool:
        return (
            self._thread is not None
            and not self._thread.is_alive()
            and self._queue.empty()
        )

    @property
    def promoted_facts(self) -> int:
        return self._promoted_facts

    @property
    def error(self) -> BaseException | None:
        return self._error

    @property
    def enrichment_status(self) -> GroundingEnrichmentStatus:
        with self._finish_lock:
            return self._enrichment_status


class GroundingTaskStatus(StrEnum):
    """Typed lifecycle of one detached grounding task."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLATION_REQUESTED = "cancellation_requested"
    CANCELLED = "cancelled"


class GroundingPersistenceStatus(StrEnum):
    """Typed handoff state for a task result.

    The runner cannot inspect an arbitrary callable's repository transaction.
    ``COMMITTED`` therefore means that the callable completed and its result
    was handed back to its owner. A timed-out/cancelled result is explicitly
    ``DISCARDED`` at the workflow boundary and must not be applied to a
    terminal campaign.
    """

    NOT_STARTED = "not_started"
    IN_FLIGHT = "in_flight"
    COMMITTED = "committed"
    DISCARDED = "discarded"
    FAILED = "failed"


class ThreadedGroundingTask(Generic[_T]):
    """Result handle backed by one daemon worker thread.

    ``ThreadPoolExecutor`` workers are non-daemon and are joined by Python's
    interpreter shutdown hook even after ``shutdown(wait=False)``. That is
    not a detached lifecycle. This handle owns a daemon thread, records the
    cancellation/persistence boundary, and lets the runner close all pending
    advisory tasks before terminal campaign evaluation.
    """

    def __init__(self, task: Callable[[], _T], *, name: str) -> None:
        self._future: Future[_T] = Future()
        self._task = task
        self._lock = threading.Lock()
        self._status = GroundingTaskStatus.PENDING
        self._persistence = GroundingPersistenceStatus.NOT_STARTED
        self._cancel_requested = False
        self._late_result_discarded = False
        self._thread = threading.Thread(
            target=self._run,
            name=name,
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        with self._lock:
            if self._cancel_requested:
                if self._status != GroundingTaskStatus.TIMED_OUT:
                    self._status = GroundingTaskStatus.CANCELLED
                self._persistence = GroundingPersistenceStatus.DISCARDED
                return
            self._status = GroundingTaskStatus.RUNNING
            self._persistence = GroundingPersistenceStatus.IN_FLIGHT
        if not self._future.set_running_or_notify_cancel():
            with self._lock:
                self._status = GroundingTaskStatus.CANCELLED
                self._persistence = GroundingPersistenceStatus.DISCARDED
            return
        try:
            result = self._task()
        except BaseException as error:  # noqa: BLE001 - surfaced by result()
            with self._lock:
                if self._cancel_requested:
                    if self._status != GroundingTaskStatus.TIMED_OUT:
                        self._status = GroundingTaskStatus.CANCELLED
                    self._persistence = GroundingPersistenceStatus.DISCARDED
                else:
                    self._status = GroundingTaskStatus.FAILED
                    self._persistence = GroundingPersistenceStatus.FAILED
            self._future.set_exception(error)
            return
        with self._lock:
            if self._cancel_requested:
                if self._status != GroundingTaskStatus.TIMED_OUT:
                    self._status = GroundingTaskStatus.CANCELLED
                self._persistence = GroundingPersistenceStatus.DISCARDED
                self._late_result_discarded = True
            else:
                self._status = GroundingTaskStatus.COMPLETED
                self._persistence = GroundingPersistenceStatus.COMMITTED
        self._future.set_result(result)

    def cancel(self, *, timed_out: bool = False) -> bool:
        """Request cancellation and discard any result that arrives later."""

        with self._lock:
            if self._status is GroundingTaskStatus.FAILED and not timed_out:
                return False
            if self._status is GroundingTaskStatus.COMPLETED and not timed_out:
                return False
            self._cancel_requested = True
            self._status = (
                GroundingTaskStatus.TIMED_OUT
                if timed_out
                else GroundingTaskStatus.CANCELLATION_REQUESTED
            )
            self._persistence = GroundingPersistenceStatus.DISCARDED
            if timed_out and self._future.done():
                self._late_result_discarded = True
        return self._future.cancel()

    def result(self, timeout: float | None = None) -> _T:
        try:
            result = self._future.result(timeout=timeout)
        except FutureTimeoutError as error:
            self.cancel(timed_out=True)
            raise TimeoutError("grounding task timed out") from error
        if self._late_result_discarded:
            raise TimeoutError("grounding task result was discarded after cancellation")
        return result

    @property
    def status(self) -> GroundingTaskStatus:
        with self._lock:
            return self._status

    @property
    def persistence_status(self) -> GroundingPersistenceStatus:
        with self._lock:
            return self._persistence

    @property
    def late_result_discarded(self) -> bool:
        with self._lock:
            return self._late_result_discarded

    @property
    def done(self) -> bool:
        return self._future.done()


class ThreadedGroundingRunner:
    """Concrete infrastructure adapter for the application runner port.

    Tasks are daemon-owned and have an explicit cancellation/result handoff.
    A late callable completion is never returned after the caller has timed
    out or closed the runner.
    """

    def __init__(self) -> None:
        self._tasks: set[ThreadedGroundingTask[object]] = set()
        self._tasks_lock = threading.Lock()
        self._lifecycle_revision = 0

    @property
    def lifecycle_revision(self) -> int:
        with self._tasks_lock:
            return self._lifecycle_revision

    @contextmanager
    def commit(self, lifecycle_revision: int) -> Iterator[bool]:
        """Linearize an owner commit against close using the lifecycle lock."""

        with self._tasks_lock:
            yield self._lifecycle_revision == lifecycle_revision

    def start(self, work: Callable[[GroundingSink], None]) -> GroundingHandle:
        handle = ThreadedGroundingHandle()

        def worker() -> None:
            try:
                work(handle)
            except BaseException as error:  # noqa: BLE001 - surfaced by handle
                handle.finish(error)

        thread = threading.Thread(
            target=worker,
            name=_GROUNDING_THREAD_NAME,
            daemon=True,
        )
        handle.bind(thread)
        thread.start()
        return handle

    def start_task(self, task: Callable[[], _T]) -> ThreadedGroundingTask[_T]:
        handle = ThreadedGroundingTask(task, name=_GROUNDING_TASK_THREAD_NAME)
        with self._tasks_lock:
            self._tasks.add(handle)  # type: ignore[arg-type]

        def remove_done(_future: Future[_T]) -> None:
            if handle.done:
                with self._tasks_lock:
                    self._tasks.discard(handle)  # type: ignore[arg-type]

        handle._future.add_done_callback(remove_done)
        handle.start()
        return handle

    def run_tasks(
        self,
        tasks: Sequence[Callable[[], _T]],
        *,
        max_workers: int,
        timeout: float | None,
    ) -> Iterator[tuple[int, _T]]:
        if not tasks:
            return
        if max_workers <= 0:
            raise ValueError("max_workers must be positive")
        lifecycle_revision = self.lifecycle_revision
        completions: queue.Queue[int] = queue.Queue()
        active: dict[int, ThreadedGroundingTask[_T]] = {}
        next_index = 0

        def start_next() -> None:
            nonlocal next_index
            if next_index >= len(tasks):
                return
            index = next_index
            next_index += 1
            handle = self.start_task(tasks[index])
            active[index] = handle
            handle._future.add_done_callback(
                lambda _future, i=index: completions.put(i)
            )

        for _ in range(min(max_workers, len(tasks))):
            start_next()

        deadline = None if timeout is None else time.monotonic() + timeout
        try:
            while active:
                remaining = (
                    None if deadline is None else max(0.0, deadline - time.monotonic())
                )
                try:
                    index = completions.get(timeout=remaining)
                except queue.Empty:
                    break
                handle = active.pop(index, None)
                if handle is None:
                    continue
                if self.lifecycle_revision != lifecycle_revision:
                    break
                yield index, handle.result()
                start_next()
        finally:
            for handle in active.values():
                handle.cancel(timed_out=True)

    def close(self) -> None:
        """Invalidate pending handoffs and cancel all tracked tasks."""

        with self._tasks_lock:
            self._lifecycle_revision += 1
            tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
