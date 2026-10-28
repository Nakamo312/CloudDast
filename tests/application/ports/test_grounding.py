from __future__ import annotations

import ast
import importlib
import os
import select
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from cloud_dast.infrastructure.runtime.grounding_runner import (
    GroundingPersistenceStatus,
    GroundingTaskStatus,
    ThreadedGroundingRunner,
)
from cloud_dast.ports import GroundingBatch
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    input_field,
)
from cloud_dast.runtime.grounding import AutoGroundingService
from cloud_dast.verification.promotion import (
    PromotionPolicy,
)


class _Repository:
    def __init__(self, graph: QdlGraph) -> None:
        self.graph = graph
        self.saved: list[str] = []

    def save(self, source_id: str, graph: QdlGraph, **_kwargs: object) -> None:
        self.saved.append(source_id)

    def load(self, source_id: str) -> QdlGraph:
        return self.graph if source_id == "contract:orders" else QdlGraph()

    def load_merged(self, source_prefix: str) -> QdlGraph:
        return QdlGraph()


class _StartupAxisGrounding:
    def __init__(self, proposal: QdlGraph, release: threading.Event | None = None):
        self.proposal = proposal
        self.release = release

    def ground_staged_stream(self, source: QdlGraph, *, cache_source=None):
        del source, cache_source
        yield "roles", "b0", self.proposal
        if self.release is not None:
            self.release.wait(timeout=5)


class _RecordingFormalGrounder:
    def __init__(self, promoted_norms: int) -> None:
        self.promoted_norms = promoted_norms
        self.calls: list[str] = []

    def ground(self, service: str) -> int:
        self.calls.append(service)
        return self.promoted_norms


class _TaskTrackingRunner(ThreadedGroundingRunner):
    """Runner that records when each detached task has fully completed."""

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._completed: list[threading.Event] = []

    def start_task(self, task):
        done = threading.Event()

        def tracked():
            try:
                return task()
            finally:
                done.set()

        handle = super().start_task(tracked)
        with self._lock:
            self._completed.append(done)
        return handle

    def wait_task(self, index: int, timeout: float = 5.0) -> None:
        with self._lock:
            done = self._completed[index]
        assert done.wait(timeout=timeout), f"task {index} did not complete"


def _fact(
    predicate: str,
    args: tuple[object, ...],
    context: Context = Context.CONTRACT,
) -> Fact:
    return Fact(
        context=context,
        predicate=Predicate.from_name(predicate),
        args=args,  # type: ignore[arg-type]
    )


def test_grounding_application_modules_do_not_own_threads_or_workflow() -> None:
    module_names = (
        "cloud_dast.runtime.grounding.axis",
        "cloud_dast.runtime.grounding",
    )
    forbidden_roots = {"threading", "concurrent", "cloud_dast.workflow"}

    for module_name in module_names:
        module = importlib.import_module(module_name)
        tree = ast.parse(Path(module.__file__).read_text())
        imported_roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])

        assert not imported_roots & forbidden_roots, module_name


def test_startup_grounding_uses_formal_grounder_port() -> None:
    action = Atom(value="action:get")
    field = input_field(action, Atom(value="query"))
    source = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action"))),
            _fact("is", (field, Atom(value="InputField"))),
        )
    )
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (field, Atom(value="InputField")), Context.PROPOSAL),
            _fact("has", (field, Atom(value="object_ref")), Context.PROPOSAL),
        )
    )
    repository = _Repository(source)
    grounder = _RecordingFormalGrounder(promoted_norms=2)
    policy = PromotionPolicy(enabled=True)
    release = threading.Event()
    grounding = AutoGroundingService(
        repository,
        axis_grounding=_StartupAxisGrounding(proposal, release),
        formal_grounder=grounder,
        promotion_policy=policy,
    )

    handle = grounding.start_grounded("orders", ThreadedGroundingRunner())
    assert handle is not None
    batches: dict[str, GroundingBatch] = {}
    while (batch := handle.wait_batch(timeout=5)) is not None:
        batches[batch.axis] = batch
        # The axis stream is held open until both batches have been
        # observed, making formal delivery deterministic: the publisher
        # delivers while the sink is still open.
        if {"roles", "formal"} <= batches.keys():
            release.set()

    axis_batch = batches["roles"]
    assert axis_batch.batch_key == "b0"
    assert axis_batch.fact_count > 0
    assert batches["formal"] == GroundingBatch(
        axis="formal",
        batch_key="threat-modeler",
        fact_count=2,
    )
    assert handle.error is None
    assert handle.promoted_facts == axis_batch.fact_count + 2
    assert grounder.calls == ["orders"]


def test_startup_grounding_finishes_without_waiting_for_formal() -> None:
    """The finish sentinel must not depend on the formal threat modeler."""

    release = threading.Event()

    class HeldFormalGrounder:
        def ground(self, service: str) -> int:
            del service
            release.wait(timeout=30)
            return 5

    repository = _Repository(QdlGraph())
    grounding = AutoGroundingService(
        repository,
        axis_grounding=_StartupAxisGrounding(QdlGraph()),
        formal_grounder=HeldFormalGrounder(),
        promotion_policy=PromotionPolicy(enabled=True),
    )
    runner = _TaskTrackingRunner()

    handle = grounding.start_grounded("orders", runner)
    assert handle is not None
    # The sentinel arrives while the formal task is still running: the
    # campaign fixed point is the axis stream, not the enrichment.
    assert handle.wait_batch(timeout=5) is None
    assert handle.error is None

    release.set()
    # Task 0 is the formal grounder, task 1 the detached publisher; wait
    # for the publisher to have attempted its late publish.
    runner.wait_task(1)
    with pytest.raises(TimeoutError):
        handle.wait_batch(timeout=0.05)
    assert handle.error is None


def test_runner_timeout_discards_late_result_without_retaining_interpreter() -> None:
    """A timed-out task cannot hand a late result into a terminal caller."""

    release = threading.Event()
    late_side_effects: list[str] = []
    runner = ThreadedGroundingRunner()
    terminal_outcome: list[str] = []
    task = runner.start_task(
        lambda: (
            release.wait(timeout=5),
            late_side_effects.append("late"),
        )[-1]
    )

    with pytest.raises(TimeoutError):
        terminal_outcome.append(task.result(timeout=0.01))
    assert task.status is GroundingTaskStatus.TIMED_OUT
    assert task.persistence_status is GroundingPersistenceStatus.DISCARDED

    release.set()
    deadline = time.monotonic() + 1.0
    while not task.done and time.monotonic() < deadline:
        time.sleep(0.005)

    assert task.done
    assert task.status is GroundingTaskStatus.TIMED_OUT
    assert task.late_result_discarded is True
    assert task.persistence_status is GroundingPersistenceStatus.DISCARDED
    assert terminal_outcome == []
    assert late_side_effects == ["late"]
    # The worker is daemon-owned: it cannot retain interpreter shutdown after
    # the lifecycle boundary is closed, even when user code is still unwinding.
    runner.close()
    assert all(
        not thread.is_alive() or thread.daemon
        for thread in threading.enumerate()
        if thread.name.startswith("cloud-dast-grounding-task")
    )


def test_runner_task_does_not_keep_subprocess_alive() -> None:
    """A held advisory callable cannot retain the worker interpreter."""

    script = (
        "import threading; "
        "from cloud_dast.infrastructure.runtime.grounding_runner import "
        "ThreadedGroundingRunner; "
        "ThreadedGroundingRunner().start_task("
        "lambda: threading.Event().wait(30)); "
        "print('task-started', flush=True)"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        cwd=Path.cwd(),
        env={
            **os.environ,
            "PYTHONPATH": os.pathsep.join(
                filter(
                    None,
                    (
                        str(Path(__file__).parents[3] / "packages/core/src"),
                        os.environ.get("PYTHONPATH"),
                    ),
                )
            ),
        },
        stdout=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    ready, _, _ = select.select([process.stdout], [], [], 5)
    assert ready, "runner subprocess did not start the held task"
    assert process.stdout.readline().strip() == "task-started"
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1)
        pytest.fail("daemon-owned grounding task retained the interpreter")
    assert process.returncode == 0
