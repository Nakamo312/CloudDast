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
from types import SimpleNamespace

import pytest

from cloud_dast.infrastructure.runtime.grounding_runner import (
    GroundingPersistenceStatus,
    GroundingTaskStatus,
    ThreadedGroundingRunner,
)
from cloud_dast.ports import GroundingBatch
from cloud_dast.proposals import ProposalPromotionRequest, ProposalPromotionResult
from cloud_dast.qdl.graph import (
    Atom,
    Context,
    Fact,
    Predicate,
    QdlGraph,
    allowed,
    input_field,
)
from cloud_dast.runtime.campaign.graph import Assembler
from cloud_dast.runtime.grounding.promotion import PromotionPolicy
from tests.grounding_owner import make_grounding


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

    def ground_stream(self, source: QdlGraph, *, cache_source=None):
        del source, cache_source
        yield "roles", "b0", self.proposal
        if self.release is not None:
            self.release.wait(timeout=5)


class _RecordingFormalGrounder:
    def __init__(self, promoted_norms: int) -> None:
        self.promoted_norms = promoted_norms
        self.calls: list[str] = []

    def prepare(self, service: str) -> ProposalPromotionRequest:
        self.calls.append(service)
        return ProposalPromotionRequest(source=QdlGraph(), proposal=QdlGraph())

    def commit(self, service, request) -> ProposalPromotionResult:
        return ProposalPromotionResult(
            QdlGraph(), tuple(str(i) for i in range(self.promoted_norms)), ()
        )


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
        "cloud_dast.runtime.grounding.startup",
        "cloud_dast.runtime.grounding.reactive",
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
    grounding_component_1 = _StartupAxisGrounding(proposal, release)
    grounding = make_grounding(
        repository,
        startup=grounding_component_1,
        reactive=grounding_component_1,
        formal_grounder=grounder,
        promotion_policy=policy,
    )

    handle = grounding.lifecycle.start_grounded("orders", ThreadedGroundingRunner())
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
        def prepare(self, service: str) -> ProposalPromotionRequest:
            release.wait(timeout=30)
            return ProposalPromotionRequest(QdlGraph(), QdlGraph())

        def commit(self, service, request) -> ProposalPromotionResult:
            return ProposalPromotionResult(QdlGraph(), ("1", "2", "3", "4", "5"), ())

    repository = _Repository(QdlGraph())
    grounding_component_2 = _StartupAxisGrounding(QdlGraph())
    grounding = make_grounding(
        repository,
        startup=grounding_component_2,
        reactive=grounding_component_2,
        formal_grounder=HeldFormalGrounder(),
        promotion_policy=PromotionPolicy(enabled=True),
    )
    runner = _TaskTrackingRunner()

    handle = grounding.lifecycle.start_grounded("orders", runner)
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


@pytest.mark.parametrize("phase", ["closed", "timed_out", "queued_close", "active"])
def test_formal_admission_obeys_campaign_lifecycle(phase) -> None:
    action, norm = Atom(value="action:orders.Get"), Atom(value="norm:orders.Get")
    source = QdlGraph(facts=(_fact("is", (action, Atom(value="Action"))),))
    proposal = QdlGraph(
        facts=(
            _fact("is", (action, Atom(value="Action")), Context.PROPOSAL),
            _fact("is", (norm, Atom(value="Norm")), Context.PROPOSAL),
            _fact("prevents", (norm, allowed(action)), Context.PROPOSAL),
        )
    )
    repository = _Repository(source)
    entered, release, queued, start = (threading.Event() for _ in range(4))

    def propose(graph):
        entered.set()
        assert release.wait(3)
        return SimpleNamespace(proposal=proposal, attempts=1, issues=())

    class QueuedRunner(_TaskTrackingRunner):
        def start(self, work):
            def delayed(sink):
                queued.set()
                assert start.wait(3)
                work(sink)

            return super().start(delayed)

    runner = QueuedRunner() if phase == "queued_close" else _TaskTrackingRunner()
    policy = PromotionPolicy(enabled=True, max_norms=1)
    assembler = Assembler(repository, SimpleNamespace(propose=propose), policy)
    grounding = make_grounding(
        repository,
        startup=_StartupAxisGrounding(QdlGraph()),
        formal_grounder=assembler,
        promotion_policy=policy,
        formal_timeout=0.05 if phase == "timed_out" else 5,
    )
    try:
        handle = grounding.lifecycle.start_grounded("orders", runner)
        assert handle is not None
        if phase == "queued_close":
            assert queued.wait(1)
            runner.close()
            start.set()
        assert entered.wait(1)
        assert handle.wait_batch(timeout=1) is None
        if phase == "closed":
            runner.close()
        elif phase == "timed_out":
            runner.wait_task(1)
        release.set()
        runner.wait_task(0)
        runner.wait_task(1)
        accepted = [
            key for key in repository.saved if key.startswith("accepted-batch:")
        ]
        assert len(accepted) == (1 if phase == "active" else 0)
        assert policy.promoted_norms == (1 if phase == "active" else 0)
    finally:
        start.set()
        release.set()
        runner.close()


@pytest.mark.parametrize("closed", [False, True])
def test_axis_batch_uses_the_same_lifecycle_admission(closed) -> None:
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
    entered, release, finished = (threading.Event() for _ in range(3))

    class HeldStartup:
        def ground_stream(self, source, *, cache_source=None):
            try:
                entered.set()
                assert release.wait(3)
                yield "roles", "b0", proposal
            finally:
                finished.set()

    repository = _Repository(source)
    policy = PromotionPolicy(enabled=True)
    runner = ThreadedGroundingRunner()
    grounding = make_grounding(
        repository, startup=HeldStartup(), promotion_policy=policy
    )
    try:
        handle = grounding.lifecycle.start_grounded("orders", runner)
        assert handle is not None
        assert entered.wait(1)
        if closed:
            runner.close()
        release.set()
        batch = handle.wait_batch(timeout=1)
        if closed:
            assert batch is None
            assert repository.saved == []
            assert policy.promoted_semantic_facts == 0
        else:
            assert batch is not None and batch.axis == "roles"
            assert any(key.startswith("accepted-batch:") for key in repository.saved)
            assert policy.promoted_semantic_facts > 0
            assert handle.wait_batch(timeout=1) is None
        assert finished.wait(1)
    finally:
        release.set()
        runner.close()
