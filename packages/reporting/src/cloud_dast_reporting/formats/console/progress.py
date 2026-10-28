"""Dependency-free console progress logger for live DAG campaigns."""

from __future__ import annotations

import logging
import sys
import threading
import time
from types import SimpleNamespace

from cloud_dast.model import events as domain_events
from cloud_dast.model.events import PhaseChanged
from cloud_dast.ports import EventSubscriber
from cloud_dast.verification.evidence_facts import verified_fact_id
from cloud_dast_reporting import QdlCoverageMatrixView, ReportService
from cloud_dast_reporting import events as report_events

logger = logging.getLogger("cloud_dast.progress")
_EVENTS = (
    PhaseChanged,
    report_events.PlanReady,
    report_events.CoverageSnapshot,
    domain_events.QdlStepEvaluated,
    domain_events.QdlPathEvaluated,
    domain_events.CheckCompleted,
    domain_events.FindingRaised,
    domain_events.FactVerified,
)


class ConsoleProgressRenderer:
    """Write campaign events as plain, one-line log records."""

    def __init__(self, *, service: str, mode="auto", stream=None, **options) -> None:
        if mode not in {"auto", "live", "plain"}:
            raise ValueError(f"unknown progress mode: {mode}")
        if options.get("color", "auto") not in {"auto", "always", "never"}:
            raise ValueError(f"unknown progress color mode: {options['color']}")
        del options
        self._lock = threading.RLock()
        self._service = service
        self._mode = "plain"
        self._stream = stream if stream is not None else sys.stdout
        self._paths = self._steps = self._probes = 0
        self._checks = self._findings = self._facts = 0

    def set_metrics(self, metrics) -> None:
        del metrics

    def attach(self, bus: EventSubscriber) -> None:
        for event_type in _EVENTS:
            bus.subscribe(event_type, self._on_event)

    def phase(self, name: str) -> None:
        self._on_event(PhaseChanged(phase=name))

    def plan_ready(self, plan, max_checks: int | None) -> None:
        snapshot = ReportService().qdl_plan(plan)
        self._on_event(report_events.PlanReady(plan=snapshot, max_checks=max_checks))

    def coverage(self, matrix: QdlCoverageMatrixView) -> None:
        model = ReportService().qdl_coverage(matrix)
        self._on_event(report_events.CoverageSnapshot(coverage=model))

    def finished(self, findings: int) -> None:
        self._findings = max(self._findings, findings)
        self._on_event(PhaseChanged(phase="finished"))

    def _on_event(self, event: object) -> None:
        with self._lock:
            if isinstance(event, PhaseChanged):
                if event.phase == "finished":
                    self._emit(
                        f"campaign finished: checks={self._checks} "
                        f"probes={self._probes}/{self._steps} "
                        f"paths={self._paths} findings={self._findings} "
                        f"facts={self._facts}"
                    )
                else:
                    self._emit(f"phase: {event.phase}")
            elif isinstance(event, report_events.PlanReady):
                self._paths = len(event.plan.paths)
                self._steps = sum(len(path.steps) for path in event.plan.paths)
                self._emit(
                    f"campaign started: service={self._service} "
                    f"paths={self._paths} steps={self._steps} "
                    f"max_checks={event.max_checks or '-'}"
                )
            elif isinstance(event, report_events.CoverageSnapshot):
                self._emit("coverage updated")
            elif isinstance(event, domain_events.QdlStepEvaluated):
                self._probes += 1
                self._emit(
                    f"step path={event.path_id} step={event.step_id} "
                    f"verdict={event.verdict.value} phase={event.phase} "
                    f"probes={self._probes} checks={self._checks}"
                )
            elif isinstance(event, domain_events.QdlPathEvaluated):
                self._emit(
                    f"path {event.path_id} {event.outcome} "
                    f"steps={event.attempted_steps}/{event.step_count} "
                    f"probes={event.probe_count}"
                )
            elif isinstance(event, domain_events.CheckCompleted):
                self._checks += 1
            elif isinstance(event, domain_events.FindingRaised):
                self._findings += 1
                self._emit(f"FINDING {event.finding.finding_id}")
            elif isinstance(event, domain_events.FactVerified):
                if verified_fact_id(event.fact) is not None:
                    self._facts += 1

    def _emit(self, text: str) -> None:
        try:
            with self._lock:
                self._stream.write(f"{time.strftime('%H:%M:%S')} {text}\n")
                self._stream.flush()
        except Exception:  # noqa: BLE001 - presentation must not kill a campaign
            logger.warning("progress_plain_write_failed", exc_info=True)


def make_progress_renderer(mode, *, service, stream=None, color="auto") -> object:
    if mode == "off":
        return SimpleNamespace(attach=lambda bus: None, set_metrics=lambda m: None)
    return ConsoleProgressRenderer(
        service=service, mode=mode, stream=stream, color=color
    )
