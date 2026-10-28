"""Coordinate staged grounding through injected model and consultation ports."""

from __future__ import annotations

from cloud_dast.consultation import (
    ConsultationBudget,
)
from cloud_dast.contracts.proposals import FormalModelOutputValidator
from cloud_dast.runtime.grounding.axes.cache import AxisResultCache
from cloud_dast.runtime.grounding.axes.scheduler import AxisTaskScheduler
from cloud_dast.runtime.grounding.config import GrounderOptions
from cloud_dast.runtime.grounding.reactive import Followup
from cloud_dast.runtime.grounding.startup import Bootstrap


class Grounder(Bootstrap, Followup):
    """Ground model facts across axes × batches.

    The optional ``task_runner`` owns any parallel execution.  Without it the
    service executes batches sequentially, which keeps application calls
    deterministic and testable without a thread.  ``metrics`` is a thread-safe
    recorder and may be updated concurrently by grounding workers.
    """

    def __init__(
        self,
        *,
        options: GrounderOptions | None = None,
        **values: object,
    ) -> None:
        settings = GrounderOptions.from_legacy(options, values)
        validator = settings.validator
        batch_size = settings.batch_size
        max_workers = settings.max_workers
        metrics = settings.metrics
        cache = settings.cache
        cache_namespace = settings.cache_namespace
        axis_timeout = settings.axis_timeout
        slice_budget = settings.slice_budget
        consultation_budget = settings.consultation_budget
        task_runner = settings.task_runner
        consultation = settings.consultation
        grounding_dispatcher = settings.grounding_dispatcher
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")
        if max_workers <= 0:
            raise ValueError("max_workers must be positive")
        if axis_timeout is not None and axis_timeout <= 0:
            raise ValueError("axis_timeout must be positive when set")
        if consultation is None:
            raise ValueError("consultation must be injected")
        if grounding_dispatcher is None:
            raise ValueError("grounding_dispatcher must be injected")
        self._validator = validator or FormalModelOutputValidator()
        self._batch_size = batch_size
        self._axis_cache = AxisResultCache(
            cache,
            namespace=cache_namespace,
            metrics=metrics,
            key_for=grounding_dispatcher.cache_key,
        )
        self._slice_budget = slice_budget
        self._consultation_budget = consultation_budget or ConsultationBudget()
        self._consultation = consultation
        self._metrics = metrics
        self._grounding_dispatcher = grounding_dispatcher
        self._axis_scheduler = AxisTaskScheduler(
            self._ground_axis_batch,
            task_runner=task_runner,
            max_workers=max_workers,
            axis_timeout=axis_timeout,
        )
