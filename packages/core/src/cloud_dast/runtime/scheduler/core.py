"""Deterministic coverage-driven path selection for the campaign search.

Unexecuted paths are tried first.  Every later selection uses the same stable
coverage/cost ordering, with a deterministic advisory cold score that combines
coverage gain, trusted bandit prior, and reward state.
A blocked path with partial progress is recorded as ``retryable`` instead
of terminal, so bounded retries remain eligible when reactive grounding or
chain fuzzing produces new work.  Retry budgets are shared by canonical
coverage keys.

Cold starts prefer paths that add uncovered action/effect/primitive cells,
but not at the cost of one effect class monopolising the campaign: selection
is round-robined across effect constructors, oracle primitives, actions, and
per-action primitive cells.  Retry budgets are shared by canonical coverage
keys.  Latency-bound paths without a runtime baseline are held in a prewarm
state instead of consuming checks that cannot be scored.
"""

from __future__ import annotations

from collections.abc import Callable

from cloud_dast.runtime.execution.contracts import (
    QdlExecutionPath,
)
from cloud_dast.runtime.prioritization import InterestPrioritizer
from cloud_dast.runtime.scheduler.coverage import keys_for
from cloud_dast.runtime.scheduler.model import State
from cloud_dast.runtime.scheduler.outcomes import OutcomePolicy
from cloud_dast.runtime.scheduler.prewarm import LatencyPrewarm
from cloud_dast.runtime.scheduler.registry import PathRegistry
from cloud_dast.runtime.scheduler.selection import Chooser


class CoverageDrivenScheduler(PathRegistry, LatencyPrewarm, Chooser, OutcomePolicy):
    """Select the next execution path by deterministic coverage order.

    Selection policy:
      1.  Eligible: not completed, not blocked, not in flight.
      2.  Never-executed paths first, preferring paths that add uncovered
          action/effect/primitive cells while balancing the least-selected
          effect, primitive, action, and action/primitive dimensions; static
          cost breaks ties.
      3.  Once every eligible path has been attempted, apply the same
          deterministic coverage/cost ordering to bounded retries.  Progress
          only decides whether a blocked path is retryable; it never becomes
          a bandit score.
    """

    def __init__(
        self,
        paths: tuple[QdlExecutionPath, ...],
        *,
        has_latency_baseline: Callable[[str], bool] | None = None,
        seed: int = 0,
        interest_prioritizer: InterestPrioritizer | None = None,
    ) -> None:
        if interest_prioritizer is not None and seed != 0:
            raise ValueError("pass either seed or interest_prioritizer")
        self._paths = list(paths)
        self._state = State()
        self._has_latency_baseline = has_latency_baseline
        self._released_latency_actions: set[str] = set()
        self._interest = interest_prioritizer or InterestPrioritizer(seed=seed)
        self._path_keys = {path.path_id: keys_for(path) for path in self._paths}
        self._sync_prewarmed()
