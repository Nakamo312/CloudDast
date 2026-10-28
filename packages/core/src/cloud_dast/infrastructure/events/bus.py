from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from threading import RLock
from typing import TypeVar

from cloud_dast.model.events import DomainEvent

E = TypeVar("E", bound=DomainEvent)


class EventBus:
    """Synchronous in-process event dispatcher.

    The dispatcher is an infrastructure detail; application code depends on
    the :class:`EventPublisher` port instead.
    """

    def __init__(self) -> None:
        self._handlers: dict[type[DomainEvent], list[Callable[[DomainEvent], None]]] = (
            defaultdict(list)
        )
        self._lock = RLock()

    def subscribe(self, event_type: type[E], handler: Callable[[E], None]) -> None:
        with self._lock:
            self._handlers[event_type].append(handler)  # type: ignore[arg-type]

    def publish(self, event: DomainEvent) -> None:
        # The default in-process bus serializes synchronous subscribers.  This
        # is the simplest contract-preserving behavior for concurrent workers.
        with self._lock:
            for handler in tuple(self._handlers[type(event)]):
                handler(event)
