from __future__ import annotations

from collections.abc import Callable, Mapping

from dishka import Container, Provider, make_container, provide

from cloud_dast.composition.app_provider import AppProvider
from cloud_dast.composition.grounding import Provider as GroundingProvider
from cloud_dast.composition.guardrails import AllowlistGuardrail
from cloud_dast.composition.run_provider import RunProvider
from cloud_dast.composition.scopes import AppScope, CloudDastScopes
from cloud_dast.extensions import ExtensionRegistry
from cloud_dast.infrastructure.neo4j.common.repository import SessionFactory
from cloud_dast.ports import (
    EventPublisher,
    EventStore,
    Guardrail,
    MethodRepository,
    ModelClient,
    ReportPublisher,
    Target,
)


class GuardrailProvider(Provider):
    """Own the single campaign guardrail in the run scope."""

    def __init__(self, guardrail: Guardrail | None = None) -> None:
        super().__init__()
        self._guardrail = guardrail

    @provide(scope=AppScope)
    def guardrail(self, method_repository: MethodRepository) -> Guardrail:
        if self._guardrail is not None:
            return self._guardrail
        return AllowlistGuardrail.from_environment(method_repository)


def make_cloud_dast_container(
    session_factory: SessionFactory | None,
    target: Target,
    event_store: EventStore,
    model_client: ModelClient | None = None,
    method_prefix_aliases: Mapping[str, str] | None = None,
    guardrail: Guardrail | None = None,
    extension_registry: ExtensionRegistry | None = None,
    report_publisher_factory: Callable[[EventPublisher], ReportPublisher] | None = None,
) -> Container:
    """Assemble the container with explicit, already-built adapters.

    ``session_factory`` may be ``None`` for the Neo4j-free file/sqlite
    composition.
    """

    return make_container(
        AppProvider(method_prefix_aliases=method_prefix_aliases),
        RunProvider(
            model_client=model_client,
            extension_registry=extension_registry,
            report_publisher_factory=report_publisher_factory,
        ),
        GroundingProvider(),
        GuardrailProvider(guardrail),
        scopes=CloudDastScopes,
        context={
            SessionFactory: session_factory,
            Target: target,
            EventStore: event_store,
        },
    )
