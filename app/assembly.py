"""Build complete Cloud DAST applications from public core ports.

This module is the composition root: core defines contracts, while the app
selects installed extensions and passes the resulting registry into the
existing Dishka assembly.  The compatibility functions in
``cloud_dast.composition`` remain available for current callers during the
bounded migration.
"""

from __future__ import annotations

from collections.abc import Mapping

from dishka import Container

from cloud_dast.composition.container import make_cloud_dast_container
from cloud_dast.composition.live import make_live_container as _make_live_container
from cloud_dast.extensions import ExtensionRegistry
from cloud_dast.infrastructure.neo4j.common.repository import SessionFactory
from cloud_dast.ports import EventStore, Guardrail, ModelClient, Target
from cloud_dast_reporting.publisher import EventReportPublisher


def report_publisher_factory(event_bus):
    """Build the optional reporting adapter at the application boundary."""

    return EventReportPublisher(event_bus)


def discover_extensions() -> ExtensionRegistry:
    """Select installed optional implementations at the application edge."""

    return ExtensionRegistry.from_entry_points() or ExtensionRegistry.discover()


def make_container(
    session_factory: SessionFactory | None,
    target: Target,
    event_store: EventStore,
    model_client: ModelClient | None = None,
    method_prefix_aliases: Mapping[str, str] | None = None,
    guardrail: Guardrail | None = None,
    extension_registry: ExtensionRegistry | None = None,
) -> Container:
    """Build a file/sqlite or Neo4j-backed container with explicit extensions."""

    return make_cloud_dast_container(
        session_factory,
        target,
        event_store,
        model_client=model_client,
        method_prefix_aliases=method_prefix_aliases,
        guardrail=guardrail,
        extension_registry=extension_registry or discover_extensions(),
        report_publisher_factory=report_publisher_factory,
    )


def make_live_container(*args, **kwargs) -> Container:
    """Build the live transport composition with selected extensions."""

    kwargs.setdefault("extension_registry", discover_extensions())
    kwargs.setdefault("report_publisher_factory", report_publisher_factory)
    return _make_live_container(*args, **kwargs)


__all__ = ["discover_extensions", "make_container", "make_live_container"]
