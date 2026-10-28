from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from typing import Any

from cloud_dast.infrastructure.secrets import secret_value

SessionFactory = Callable[[], AbstractContextManager[Any]]


@dataclass(frozen=True)
class Neo4jConfig:
    """Connection settings for the graph store.

    Values are supplied by the composition root.  The environment constructor
    only reads variable names; credentials are never embedded in the package.
    """

    uri: str
    user: str
    password: str = field(repr=False)

    @classmethod
    def from_environment(cls) -> Neo4jConfig:
        values = {
            "uri": os.environ.get("CPA_NEO4J_URI", "").strip(),
            "user": os.environ.get("CPA_NEO4J_USER", "").strip(),
            "password": secret_value("CPA_NEO4J_PASSWORD"),
        }
        missing = tuple(name for name, value in values.items() if not value)
        if missing:
            raise RuntimeError(
                "Neo4j configuration is incomplete; missing environment "
                + ", ".join(f"CPA_NEO4J_{name.upper()}" for name in missing)
            )
        return cls(**values)


def normalize_method_id(method_id: str) -> str:
    normalized = method_id.strip().replace("/", ".")
    if normalized.startswith(("grpc:", "grpc-priv:", "http:", "rest:")):
        return normalized
    if ".priv." in f".{normalized}.":
        return f"grpc-priv:{normalized}"
    return f"grpc:{normalized}"


class Neo4jSessionFactory:
    """Lazy, configuration-scoped Neo4j session factory."""

    def __init__(self, config: Neo4jConfig) -> None:
        self._config = config
        self._driver: Any | None = None

    @contextmanager
    def __call__(self) -> Iterator[Any]:
        if self._driver is None:
            from neo4j import GraphDatabase

            self._driver = GraphDatabase.driver(
                self._config.uri,
                auth=(self._config.user, self._config.password),
            )

        with self._driver.session() as neo4j_session:
            yield neo4j_session

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None


def make_session_factory(config: Neo4jConfig | None = None) -> SessionFactory:
    """Create a lazy Neo4j session factory from injected configuration.

    The driver is initialized on the first session, not while importing or
    composing the application.  This keeps tests and offline tooling free of
    network side effects while allowing the live composition to use the same
    repository implementations.
    """

    return Neo4jSessionFactory(config or Neo4jConfig.from_environment())


# Kept as an internal alias for repository construction.  Public callers use
# ``make_session_factory`` so configuration remains explicit at the composition
# boundary.
_default_session_factory = make_session_factory


class Neo4jRepository:
    """Base class for Neo4j-backed repositories."""

    def __init__(self, session_factory: SessionFactory | None = None) -> None:
        self._session_factory = session_factory or make_session_factory()

    def _run(self, query: str, **params: Any) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            result = session.run(query, **params)
            return [dict(record) for record in result]

    def _run_one(self, query: str, **params: Any) -> dict[str, Any] | None:
        rows = self._run(query, **params)
        return rows[0] if rows else None

    def close(self) -> None:
        """Close the injected session factory when it owns a driver."""

        close = getattr(self._session_factory, "close", None)
        if close is not None:
            close()
