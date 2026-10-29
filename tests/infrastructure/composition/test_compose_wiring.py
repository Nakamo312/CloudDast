"""Regression tests for the Neo4j-free benchmark compose wiring (B29)."""

from __future__ import annotations

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_PATH = PROJECT_ROOT / "compose.yaml"


def _compose() -> dict:
    document = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def test_compose_has_no_neo4j_service() -> None:
    compose = _compose()

    assert "neo4j" not in compose.get("services", {})
    assert "neo4j_data" not in compose.get("volumes", {})
    assert not {name for name in compose.get("secrets", {}) if "neo4j" in name}


def test_cloud_dast_service_runs_without_neo4j_environment() -> None:
    service = _compose()["services"]["cloud-dast"]
    environment = service.get("environment", {})

    assert not {name for name in environment if name.startswith("CPA_NEO4J_")}
    assert environment["CLOUD_DAST_STAND_SOURCE"] == "file"
    assert environment["CLOUD_DAST_CONTRACT_FILE"] == "/run/config/contract.json"
    assert environment["CLOUD_DAST_FORMAL_STORE"] == "sqlite"
    assert "neo4j" not in service.get("depends_on", {})


def test_cloud_dast_service_mounts_the_contract_fixture() -> None:
    volumes = _compose()["services"]["cloud-dast"]["volumes"]

    assert any(
        isinstance(volume, str) and volume.endswith(":/run/config/contract.json:ro")
        for volume in volumes
    )
