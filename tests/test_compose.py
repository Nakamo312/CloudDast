"""Compose wiring guardrails.

B29 removed the neo4j service from the default compose wiring: the benchmark
e2e now runs on file-based stand + contract fixtures with SQLite and no
neo4j-driver dependency.  These tests pin the new invariant instead of the
old neo4j hardening (which only applied while the service existed).
"""

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_compose_has_no_neo4j_service() -> None:
    with (PROJECT_ROOT / "compose.yaml").open(encoding="utf-8") as stream:
        config = yaml.safe_load(stream)

    assert "neo4j" not in config.get("services", {})
    assert "neo4j" not in config.get("volumes", {})
    assert "neo4j" not in config.get("secrets", {})


def test_compose_mounts_contract_fixture() -> None:
    with (PROJECT_ROOT / "compose.yaml").open(encoding="utf-8") as stream:
        config = yaml.safe_load(stream)

    service = config["services"]["cloud-dast"]
    volumes = service["volumes"]
    assert any("contract.json" in str(v) for v in volumes), volumes
    environment = service["environment"]
    assert environment["CLOUD_DAST_FORMAL_STORE"] == "sqlite"


def test_env_example_has_no_inline_neo4j_password() -> None:
    text = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")

    # B29 removed the neo4j wiring entirely; the example must not reintroduce
    # inline passwords, and neo4j secrets are optional-extra only.
    assert "NEO4J_PASSWORD=" not in text
