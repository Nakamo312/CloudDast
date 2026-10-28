from __future__ import annotations

import pytest

from cloud_dast.composition.run_provider import RunProvider, select_promotion_policy
from cloud_dast.config import DEFAULT_MAX_PROMOTED_NORMS, MAX_SEMANTIC_FACTS


def test_promotion_policy_defaults_to_explicit_opt_in(monkeypatch) -> None:
    for name in (
        "CLOUD_DAST_PROMOTE_FORMAL_PROPOSALS",
        "CLOUD_DAST_MAX_PROMOTED_NORMS",
        "CLOUD_DAST_MAX_PROMOTED_SEMANTIC_FACTS",
    ):
        monkeypatch.delenv(name, raising=False)

    policy = select_promotion_policy()

    assert policy.enabled is False
    assert policy.max_norms == DEFAULT_MAX_PROMOTED_NORMS
    assert policy.max_semantic_facts == MAX_SEMANTIC_FACTS
    assert policy.promoted_norms == 0
    assert policy.promoted_semantic_facts == 0


def test_promotion_policy_reads_explicit_environment(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_PROMOTE_FORMAL_PROPOSALS", "true")
    monkeypatch.setenv("CLOUD_DAST_MAX_PROMOTED_NORMS", "7")
    monkeypatch.setenv("CLOUD_DAST_MAX_PROMOTED_SEMANTIC_FACTS", "11")

    policy = select_promotion_policy()

    assert policy.enabled is True
    assert policy.max_norms == 7
    assert policy.max_semantic_facts == 11


def test_run_provider_builds_the_shared_policy(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_PROMOTE_FORMAL_PROPOSALS", "1")

    policy = RunProvider().promotion_policy()

    assert policy.enabled is True


def test_promotion_flag_rejects_invalid_environment(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_PROMOTE_FORMAL_PROPOSALS", "maybe")

    with pytest.raises(RuntimeError, match="CLOUD_DAST_PROMOTE_FORMAL_PROPOSALS"):
        select_promotion_policy()


def test_promotion_cap_rejects_non_positive_environment(monkeypatch) -> None:
    monkeypatch.setenv("CLOUD_DAST_PROMOTE_FORMAL_PROPOSALS", "1")
    monkeypatch.setenv("CLOUD_DAST_MAX_PROMOTED_NORMS", "0")

    with pytest.raises(RuntimeError, match="CLOUD_DAST_MAX_PROMOTED_NORMS"):
        select_promotion_policy()
