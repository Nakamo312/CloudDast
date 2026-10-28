from __future__ import annotations

import pytest

from cloud_dast.contracts.plan import VerificationPlan
from cloud_dast.model import (
    Check,
    EndpointLayer,
    FieldSpec,
    MethodSpec,
    Severity,
)
from cloud_dast.verification.invariant_projection import InvariantProjection
from cloud_dast_fuzzing import FindingShrinker


def method() -> MethodSpec:
    return MethodSpec(
        method_id="get-secret",
        service="lockbox",
        name="Get",
        layer=EndpointLayer.PRIVATE,
        fields=(FieldSpec(name="secret_id", type="string", required=True),),
    )


def plan() -> VerificationPlan:
    return VerificationPlan(
        plan_id="plan",
        invariant_id="inv",
        method_id="get-secret",
        scenario_id="scenario",
    )


def invariant() -> InvariantProjection:
    return InvariantProjection(
        invariant_id="inv",
        norm_id="norm",
        statement="norm",
        severity=Severity.HIGH,
    )


def seed(value: str = "secret-victim-with-long-payload") -> Check:
    return Check(
        invariant_id="inv",
        method_id="get-secret",
        scenario_id="scenario",
        request=(("secret_id", value),),
        identities=("attacker",),
    )


def shrinker(check: Check, **kwargs) -> FindingShrinker:
    return FindingShrinker(
        seed=check,
        plan=plan(),
        method=method(),
        invariant=invariant(),
        **kwargs,
    )


def test_shrinker_selects_a_simpler_hypothesis_candidate() -> None:
    original = seed()
    fuzz = shrinker(original)
    candidate = fuzz.next()

    assert candidate is not None
    assert len(dict(candidate.request)["secret_id"]) < len(
        dict(original.request)["secret_id"]
    )
    fuzz.record(candidate, reproduced=True)

    assert fuzz.result.check.request == candidate.request
    assert fuzz.result.steps == 1


def test_shrinker_keeps_seed_when_witness_does_not_reproduce() -> None:
    original = seed("abc")
    fuzz = shrinker(original)
    candidate = fuzz.next()
    assert candidate is not None

    fuzz.record(candidate, reproduced=False)

    assert fuzz.result.check == original
    assert fuzz.result.steps == 1

    alternative = fuzz.next()
    assert alternative is not None
    assert alternative.request != candidate.request


def test_shrinker_has_a_hard_ten_step_budget() -> None:
    with pytest.raises(ValueError, match="between 1 and 10"):
        shrinker(seed(), max_steps=11)

    fuzz = shrinker(seed(), max_steps=1)
    candidate = fuzz.next()
    assert candidate is not None
    fuzz.record(candidate, reproduced=False)

    assert fuzz.next() is None
    assert fuzz.result.steps == 1


def test_shrinker_refreshes_probe_marker_identity() -> None:
    original = seed("marker-value").model_copy(
        update={"probe_marker": "marker-value"},
    )
    candidate = shrinker(original).next()

    assert candidate is not None
    assert candidate.probe_marker is not None
    assert candidate.probe_marker != original.probe_marker
