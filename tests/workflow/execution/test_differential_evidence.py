from __future__ import annotations

from cloud_dast.model import (
    AccessOutcome,
    Check,
    HttpStatus,
    Observation,
)
from cloud_dast.runtime.differential.evidence import (
    MeasurementKey,
    Store,
)
from cloud_dast.verification.differential.contracts import (
    ConcurrencyResult,
    ReadBackResult,
)


def _check(check_id: str) -> Check:
    return Check(
        check_id=check_id,
        invariant_id="invariant:test",
        method_id="method:test",
        scenario_id="scenario:test",
        request=(),
        identities=("attacker",),
    )


def _observation(observation_id: str, check_id: str) -> Observation:
    return Observation(
        observation_id=observation_id,
        check_id=check_id,
        scenario_id="scenario:test",
        observed_outcome=AccessOutcome.ALLOWED,
        response_summary="allowed",
        transport_status=HttpStatus(code=200),
    )


def _readback_result(suffix: str) -> ReadBackResult:
    write_check = _check(f"check:{suffix}:write")
    read_before_check = _check(f"check:{suffix}:before")
    read_after_check = _check(f"check:{suffix}:after")
    return ReadBackResult(
        write_check=write_check,
        read_before_check=read_before_check,
        read_after_check=read_after_check,
        write=_observation(f"observation:{suffix}:write", write_check.check_id),
        read_before=_observation(
            f"observation:{suffix}:before", read_before_check.check_id
        ),
        read_after=_observation(
            f"observation:{suffix}:after", read_after_check.check_id
        ),
    )


def _concurrency_result(suffix: str) -> ConcurrencyResult:
    before_check = _check(f"check:{suffix}:before")
    probe_check = _check(f"check:{suffix}:probe")
    after_check = _check(f"check:{suffix}:after")
    return ConcurrencyResult(
        read_before=(
            before_check,
            _observation(f"observation:{suffix}:before", before_check.check_id),
        ),
        probes=(
            (
                probe_check,
                _observation(f"observation:{suffix}:probe", probe_check.check_id),
            ),
        ),
        read_after=(
            after_check,
            _observation(f"observation:{suffix}:after", after_check.check_id),
        ),
    )


def _key(resource_id: str, invariant_id: str = "invariant:test") -> MeasurementKey:
    return MeasurementKey(
        method_id="method:test",
        scenario_id="scenario:test",
        resource_id=resource_id,
        invariant_id=invariant_id,
    )


def test_readback_put_get_overwrite_and_missing_are_keyed() -> None:
    store = Store[MeasurementKey]()
    key = _key("resource:one")
    replacement = _readback_result("replacement")

    store.put_readback(key, _readback_result("initial"))
    store.put_readback(key, replacement)

    assert store.get_readback(key) is replacement
    assert store.get_readback(_key("resource:missing")) is None


def test_iterators_are_sorted_snapshots_and_keep_namespaces_separate() -> None:
    store = Store[MeasurementKey]()
    late_key = _key("resource:two")
    early_key = _key("resource:one")
    concurrency = _concurrency_result("concurrency")

    store.put_readback(late_key, _readback_result("late"))
    readback_snapshot = store.iter_readbacks()
    store.put_readback(early_key, _readback_result("early"))
    store.put_concurrency(early_key, concurrency)

    assert tuple(key for key, _ in readback_snapshot) == (late_key,)
    assert tuple(key for key, _ in store.iter_readbacks()) == (
        early_key,
        late_key,
    )
    assert store.get_concurrency(early_key) is concurrency
    assert tuple(store.iter_concurrency()) == ((early_key, concurrency),)


def test_clear_can_remove_one_namespace_or_the_whole_campaign() -> None:
    store = Store[MeasurementKey]()
    key = _key("resource:one")
    readback = _readback_result("clear")
    concurrency = _concurrency_result("clear")

    store.put_readback(key, readback)
    store.put_concurrency(key, concurrency)
    store.clear_readbacks()

    assert store.get_readback(key) is None
    assert store.get_concurrency(key) is concurrency

    store.clear()

    assert store.get_concurrency(key) is None


def test_public_evidence_values_are_immutable_contracts() -> None:
    key = _key("resource:one")
    result = _readback_result("immutable")

    assert key._fields == (
        "method_id",
        "scenario_id",
        "resource_id",
        "invariant_id",
    )
    assert result.write_check.model_config["frozen"] is True
    assert result.read_before_check.model_config["frozen"] is True
    assert result.read_after_check.model_config["frozen"] is True
