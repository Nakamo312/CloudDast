from __future__ import annotations

import pytest

from cloud_dast.model import (
    AccessOutcome,
    GrpcStatus,
    JsonValue,
    Observation,
    ResponseData,
    TransportStatus,
)
from cloud_dast.model.evidence import response_tree_digest
from cloud_dast.verification.differential import compare_observations


def make_observation(
    *,
    observed_outcome: AccessOutcome = AccessOutcome.ALLOWED,
    transport_status: TransportStatus | None = GrpcStatus(code="OK"),
    output: ResponseData | None = None,
    error_reason: str | None = None,
    duration_ms: float | None = 10.0,
    response_tree: tuple[tuple[str, JsonValue], ...] = (),
) -> Observation:
    return Observation(
        check_id="check-1",
        scenario_id="scenario-1",
        observed_outcome=observed_outcome,
        response_summary="gRPC status: OK",
        transport_status=transport_status,
        output=output,
        duration_ms=duration_ms,
        error_reason=error_reason,
        response_tree=response_tree,
    )


def test_identical_observations_have_no_variance() -> None:
    output = ResponseData(
        fields=(("id", "same"),),
        field_names=("id", "nested.leaf"),
    )
    control = make_observation(output=output)
    treatment = make_observation(output=output)

    report = compare_observations("grpc:orders.Get", control, treatment)

    assert report.has_variance is False
    assert report.dimensions == ()
    assert report.signature == "no-variance"
    assert report.outcome_differs is False
    assert report.status_differs is False
    assert report.fields_only_control == ()
    assert report.fields_only_treatment == ()
    assert report.value_differs == ()
    assert report.error_differs is False
    assert report.latency_class_differs is False


def test_compare_observations_reports_every_safe_dimension() -> None:
    control = make_observation(
        observed_outcome=AccessOutcome.ALLOWED,
        transport_status=GrpcStatus(code="OK"),
        output=ResponseData(
            fields=(("shared", "one"), ("control_only", "value")),
            field_names=("shared", "control_only", "nested.leaf"),
        ),
    )
    treatment = make_observation(
        observed_outcome=AccessOutcome.DENIED,
        transport_status=GrpcStatus(code="PERMISSION_DENIED"),
        output=ResponseData(
            fields=(("shared", "two"), ("treatment_only", "value")),
            field_names=("shared", "treatment_only", "nested.extra"),
        ),
        error_reason="export denied for attacker",
        duration_ms=900.0,
    )

    report = compare_observations("grpc:orders.Get", control, treatment)

    assert report.action_id == "grpc:orders.Get"
    assert report.control_observation_id == control.observation_id
    assert report.treatment_observation_id == treatment.observation_id
    assert report.outcome_differs is True
    assert report.status_differs is True
    assert report.fields_only_control == ("control_only", "nested.leaf")
    assert report.fields_only_treatment == ("nested.extra", "treatment_only")
    assert report.value_differs == ("shared",)
    assert report.error_differs is True
    assert report.latency_class_differs is False
    assert report.dimensions == ("outcome", "status", "fields", "value", "error")
    assert report.has_variance is True
    assert "error" in report.signature


def test_value_differs_keeps_names_only() -> None:
    control = make_observation(
        output=ResponseData(
            fields=(("shared", "alpha-secret"),),
            field_names=("shared", "shape.only"),
        )
    )
    treatment = make_observation(
        output=ResponseData(
            fields=(("shared", "beta-secret"),),
            field_names=("shared", "shape.only"),
        )
    )

    report = compare_observations("grpc:orders.Get", control, treatment)

    assert report.value_differs == ("shared",)
    assert "alpha-secret" not in repr(report)
    assert "beta-secret" not in repr(report)


def test_error_reason_comparison_is_none_safe() -> None:
    assert (
        compare_observations(
            "grpc:orders.Get", make_observation(), make_observation()
        ).error_differs
        is False
    )
    assert (
        compare_observations(
            "grpc:orders.Get",
            make_observation(),
            make_observation(error_reason="export denied"),
        ).error_differs
        is True
    )
    assert (
        compare_observations(
            "grpc:orders.Get",
            make_observation(error_reason="export denied"),
            make_observation(error_reason="export denied"),
        ).error_differs
        is False
    )


def test_status_comparison_treats_missing_status_as_different() -> None:
    control = make_observation(transport_status=GrpcStatus(code="OK"))
    treatment = make_observation(transport_status=None)

    report = compare_observations("grpc:orders.Get", control, treatment)

    assert report.status_differs is True
    assert report.dimensions == ("status",)


def test_latency_class_differs_is_stubbed_until_baseline_exists() -> None:
    control = make_observation(duration_ms=1.0)
    treatment = make_observation(duration_ms=10_000.0)

    report = compare_observations("grpc:orders.Get", control, treatment)

    assert report.latency_class_differs is False
    assert "latency" not in report.dimensions


def test_value_differs_reports_non_whitelisted_tree_paths() -> None:
    shared_output = ResponseData(fields=(("user_id", "same"),))
    control = make_observation(
        output=shared_output,
        response_tree=(
            ("user_id", "same"),
            ("debug.internal_id", "control-debug"),
            ("user.address.city", "Moscow"),
        ),
    )
    treatment = make_observation(
        output=shared_output,
        response_tree=(
            ("user_id", "same"),
            ("debug.internal_id", "treatment-debug"),
            ("user.address.city", "Moscow"),
        ),
    )

    report = compare_observations("grpc:orders.Get", control, treatment)

    assert report.value_differs == ("debug.internal_id",)
    assert report.dimensions == ("value",)
    assert report.has_variance is True


def test_shape_names_use_tree_paths_when_present() -> None:
    control = make_observation(
        output=ResponseData(
            fields=(("shared", "one"),),
            field_names=("legacy.only",),
        ),
        response_tree=(("shared", "one"), ("tree.only", "x")),
    )
    treatment = make_observation(
        output=ResponseData(fields=(("shared", "one"),)),
        response_tree=(("shared", "one"), ("extra", "y")),
    )

    report = compare_observations("grpc:orders.Get", control, treatment)

    assert report.fields_only_control == ("tree.only",)
    assert report.fields_only_treatment == ("extra",)
    assert report.dimensions == ("fields",)


def test_value_differs_merges_tree_and_legacy_paths_without_duplicates() -> None:
    control = make_observation(
        output=ResponseData(fields=(("shared", "one"), ("tags", ("a",)))),
        response_tree=(("shared", "one"), ("nested.leaf", "same")),
    )
    treatment = make_observation(
        output=ResponseData(fields=(("shared", "two"), ("tags", ("a", "b")))),
        response_tree=(("shared", "two"), ("nested.leaf", "changed")),
    )

    report = compare_observations("grpc:orders.Get", control, treatment)

    assert report.value_differs == ("nested.leaf", "shared", "tags")


def test_value_differs_compares_mixed_tree_and_legacy_observations() -> None:
    control = make_observation(
        output=ResponseData(fields=(("shared", "one"),)),
        response_tree=(("shared", "one"), ("debug.id", "x")),
    )
    treatment = make_observation(output=ResponseData(fields=(("shared", "two"),)))

    report = compare_observations("grpc:orders.Get", control, treatment)

    assert report.value_differs == ("shared",)
    assert report.fields_only_control == ("debug.id",)


def test_value_differs_falls_back_to_whitelisted_fields_without_tree() -> None:
    control = make_observation(output=ResponseData(fields=(("shared", "one"),)))
    treatment = make_observation(output=ResponseData(fields=(("shared", "two"),)))

    report = compare_observations("grpc:orders.Get", control, treatment)

    assert report.value_differs == ("shared",)


@pytest.mark.parametrize(
    "incomplete_path",
    ["__truncated__", "not_available", "__response__.not_available"],
)
def test_incomplete_response_is_unscoreable(incomplete_path: str) -> None:
    control = make_observation(response_tree=(("shared", "one"),))
    treatment = make_observation(
        response_tree=(("shared", "one"), (incomplete_path, True))
    )

    assert compare_observations("grpc:orders.Get", control, treatment) is None


def test_response_digest_distinguishes_truncated_from_complete_tree() -> None:
    complete = (("shared", "one"),)
    truncated = (("shared", "one"), ("__truncated__", True))

    assert response_tree_digest(complete) != response_tree_digest(truncated)
