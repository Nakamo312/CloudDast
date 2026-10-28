from cloud_dast.runtime.campaign import LiveWorkflow
from cloud_dast.runtime.execution import BoundPathRunner


def test_live_workflow_uses_public_path_runner_boundary() -> None:
    forbidden = {
        "_execute_step_pair",
        "_pair_check",
        "_execute_readback",
        "_execute_payload_pair",
        "_execute_concurrency_step",
    }
    assert not any(hasattr(LiveWorkflow, name) for name in forbidden)


def test_path_runner_exposes_differential_owner() -> None:
    assert isinstance(BoundPathRunner.differential, property)
    assert isinstance(BoundPathRunner.readback_reevaluation, property)
    assert not hasattr(BoundPathRunner, "execute_step_pair")
    assert not hasattr(BoundPathRunner, "execute_readback")
