import pytest
from pydantic import ValidationError

from cloud_dast_llm.proposals import LlmGeneratedCheck, LlmGeneratedChecks


def test_proposals_keep_request_values_structured_and_bounded() -> None:
    proposal = LlmGeneratedChecks.model_validate(
        {"checks": [{"request": {"name": "candidate"}}]}
    )

    assert proposal.checks[0].request == {"name": "candidate"}


def test_proposals_reject_unbounded_nested_request_strings() -> None:
    with pytest.raises(ValidationError):
        LlmGeneratedCheck.model_validate({"request": {"name": "x" * 8193}})
