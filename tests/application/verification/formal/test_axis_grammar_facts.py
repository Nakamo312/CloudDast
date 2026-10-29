from __future__ import annotations

from cloud_dast_llm.axis_grounding import _AXIS_INSTRUCTIONS


def test_dataflows_instruction_requests_grammar_facts() -> None:
    instruction = _AXIS_INSTRUCTIONS["dataflows"]

    assert "format(input_field(Action, Field), Format)" in instruction
    assert "constraint(input_field(Action, Field), Operator, Value)" in instruction
    assert "dialect(SinkId, Dialect)" in instruction
    assert "causes(Action, changed(ResourceId, Field))" in instruction
    assert "causes(Action, create(ResourceType))" in instruction
    assert "causes(Action, remove(ResourceId))" in instruction
    assert "eq, ne, lt, le, gt, ge" in instruction
    assert "never return strategy code" in instruction
