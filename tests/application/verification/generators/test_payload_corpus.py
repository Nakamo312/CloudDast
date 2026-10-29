from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import HealthCheck, find, settings
from pydantic import ValidationError

from cloud_dast_fuzzing.corpus import (
    PayloadAlternative,
    PayloadCondition,
    PayloadCorpus,
    PayloadCorpusAuditRecord,
    PayloadCorpusCompiler,
    PayloadCorpusDelta,
    PayloadCorpusGuardrail,
    PayloadCorpusStore,
    PayloadNode,
    PayloadProduction,
    PayloadReference,
    PayloadSlotAlternative,
    PayloadTerminal,
    PayloadTerminalAlternative,
    SeedEnrichmentModelWireOutput,
    load_payload_corpus,
    merge_payload_corpus_delta,
)

_FIND_SETTINGS = settings(
    derandomize=True,
    database=None,
    deadline=None,
    max_examples=100,
    suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.too_slow],
)


def _alternative(
    value: str,
    condition: PayloadCondition | None = None,
) -> PayloadTerminalAlternative:
    return PayloadTerminalAlternative(value=value, condition=condition)


def _terminal(
    *alternatives: PayloadTerminalAlternative,
) -> PayloadTerminal:
    return PayloadTerminal(alternatives=alternatives)


def _reference(
    node: str,
    *,
    repeat_min: int = 1,
    repeat_max: int = 1,
) -> PayloadReference:
    return PayloadReference(
        node=node,
        repeat_min=repeat_min,
        repeat_max=repeat_max,
    )


def test_payload_corpus_is_versioned_and_covers_required_sinks() -> None:
    corpus = load_payload_corpus()

    assert corpus.schema_version == 2
    assert corpus.corpus_version == "2"
    covered = {
        sink_type
        for production in corpus.productions
        for sink_type in production.sink_types
    }
    assert {"filesystem", "interpreter", "command"} <= covered
    assert any(production.root is not None for production in corpus.productions)


def test_payload_compiler_generates_balanced_recursive_grammar() -> None:
    corpus = PayloadCorpus(
        schema_version=2,
        corpus_version="test",
        productions=(
            PayloadProduction(
                production_id="recursive",
                sink_types=("custom",),
                dialects=("custom",),
                root="expression",
                nodes=(
                    PayloadNode(
                        name="expression",
                        alternatives=(
                            PayloadAlternative(
                                elements=(
                                    _terminal(
                                        _alternative("{marker}"),
                                        _alternative("value"),
                                    ),
                                ),
                            ),
                            PayloadAlternative(
                                elements=(
                                    _terminal(_alternative("(")),
                                    _reference("expression"),
                                    _terminal(_alternative(")")),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    strategy = PayloadCorpusCompiler(corpus).compile(("custom",), ("custom",))

    assert strategy is not None
    value = find(
        strategy,
        lambda candidate: "(" in candidate and ")" in candidate,
        settings=_FIND_SETTINGS,
    )

    assert value.count("(") == value.count(")")
    assert value.count("(") >= 1


def test_payload_grammar_recursive_components_compile() -> None:
    """A two-node recursive SCC compiles through the shared graph utility."""

    corpus = PayloadCorpus(
        schema_version=2,
        corpus_version="test",
        productions=(
            PayloadProduction(
                production_id="mutual",
                sink_types=("custom",),
                dialects=("custom",),
                root="left",
                nodes=(
                    PayloadNode(
                        name="left",
                        alternatives=(
                            PayloadAlternative(
                                elements=(
                                    _terminal(
                                        _alternative("{marker}"),
                                        _alternative("a"),
                                    ),
                                ),
                            ),
                            PayloadAlternative(
                                elements=(
                                    _terminal(_alternative("a")),
                                    _reference("right"),
                                ),
                            ),
                        ),
                    ),
                    PayloadNode(
                        name="right",
                        alternatives=(
                            PayloadAlternative(
                                elements=(_terminal(_alternative("b")),)
                            ),
                            PayloadAlternative(
                                elements=(
                                    _terminal(_alternative("b")),
                                    _reference("left"),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    strategy = PayloadCorpusCompiler(corpus).compile(("custom",), ("custom",))

    assert strategy is not None
    value = find(
        strategy,
        lambda candidate: len(candidate) >= 2,
        settings=_FIND_SETTINGS,
    )

    assert value[0] == "a"
    assert set(value) <= {"a", "b"}


def test_payload_compiler_selects_alternatives_from_generated_prefix() -> None:
    corpus = PayloadCorpus(
        schema_version=2,
        corpus_version="test",
        productions=(
            PayloadProduction(
                production_id="prefix",
                sink_types=("custom",),
                dialects=("custom",),
                root="quoted",
                nodes=(
                    PayloadNode(
                        name="quoted",
                        alternatives=(
                            PayloadAlternative(
                                elements=(
                                    _terminal(_alternative("'"), _alternative("`")),
                                    _reference("expression"),
                                    _terminal(
                                        _alternative(
                                            "'",
                                            PayloadCondition(
                                                prefix_contains=("'",),
                                            ),
                                        ),
                                        _alternative(
                                            "`",
                                            PayloadCondition(
                                                prefix_contains=("`",),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                    PayloadNode(
                        name="expression",
                        alternatives=(
                            PayloadAlternative(
                                elements=(
                                    _terminal(
                                        _alternative("{marker}"),
                                        _alternative("value"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    strategy = PayloadCorpusCompiler(corpus).compile(("custom",), ("custom",))

    assert strategy is not None
    for quote in ("'", "`"):
        value = find(
            strategy,
            lambda candidate, quote=quote: (
                candidate.startswith(quote) and candidate.endswith(quote)
            ),
            settings=_FIND_SETTINGS,
        )
        assert value[0] == value[-1] == quote


def test_payload_compiler_selects_terminal_by_dialect_context() -> None:
    corpus = PayloadCorpus(
        schema_version=2,
        corpus_version="test",
        productions=(
            PayloadProduction(
                production_id="dialect",
                sink_types=("custom",),
                dialects=("ansi", "backtick"),
                root="expression",
                nodes=(
                    PayloadNode(
                        name="expression",
                        alternatives=(
                            PayloadAlternative(
                                elements=(
                                    _terminal(
                                        _alternative(
                                            "'",
                                            PayloadCondition(dialects=("ansi",)),
                                        ),
                                        _alternative(
                                            "`",
                                            PayloadCondition(dialects=("backtick",)),
                                        ),
                                    ),
                                    _terminal(
                                        _alternative("{marker}"),
                                        _alternative("value"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    compiler = PayloadCorpusCompiler(corpus)
    ansi = compiler.compile(("custom",), ("ansi",))
    backtick = compiler.compile(("custom",), ("backtick",))

    assert ansi is not None
    assert backtick is not None
    assert find(
        ansi,
        lambda candidate: candidate.startswith("'"),
        settings=_FIND_SETTINGS,
    ).startswith("'")
    assert find(
        backtick,
        lambda candidate: candidate.startswith("`"),
        settings=_FIND_SETTINGS,
    ).startswith("`")


def test_payload_compiler_honours_reference_repeat_bounds() -> None:
    corpus = PayloadCorpus(
        schema_version=2,
        corpus_version="test",
        productions=(
            PayloadProduction(
                production_id="repeat",
                sink_types=("custom",),
                dialects=("custom",),
                root="sequence",
                nodes=(
                    PayloadNode(
                        name="sequence",
                        alternatives=(
                            PayloadAlternative(
                                elements=(
                                    _reference(
                                        "item",
                                        repeat_min=2,
                                        repeat_max=3,
                                    ),
                                ),
                            ),
                        ),
                    ),
                    PayloadNode(
                        name="item",
                        alternatives=(
                            PayloadAlternative(
                                elements=(
                                    _terminal(
                                        _alternative("{marker}"),
                                        _alternative("x"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    strategy = PayloadCorpusCompiler(corpus).compile(("custom",), ("custom",))

    assert strategy is not None
    value = find(strategy, lambda candidate: True, settings=_FIND_SETTINGS)

    assert set(value) == {"x"}
    assert len(value) in {2, 3}


def test_payload_corpus_renders_deterministic_runtime_markers() -> None:
    corpus = load_payload_corpus()

    assert corpus.render_marker(("interpreter",), ("ansi",), "marker") == "'marker'--"
    assert (
        corpus.render_marker(("filesystem",), ("posix",), "marker") == ".pdf/../marker"
    )
    assert corpus.render_marker(("command",), ("posix",), "marker") == "; printf marker"
    assert corpus.render_marker(("unknown",), ("ansi",), "marker") is None


def test_payload_compiler_separates_marker_and_payload_alternatives() -> None:
    compiler = PayloadCorpusCompiler()
    marker_strategy = compiler.compile(
        ("interpreter",),
        ("ansi",),
        marker_placeholder="{probe_marker}",
    )
    payload_strategy = compiler.compile(("interpreter",), ("ansi",))

    assert marker_strategy is not None
    assert payload_strategy is not None
    marker_value = find(
        marker_strategy,
        lambda value: "{probe_marker}" in value,
        settings=_FIND_SETTINGS,
    )
    payload_value = find(
        payload_strategy,
        lambda value: True,
        settings=_FIND_SETTINGS,
    )

    assert marker_value.startswith("'{probe_marker}'")
    assert "{probe_marker}" not in payload_value
    assert payload_value.startswith("'")


def test_payload_compiler_keeps_traversal_bounded_and_encoded() -> None:
    strategy = PayloadCorpusCompiler().compile(("filesystem",), ("posix",))

    assert strategy is not None
    value = find(
        strategy,
        lambda candidate: "%2e" in candidate or "%252e" in candidate,
        settings=_FIND_SETTINGS,
    )

    assert value.split("/", 1)[0].endswith(".pdf")
    assert "../" not in value or value.count("../") <= 4


def test_payload_corpus_rejects_unknown_template_slot(tmp_path: Path) -> None:
    path = tmp_path / "payloads.yaml"
    path.write_text(
        """
schema_version: 1
corpus_version: test
productions:
  - production_id: invalid
    sink_types: [interpreter]
    dialects: [ansi]
    template: "{quote}{witness}{terminator}"
    slots:
      - name: quote
        alternatives: ["'"]
      - name: witness
        alternatives: ["{marker}", " OR 1=1"]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="payload template"):
        load_payload_corpus(path)


def test_payload_corpus_migrates_schema_v1_to_v2(tmp_path: Path) -> None:
    path = tmp_path / "payloads.yaml"
    path.write_text(
        """
schema_version: 1
corpus_version: test
productions:
  - production_id: legacy
    sink_types: [custom]
    dialects: [custom]
    template: "{prefix}{witness}"
    slots:
      - name: prefix
        alternatives: ["engine-"]
      - name: witness
        alternatives: ["{marker}", "payload"]
""",
        encoding="utf-8",
    )

    corpus = load_payload_corpus(path)

    assert corpus.schema_version == 2
    assert corpus.corpus_version == "test"
    production = corpus.productions[0]
    assert production.root is not None
    assert production.template is None
    assert production.render("marker") == "engine-marker"
    strategy = PayloadCorpusCompiler(corpus).compile(("custom",), ("custom",))
    assert strategy is not None
    assert (
        find(
            strategy,
            lambda candidate: True,
            settings=_FIND_SETTINGS,
        )
        == "engine-payload"
    )


def test_payload_delta_is_bounded_data_and_rejects_strategy_code() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SeedEnrichmentModelWireOutput.model_validate(
            {
                "context": "proposal",
                "slot_alternatives": [
                    {
                        "production_id": "sql-ansi",
                        "slot_name": "terminator",
                        "alternatives": ["\n"],
                    }
                ],
                "strategy": "return st.just('benchmark-specific-payload')",
            }
        )


def test_payload_delta_guardrail_rejects_oversized_model_output() -> None:
    corpus = load_payload_corpus()
    delta = PayloadCorpusDelta(
        slot_alternatives=(
            PayloadSlotAlternative(
                production_id="sql-ansi",
                slot_name="terminator",
                alternatives=("\n", " ", "\t"),
            ),
        )
    )
    guardrail = PayloadCorpusGuardrail(max_total_alternatives=1)

    reasons = guardrail.rejection_reasons(delta)

    assert "delta alternative cap exceeded" in reasons
    with pytest.raises(ValueError, match="delta alternative cap exceeded"):
        merge_payload_corpus_delta(corpus, delta, guardrail)


def test_payload_corpus_store_grows_versioned_data_with_audit_trail() -> None:
    corpus = load_payload_corpus()
    store = PayloadCorpusStore(corpus)
    delta = PayloadCorpusDelta(
        slot_alternatives=(
            PayloadSlotAlternative(
                production_id="sql-ansi",
                slot_name="terminator",
                alternatives=("\n",),
            ),
        )
    )
    audit = PayloadCorpusAuditRecord(
        record_id="record",
        deficit_id="payload_entropy|action:get|inv|scenario",
        action="action:get",
        status="promoted",
        reason="",
        history_digest="history",
        proposal_digest="proposal",
        prompt_hash="prompt",
        graph_slice_hash="slice",
        model_version="model",
        input_tokens=1,
        cached_input_tokens=0,
        output_tokens=2,
        latency_ms=3.0,
        depth=0,
        base_corpus_version=corpus.corpus_version,
        promoted_slot_alternatives=("sql-ansi.terminator",),
        promoted_items=1,
        delta=delta,
    )

    assert store.record(audit, delta=delta)

    assert store.corpus.corpus_version == "3"
    production = next(
        item for item in store.corpus.productions if item.production_id == "sql-ansi"
    )
    slot = next(item for item in production.slots if item.name == "terminator")
    assert "\n" in slot.alternatives
    recorded = store.audit_trail[0]
    assert recorded.record_id == "record"
    assert recorded.next_corpus_version == "3"
    assert recorded.delta == delta


def test_payload_delta_can_extend_repeat_bounds_without_new_terminals() -> None:
    corpus = load_payload_corpus()
    delta = PayloadCorpusDelta(
        slot_alternatives=(
            PayloadSlotAlternative(
                production_id="sql-ansi",
                slot_name="terminator",
                alternatives=("--",),
                repeat_min=2,
                repeat_max=4,
            ),
        )
    )

    merged = merge_payload_corpus_delta(corpus, delta)

    production = next(
        item for item in merged.productions if item.production_id == "sql-ansi"
    )
    slot = next(item for item in production.slots if item.name == "terminator")
    assert (slot.repeat_min, slot.repeat_max) == (2, 4)
