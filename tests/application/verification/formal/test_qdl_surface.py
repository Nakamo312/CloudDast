from pathlib import Path

from cloud_dast.qdl.compiler import QdlCompiler
from cloud_dast.qdl.engine import ClingoEngine
from cloud_dast.qdl.parser import parse_document
from cloud_dast.qdl.renderer import render_qdl


def test_surface_document_compiles_sections_rules_and_metadata() -> None:
    source = """
meta:
  source: "contract:profiles"
  provenance: "adapter:v1"

contract:
  is(action:read_profile, Action)
  is(norm:profile_visibility, Norm)
  causes(action:read_profile, allowed(action:read_profile))

accepted:
  prevents(norm:profile_visibility, allowed(action:read_profile))
  attacker($X) :- is(action:read_profile, $X)

uncertainty:
  uncertainty("response.body.owner", "provide a complete response example")
"""

    result = QdlCompiler().compile(source)

    assert result.valid
    assert result.graph is not None
    assert result.metadata.source == "contract:profiles"
    assert result.metadata.provenance == "adapter:v1"
    assert result.metadata.uncertainties == (
        ("response.body.owner", "provide a complete response example"),
    )
    assert any(fact.predicate.name == "prevents" for fact in result.graph.facts)
    assert result.graph.rules[0].body[0].context.value == "accepted"


def test_surface_diagnostics_keep_line_and_column() -> None:
    document, diagnostics = parse_document(
        "contract:\n  is(action:read_profile, Action)\n  broken(\n"
    )

    assert document is not None
    assert diagnostics
    assert diagnostics[0].code == "syntax"
    assert diagnostics[0].span is not None
    assert diagnostics[0].span.line == 3
    assert diagnostics[0].format().startswith("line 3, column")


def test_surface_rule_grammar_preserves_nested_terms_and_body_positions() -> None:
    document, diagnostics = parse_document(
        "contract:\n"
        "  emits(wrapper(left, right)) :- source(wrapper(left, right)), marker(x)\n"
    )

    assert not diagnostics
    assert document is not None
    assert len(document.rules) == 1
    rule = document.rules[0]
    assert rule.head.predicate == "emits"
    assert rule.head.args[0].args[0].value == "left"
    assert rule.body[1].predicate == "marker"
    assert rule.body[1].span is not None
    assert rule.body[1].span.column > rule.body[0].span.column


def test_compiler_reports_unknown_predicate_without_creating_graph() -> None:
    result = QdlCompiler().compile("contract:\n  made_up(action:x)\n")

    assert not result.valid
    assert result.graph is None
    assert result.diagnostics[0].code == "semantic"
    assert "unknown predicate" in result.diagnostics[0].message
    assert result.diagnostics[0].path == "facts[0]"


def test_surface_diagnostics_reject_unknown_section() -> None:
    document, diagnostics = parse_document("mystery:\n  is(action:x, Action)\n")

    assert document is not None
    assert diagnostics[0].code == "section"
    assert diagnostics[0].span is not None
    assert diagnostics[0].span.line == 1


def test_renderer_is_canonical_for_compiled_graph() -> None:
    source = """contract:
  is(action:read_profile, Action)
  is(norm:profile_visibility, Norm)

accepted:
  prevents(norm:profile_visibility, allowed(action:read_profile))
  attacker($X) :- is(action:read_profile, $X)
"""
    first = QdlCompiler().compile(source)
    assert first.valid and first.graph is not None

    rendered = render_qdl(first.graph)
    second = QdlCompiler().compile(rendered)

    assert second.valid and second.graph is not None
    assert second.graph.content_hash == first.graph.content_hash


def test_renderer_round_trips_sidecar_metadata() -> None:
    first = QdlCompiler().compile(
        "meta:\n"
        '  source: "contract:profiles"\n'
        '  provenance: "adapter:v1"\n'
        '  ticket: "CLOUD-42"\n'
        "contract:\n"
        "  is(action:read_profile, Action)\n"
        "uncertainty:\n"
        '  uncertainty("response.body", "need a complete example")\n'
    )
    assert first.valid and first.graph is not None

    rendered = render_qdl(first.graph, metadata=first.metadata)
    second = QdlCompiler().compile(rendered)

    assert second.valid
    assert second.metadata == first.metadata


def test_query_layers_use_the_canonical_clingo_boundary() -> None:
    assert hasattr(ClingoEngine, "solve_program")
    state_machine_path = (
        Path(__file__).parents[4] / "packages/core/src/cloud_dast/qdl/state_machine.py"
    )
    assert "clingo.Control()" not in state_machine_path.read_text()
    planner_path = (
        Path(__file__).parents[4]
        / "packages/core/src/cloud_dast/runtime/planning/core.py"
    )
    assert "clingo.Control()" not in planner_path.read_text()
