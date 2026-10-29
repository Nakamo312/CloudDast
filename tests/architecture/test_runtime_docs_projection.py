"""S22R: project runtime facts into documentation and reject drift."""

from __future__ import annotations

import ast
import inspect
import re
from dataclasses import dataclass, fields
from pathlib import Path
from typing import get_args, get_type_hints

import pytest

from cloud_dast.config import QDL_MAX_DEPTH
from cloud_dast.consultation import (
    axis_for_predicate_class,
)
from cloud_dast.contracts.assessment import COVERAGE_FACTORS
from cloud_dast.qdl.graph import Context
from cloud_dast.qdl.reasoning import QdlPlan
from cloud_dast.runtime.consultation.outcomes import (
    CONSULTATION_OUTCOMES,
)
from cloud_dast.runtime.grounding.state import ParkedLeadState
from cloud_dast.runtime.planning import ATTACK_CLOSURE, PLANNING_CONTEXTS

ROOT = Path(__file__).resolve().parents[2]
CORE_SRC = ROOT / "packages" / "core" / "src"
README = ROOT / "README.md"
ENGINE_RUNTIME = ROOT / "docs" / "engine-runtime-2026-10-19.md"
RUN_PROVIDER = CORE_SRC / "cloud_dast" / "composition" / "run_provider.py"
CAMPAIGN_GRAPHS = CORE_SRC / "cloud_dast" / "runtime" / "campaign" / "graph.py"


@dataclass(frozen=True, slots=True)
class ProviderFact:
    scope: str
    method: str
    provides: str


def _projection(document: str, name: str) -> str:
    pattern = re.compile(
        rf"<!-- runtime-projection:{re.escape(name)} -->\n"
        rf"(.*?)\n"
        rf"<!-- /runtime-projection:{re.escape(name)} -->",
        flags=re.DOTALL,
    )
    matches = pattern.findall(document)
    assert len(matches) == 1, f"projection {name!r} must occur exactly once"

    lines = matches[0].strip().splitlines()
    if lines and lines[0].startswith("```"):
        assert lines[-1].strip() == "```", "projection code fence is unclosed"
        lines = lines[1:-1]
    return "\n".join(lines).strip()


def _provider_facts() -> tuple[ProviderFact, ...]:
    tree = ast.parse(RUN_PROVIDER.read_text(encoding="utf-8"))
    provider = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "RunProvider"
    )

    facts: list[ProviderFact] = []
    for method in provider.body:
        if not isinstance(method, ast.FunctionDef):
            continue
        for decorator in method.decorator_list:
            if not (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Name)
                and decorator.func.id == "provide"
            ):
                continue

            scope = "RunScope"
            provides = method.name
            for keyword in decorator.keywords:
                if keyword.arg == "scope":
                    scope = ast.unparse(keyword.value)
                elif keyword.arg == "provides":
                    provides = ast.unparse(keyword.value)
            facts.append(ProviderFact(scope, method.name, provides))

    assert facts, "RunProvider has no Dishka providers"
    return tuple(facts)


def _render_provider_surface() -> str:
    facts = _provider_facts()
    lines: list[str] = []
    for scope in ("AppScope", "RunScope"):
        methods = sorted(fact.method for fact in facts if fact.scope == scope)
        assert methods, f"{scope} has no providers"
        lines.append(f"{scope} providers:")
        lines.extend(f"  {method}" for method in methods)

    ports = sorted({fact.provides for fact in facts if fact.provides != fact.method})
    lines.append("Explicit ports:")
    lines.extend(f"  {port}" for port in ports)
    return "\n".join(lines)


def _source_selector(argument: ast.expr) -> str | None:
    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
        return argument.value
    if not isinstance(argument, ast.JoinedStr):
        return None

    parts: list[str] = []
    for value in argument.values:
        if isinstance(value, ast.Constant):
            parts.append(str(value.value))
        elif isinstance(value, ast.FormattedValue):
            parts.append("{service}")
        else:
            return None
    return "".join(parts)


def _render_qdl_sources() -> str:
    tree = ast.parse(CAMPAIGN_GRAPHS.read_text(encoding="utf-8"))
    assembler = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "Assembler"
    )
    load_graph = next(
        node
        for node in assembler.body
        if isinstance(node, ast.FunctionDef) and node.name == "_source"
    )

    selectors: set[str] = set()
    for call in ast.walk(load_graph):
        if not (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr in {"load", "load_merged"}
            and call.args
        ):
            continue
        selector = _source_selector(call.args[0])
        if selector is None:
            continue
        if call.func.attr == "load_merged" and selector.endswith(":"):
            selector += "*"
        selectors.add(selector)

    assert selectors, "ScenarioBinder loads no QDL sources"
    return "\n".join(sorted(selectors))


def _render_planner_surface() -> str:
    planning_contexts = tuple(context.value for context in PLANNING_CONTEXTS)
    non_planning_contexts = tuple(
        context.value for context in Context if context not in PLANNING_CONTEXTS
    )
    plan_fields = tuple(field.name for field in fields(QdlPlan))
    return "\n".join(
        (
            f"planning contexts: {', '.join(planning_contexts)}",
            f"non-planning contexts: {', '.join(non_planning_contexts)}",
            f"plan fields: {', '.join(plan_fields)}",
            f"default max depth: {QDL_MAX_DEPTH}",
            f"default closure: {ATTACK_CLOSURE}",
        )
    )


def _render_sibling_invariants() -> str:
    signature = inspect.signature(axis_for_predicate_class)
    assert tuple(signature.parameters)[:1] == ("predicate_class",)
    evidence_hint = get_type_hints(axis_for_predicate_class)["evidence"]
    evidence_type = next(
        (
            argument
            for argument in get_args(evidence_hint)
            if argument is not type(None)
        ),
        evidence_hint,
    )
    evidence_context = "_".join(
        part.lower() for part in re.findall("[A-Z][^A-Z]*", evidence_type.__name__)
    )

    lead_state = ParkedLeadState(
        fact_key="fact-key",
        fact_hash="fact-hash",
        action="action",
        holder="holder",
        role="role",
        evidence_signature="evidence_signature",
        evidence_refs=frozenset(),
        confirmations=0,
    )

    return "\n".join(
        (
            "S21R: axis = f("
            f"{next(iter(signature.parameters))}, {evidence_context}"
            "); absent image = consultation_deficit(predicate_class)",
            f"S24R: coverage(term) = {' × '.join(COVERAGE_FACTORS)}",
            f"S32R: lead_key = {', '.join(lead_state.lead_key)}",
            f"S33R: outcomes = {', '.join(sorted(CONSULTATION_OUTCOMES))}",
        )
    )


def test_qdl_sources_are_projected_into_both_documents() -> None:
    expected = _render_qdl_sources()

    assert _projection(README.read_text(encoding="utf-8"), "qdl-sources") == expected
    assert (
        _projection(ENGINE_RUNTIME.read_text(encoding="utf-8"), "qdl-sources")
        == expected
    )


def test_planner_surface_is_projected_into_both_documents() -> None:
    expected = _render_planner_surface()

    assert _projection(README.read_text(encoding="utf-8"), "qdl-planner") == expected
    assert (
        _projection(ENGINE_RUNTIME.read_text(encoding="utf-8"), "qdl-planner")
        == expected
    )


def test_run_provider_surface_is_projected_into_engine_runtime() -> None:
    document = ENGINE_RUNTIME.read_text(encoding="utf-8")

    assert _projection(document, "run-provider") == _render_provider_surface()


def test_sibling_invariants_are_projected_without_conflicts() -> None:
    document = ENGINE_RUNTIME.read_text(encoding="utf-8")

    assert _projection(document, "sibling-invariants") == _render_sibling_invariants()


@pytest.mark.parametrize(
    "path",
    [README, ENGINE_RUNTIME],
    ids=["readme", "engine-runtime"],
)
def test_known_stale_runtime_claims_are_absent(path: Path) -> None:
    document = path.read_text(encoding="utf-8")
    stale_claims = (
        "Live runtime читает три QDL-источника",
        "Coverage считается по двум осям",
        "LLM: ровно три роли",
        "Composition-root пока не выбирает его по умолчанию",
        "не является default wiring",
        "ScenarioRepository      <- Neo4jScenarioRepository",
        "1360 passed",
    )

    assert not any(claim in document for claim in stale_claims)
