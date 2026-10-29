"""Fitness checks for the canonical domain-model boundary."""

from __future__ import annotations

import ast
from pathlib import Path

import cloud_dast.model as model

_SOURCE_ROOT = Path(__file__).parents[2] / "packages/core/src/cloud_dast"
_MODEL_ROOT = _SOURCE_ROOT / "model"
_CONTRACTS_ROOT = _SOURCE_ROOT / "contracts"
_REMOVED_TECHNICAL_MODULES = (
    "feedback.py",
    "grammar.py",
    "payloads.py",
    "payload_proposals.py",
    "proposals.py",
    "couplings.py",
    "evidence_facts.py",
    "replay.py",
)

_CANONICAL_EXPORTS = {
    "ANONYMOUS_PRINCIPAL_ID",
    "AccessOutcome",
    "AddressingMode",
    "BindingLevel",
    "BindingRef",
    "Check",
    "EndpointLayer",
    "ExecutionTrace",
    "FieldSpec",
    "Finding",
    "FindingFingerprint",
    "GeneratorName",
    "IdentityClass",
    "JsonValue",
    "MessageSchema",
    "MethodSpec",
    "Observation",
    "OracleDeficit",
    "OracleDeficitKind",
    "PolicyVerdict",
    "PrincipalRef",
    "RequestSchema",
    "ResourceRef",
    "ResourceState",
    "ResponseData",
    "ResponseSchema",
    "ScenarioPosition",
    "ScenarioProfile",
    "ScopeRelation",
    "Severity",
    "StandState",
    "TraceStep",
    "TransportStatus",
    "VerdictStatus",
}

_FORBIDDEN_OUTWARD_PACKAGES = {
    "application",
    "composition",
    "infrastructure",
    "presentation",
    "runtime",
}


def _imports(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.append(node.module)
    return tuple(modules)


def test_model_facade_exports_only_canonical_domain_contracts() -> None:
    assert set(model.__all__) == _CANONICAL_EXPORTS
    assert all(hasattr(model, name) for name in model.__all__)
    assert not hasattr(model, "EvidenceEvent")
    assert not hasattr(model, "EvidenceChannelKind")
    assert not hasattr(model, "severity_score")
    assert not hasattr(model, "response_tree_digest")
    assert not hasattr(model, "InvariantProjection")
    assert not hasattr(model, "VerificationPlan")
    assert not hasattr(model, "InvestigationIntent")
    for helper in ("float_range", "integer_range", "is_float_type", "is_integer_type"):
        assert not hasattr(model, helper)
    for extension_type in (
        "ExecutionFeedback",
        "ExecutionFeedbackEntry",
        "GrammarConstraint",
        "GrammarFacts",
        "GrammarFieldRule",
        "GrammarSolution",
        "PayloadCorpus",
        "PayloadCorpusDelta",
        "SeedEnrichmentModelWireOutput",
    ):
        assert not hasattr(model, extension_type)


def test_model_modules_do_not_depend_on_imperative_layers() -> None:
    violations = [
        (path.relative_to(_SOURCE_ROOT), module)
        for path in sorted(_MODEL_ROOT.rglob("*.py"))
        for module in _imports(path)
        if (
            module.startswith("cloud_dast.")
            and len(module.split(".")) > 1
            and module.split(".")[1] in _FORBIDDEN_OUTWARD_PACKAGES
        )
    ]

    assert violations == []


def test_shared_contracts_do_not_depend_on_imperative_layers() -> None:
    violations = [
        (path.relative_to(_SOURCE_ROOT), module)
        for path in sorted(_CONTRACTS_ROOT.rglob("*.py"))
        for module in _imports(path)
        if (
            module.startswith("cloud_dast.")
            and len(module.split(".")) > 1
            and module.split(".")[1] in _FORBIDDEN_OUTWARD_PACKAGES
        )
    ]

    assert violations == []


def test_domain_model_decision_record_exists() -> None:
    document = _SOURCE_ROOT.parent.parent.parent.parent / "docs/domain-model.md"
    text = document.read_text(encoding="utf-8")

    for concept in ("MethodSpec", "Check", "Observation", "Finding"):
        assert f"`{concept}`" in text


def test_bound_scenario_has_one_canonical_model() -> None:
    source = (_MODEL_ROOT / "checks.py").read_text(encoding="utf-8")
    document = _SOURCE_ROOT.parent.parent.parent.parent / "docs/domain-model.md"
    text = document.read_text(encoding="utf-8")
    assert source.count("class ScenarioProfile(") == 1
    assert source.count("class StandState(") == 1
    assert source.count("class ScenarioPosition(") == 1
    assert "class BoundScenario(" not in source
    assert "BoundScenario" in text


def test_technical_contracts_have_explicit_owners() -> None:
    assert not any((_MODEL_ROOT / name).exists() for name in _REMOVED_TECHNICAL_MODULES)
    assert (_SOURCE_ROOT / "contracts/feedback.py").exists()
    assert (_SOURCE_ROOT / "runtime/candidates/feedback.py").exists()
    assert (_SOURCE_ROOT / "contracts/grammar.py").exists()
    assert (_SOURCE_ROOT / "contracts/payloads.py").exists()
    assert (_SOURCE_ROOT / "contracts/payload_proposals.py").exists()
    assert (_SOURCE_ROOT / "contracts/proposals.py").exists()
    assert (_SOURCE_ROOT / "verification/evidence_facts.py").exists()
