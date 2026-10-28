from __future__ import annotations

import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENGINE_ROOT = PROJECT_ROOT / "packages/core/src/cloud_dast"


def _is_benchmark_module(name: str | None) -> bool:
    return name == "benchmarks" or bool(name and name.startswith("benchmarks."))


def test_engine_never_imports_benchmark_harness() -> None:
    """Keep benchmark adapters outside the generic engine dependency graph."""

    violations: list[str] = []
    for path in sorted(ENGINE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if _is_benchmark_module(alias.name):
                        violations.append(f"{path}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if _is_benchmark_module(node.module):
                    violations.append(f"{path}: from {node.module} import ...")
            elif (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and _is_benchmark_module(node.value)
            ):
                violations.append(f"{path}: dynamic benchmark reference {node.value!r}")

    assert not violations, "\n".join(violations)
