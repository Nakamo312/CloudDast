"""Layer-model regression for the ports-and-adapters invariant.

The target architecture has no application layer.  This check covers the
remaining outward-facing boundaries and parses every module with ``ast`` so
lazy imports inside functions are covered too.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]

FORBIDDEN_DEPENDENCIES = {
    "model": ("runtime", "verification", "infrastructure", "composition"),
    "qdl": ("runtime", "infrastructure", "composition"),
    "runtime": ("infrastructure", "composition"),
    "verification": ("runtime", "infrastructure", "composition"),
    "infrastructure": ("runtime", "composition"),
}


def test_root_package_has_no_import_facade() -> None:
    """The root package must stay import-light and layer-neutral."""

    path = _REPO_ROOT / "packages/core/src/cloud_dast" / "__init__.py"
    tree = ast.parse(path.read_text())
    imports = [
        node for node in ast.walk(tree) if isinstance(node, ast.Import | ast.ImportFrom)
    ]
    exports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign | ast.AnnAssign)
        and _assignment_target_names(node) == {"__all__"}
    ]

    assert not imports
    assert not exports


def test_application_layer_has_been_removed() -> None:
    assert not (_REPO_ROOT / "packages/core/src/cloud_dast/application").exists()


def _assignment_target_names(node: ast.Assign | ast.AnnAssign) -> set[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return {target.id for target in targets if isinstance(target, ast.Name)}


def _imported_cloud_dast_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return {
        module
        for module in modules
        if module == "cloud_dast" or module.startswith("cloud_dast.")
    }


@pytest.mark.parametrize(("layer", "forbidden"), FORBIDDEN_DEPENDENCIES.items())
def test_layer_never_imports_outward(layer: str, forbidden: tuple[str, ...]) -> None:
    layer_root = _REPO_ROOT / "packages/core/src/cloud_dast" / layer
    assert layer_root.is_dir(), f"missing layer directory: {layer_root}"

    violations: list[str] = []
    for path in sorted(layer_root.rglob("*.py")):
        for module in _imported_cloud_dast_modules(path):
            parts = module.split(".")
            if len(parts) >= 2 and parts[1] in forbidden:
                violations.append(f"{path.relative_to(_REPO_ROOT)}: {module}")

    assert not violations, (
        f"{layer} layer imports forbidden packages: {', '.join(violations)}"
    )
