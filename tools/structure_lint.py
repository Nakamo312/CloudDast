"""Structural quality checks for Python modules.

The project uses Ruff for syntax, style, imports, and McCabe checks.  This
small AST linter complements Ruff with the structural checks that are not
available as stable, project-local rules: oversized function bodies, import
blocks, symbol names, and tautological function names.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

DEFAULT_CONFIG = {
    "function-max-lines": 100,
    "signature-max-parameters": 8,
    "module-max-imports": 40,
    "cyclomatic-max": 15,
    "name-max-length": 48,
    "name-max-words": 5,
}

RULE_NAMES = {
    "SL100": "function body is too large",
    "SL101": "function signature has too many parameters",
    "SL102": "module import block is too large",
    "SL103": "function is too complex",
    "SL104": "class/function/method name is too long",
    "SL105": "function name is tautological",
    "SL106": "name repeats its parent namespace",
    "SL107": "name contains too many words",
}

_NAME_PART = re.compile(r"[A-Z]+(?=[A-Z][a-z]|[0-9]|$)|[A-Z]?[a-z]+|[0-9]+")
_REDUNDANT_PAIRS = {
    frozenset(pair)
    for pair in (
        ("build", "builder"),
        ("compile", "compiler"),
        ("create", "creator"),
        ("execute", "execution"),
        ("generate", "generator"),
        ("parse", "parser"),
        ("record", "recorder"),
        ("resolve", "resolver"),
        ("serialize", "serializer"),
        ("validate", "validation"),
        ("classify", "classification"),
        ("project", "projection"),
    )
}


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    code: str
    message: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.code} {self.message}"


def _load_config(config_path: Path) -> dict[str, int]:
    if not config_path.exists():
        return DEFAULT_CONFIG.copy()
    with config_path.open("rb") as stream:
        project = tomllib.load(stream).get("tool", {})
    configured = project.get("structure-lint", {})
    config = DEFAULT_CONFIG.copy()
    for key in config:
        value = configured.get(key)
        if value is not None:
            config[key] = int(value)
    return config


def _iter_python_files(paths: Iterable[Path]) -> Iterator[Path]:
    seen: set[Path] = set()
    for path in paths:
        if path.is_file():
            candidates = (path,) if path.suffix == ".py" else ()
        elif path.is_dir():
            candidates = path.rglob("*.py")
        else:
            candidates = ()
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved not in seen:
                seen.add(resolved)
                yield candidate


def _qualified_name(stack: tuple[str, ...], name: str) -> str:
    return ".".join((*stack, name))


def _function_parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    args = node.args
    count = (
        len(args.posonlyargs)
        + len(args.args)
        + len(args.kwonlyargs)
        + (args.vararg is not None)
        + (args.kwarg is not None)
    )
    if args.args and args.args[0].arg in {"self", "cls"}:
        count -= 1
    return count


class _ComplexityVisitor(ast.NodeVisitor):
    """Small McCabe-compatible complexity counter for one function body."""

    def __init__(self) -> None:
        self.complexity = 1

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is not self.root:
            return
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if node is not self.root:
            return
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_If(self, node: ast.If) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.complexity += max(0, len(node.values) - 1)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        self.complexity += len(node.cases)
        self.generic_visit(node)


def _complexity(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    visitor = _ComplexityVisitor()
    visitor.root = node
    visitor.visit(node)
    return visitor.complexity


def _name_parts(name: str) -> list[str]:
    parts: list[str] = []
    for underscore_part in name.split("_"):
        parts.extend(
            match.group(0).lower() for match in _NAME_PART.finditer(underscore_part)
        )
    return parts


def _tautology_reason(name: str) -> str | None:
    parts = _name_parts(name)
    if any(left == right for left, right in zip(parts, parts[1:])):
        return "repeats the same word"
    for pair in _REDUNDANT_PAIRS:
        if pair.issubset(parts):
            return f"combines redundant words: {' / '.join(sorted(pair))}"
    return None


def _hierarchy_reason(parent: str, child: str) -> str | None:
    parent_parts = _name_parts(parent)
    child_parts = _name_parts(child)
    if parent_parts and child_parts[: len(parent_parts)] == parent_parts:
        return f"repeats parent namespace {parent!r} in {child!r}"
    return None


def _path_hierarchy_findings(path: Path) -> list[Finding]:
    package = path.parent.name
    module = path.stem
    if not package or package in {".", module}:
        return []
    if _hierarchy_reason(package, module) is None:
        return []
    return [
        Finding(
            path,
            1,
            "SL106",
            f"module {module!r} repeats package directory {package!r}",
        )
    ]


class _ModuleChecker(ast.NodeVisitor):
    def __init__(self, path: Path, config: dict[str, int]) -> None:
        self.path = path
        self.config = config
        self.findings: list[Finding] = []
        self._scope: tuple[str, ...] = ()
        self._class_scope: list[str] = []
        self._function_scope: list[str] = []
        self._module_name = path.stem
        self._package_name = path.parent.name

    def add(
        self, node: ast.AST, code: str, message: str, *, line: int | None = None
    ) -> None:
        self.findings.append(
            Finding(self.path, line or getattr(node, "lineno", 1), code, message)
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if len(node.name) > self.config["name-max-length"]:
            self.add(
                node,
                "SL104",
                f"class name {node.name!r} has {len(node.name)} characters "
                f"(max {self.config['name-max-length']})",
            )
        self._check_hierarchy(node, node.name, parent=self._module_name)
        self._check_hierarchy(node, node.name, parent=self._package_name)
        self._check_word_count(node, node.name)
        previous = self._scope
        self._class_scope.append(node.name)
        self._scope = (*previous, node.name)
        self.generic_visit(node)
        self._scope = previous
        self._class_scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualified = _qualified_name(self._scope, node.name)
        lines = node.end_lineno - node.lineno + 1
        if lines > self.config["function-max-lines"]:
            self.add(
                node,
                "SL100",
                f"{qualified} spans {lines} lines "
                f"(max {self.config['function-max-lines']})",
            )

        parameters = _function_parameters(node)
        if parameters > self.config["signature-max-parameters"]:
            self.add(
                node,
                "SL101",
                f"{qualified} has {parameters} parameters "
                f"(max {self.config['signature-max-parameters']})",
            )

        complexity = _complexity(node)
        if complexity > self.config["cyclomatic-max"]:
            self.add(
                node,
                "SL103",
                f"{qualified} has cyclomatic complexity {complexity} "
                f"(max {self.config['cyclomatic-max']})",
            )

        if len(node.name) > self.config["name-max-length"]:
            self.add(
                node,
                "SL104",
                f"{qualified} name has {len(node.name)} characters "
                f"(max {self.config['name-max-length']})",
            )

        if (reason := _tautology_reason(node.name)) is not None:
            self.add(node, "SL105", f"{qualified} {reason}")

        if not self._function_scope and self._class_scope:
            self._check_hierarchy(node, node.name, parent=self._class_scope[-1])
        elif not self._scope:
            for parent in (self._module_name, self._package_name):
                if _hierarchy_reason(parent, node.name) is not None:
                    self._check_hierarchy(node, node.name, parent=parent)
                    break
        self._check_word_count(node, node.name)

        previous = self._scope
        self._function_scope.append(node.name)
        self._scope = (*previous, node.name)
        self.generic_visit(node)
        self._scope = previous
        self._function_scope.pop()

    def _check_hierarchy(self, node: ast.AST, name: str, *, parent: str) -> None:
        if (reason := _hierarchy_reason(parent, name)) is not None:
            self.add(node, "SL106", reason)

    def _check_word_count(self, node: ast.AST, name: str) -> None:
        words = len(_name_parts(name))
        max_words = self.config.get("name-max-words", DEFAULT_CONFIG["name-max-words"])
        if words > max_words:
            self.add(
                node,
                "SL107",
                f"{name!r} has {words} word parts (max {max_words})",
            )


def _check_import_block(
    tree: ast.Module, path: Path, config: dict[str, int]
) -> list[Finding]:
    body = list(tree.body)
    index = 0
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        index += 1
    aliases = 0
    first_import: ast.AST | None = None
    last_import: ast.AST | None = None
    while index < len(body):
        node = body[index]
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            index += 1
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if first_import is None:
                first_import = node
            last_import = node
            aliases += len(node.names)
            index += 1
            continue
        break
    if (
        aliases <= config["module-max-imports"]
        or first_import is None
        or last_import is None
    ):
        return []
    return [
        Finding(
            path,
            getattr(first_import, "lineno", 1),
            "SL102",
            f"top-level import block has {aliases} imported names "
            f"(max {config['module-max-imports']}; ends at line "
            f"{getattr(last_import, 'end_lineno', getattr(last_import, 'lineno', 1))})",
        )
    ]


def check_file(path: Path, config: dict[str, int]) -> list[Finding]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as exc:
        return [Finding(path, getattr(exc, "lineno", 1) or 1, "SL000", str(exc))]
    checker = _ModuleChecker(path, config)
    checker.visit(tree)
    checker.findings.extend(_path_hierarchy_findings(path))
    checker.findings.extend(_check_import_block(tree, path, config))
    return sorted(
        checker.findings, key=lambda item: (item.line, item.code, item.message)
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=[Path("packages/core/src/cloud_dast")],
    )
    parser.add_argument("--config", type=Path, default=Path("pyproject.toml"))
    args = parser.parse_args(argv)
    config = _load_config(args.config)
    findings = [
        finding
        for path in _iter_python_files(args.paths)
        for finding in check_file(path, config)
    ]
    for finding in sorted(
        findings, key=lambda item: (str(item.path), item.line, item.code)
    ):
        print(finding.render())
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
