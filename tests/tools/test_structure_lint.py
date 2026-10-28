from __future__ import annotations

from pathlib import Path

from tools.structure_lint import check_file


def _write(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "sample.py"
    path.write_text(source, encoding="utf-8")
    return path


def _write_nested(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "qdl" / "qdl_graph.py"
    path.parent.mkdir()
    path.write_text(source, encoding="utf-8")
    return path


def test_structural_rules_report_their_own_categories(tmp_path: Path) -> None:
    source = '''
"""Synthetic structural-lint fixture."""

from __future__ import annotations
from one import a, b, c
from two import d, e, f


class ThisClassNameIsDeliberatelyMuchLongerThanTheLimit:
    def build_builder(self, first, second, third, fourth):
        if first and second and third:
            return fourth
        return None
'''
    findings = check_file(
        _write(tmp_path, source),
        {
            "function-max-lines": 4,
            "signature-max-parameters": 3,
            "module-max-imports": 4,
            "cyclomatic-max": 2,
            "name-max-length": 20,
        },
    )

    codes = {finding.code for finding in findings}
    assert {"SL101", "SL102", "SL103", "SL104", "SL105"} <= codes


def test_nested_functions_are_checked_without_counting_their_body_twice(
    tmp_path: Path,
) -> None:
    source = """
def outer(value):
    def inner(item):
        return item
    return inner(value)
"""
    findings = check_file(
        _write(tmp_path, source),
        {
            "function-max-lines": 2,
            "signature-max-parameters": 8,
            "module-max-imports": 40,
            "cyclomatic-max": 15,
            "name-max-length": 48,
        },
    )

    assert [(finding.code, finding.line) for finding in findings] == [("SL100", 2)]


def test_hierarchy_names_are_reported_at_each_repeated_boundary(tmp_path: Path) -> None:
    source = """
class QdlGraph:
    def qdl_graph(self):
        return None

def qdl_graph():
    return None

def _qdl():
    return None
"""
    findings = check_file(
        _write_nested(tmp_path, source),
        {
            "function-max-lines": 100,
            "signature-max-parameters": 8,
            "module-max-imports": 40,
            "cyclomatic-max": 15,
            "name-max-length": 48,
            "name-max-words": 5,
        },
    )

    hierarchy = [finding for finding in findings if finding.code == "SL106"]
    assert len(hierarchy) == 6
    assert any("package directory 'qdl'" in finding.message for finding in hierarchy)
    assert any(
        "parent namespace 'QdlGraph'" in finding.message for finding in hierarchy
    )
    assert (
        sum("parent namespace 'qdl_graph'" in finding.message for finding in hierarchy)
        == 2
    )


def test_class_name_cannot_repeat_its_package_directory(tmp_path: Path) -> None:
    path = tmp_path / "campaign" / "finalization.py"
    path.parent.mkdir()
    path.write_text(
        "class CampaignFinalizer:\n    pass\n",
        encoding="utf-8",
    )

    findings = check_file(
        path,
        {
            "function-max-lines": 100,
            "signature-max-parameters": 8,
            "module-max-imports": 40,
            "cyclomatic-max": 15,
            "name-max-length": 48,
            "name-max-words": 5,
        },
    )

    assert any(
        finding.code == "SL106" and "parent namespace 'campaign'" in finding.message
        for finding in findings
    )


def test_word_soup_names_are_reported_separately(tmp_path: Path) -> None:
    source = """
def build_secure_authenticated_resource_request(value):
    return value
"""
    findings = check_file(
        _write(tmp_path, source),
        {
            "function-max-lines": 100,
            "signature-max-parameters": 8,
            "module-max-imports": 40,
            "cyclomatic-max": 15,
            "name-max-length": 48,
            "name-max-words": 4,
        },
    )

    assert [(finding.code, finding.line) for finding in findings] == [("SL107", 2)]
