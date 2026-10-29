from __future__ import annotations

from cloud_dast_reporting import OwaspSlice, owasp_distribution
from cloud_dast_reporting.formats.charts import (
    category_title,
    render_owasp_ascii_donut,
    render_owasp_donut_svg,
)


class _TaggedFinding:
    def __init__(self, *categories: str) -> None:
        self.owasp = categories


def test_owasp_distribution_counts_multi_tag_findings_in_each_category() -> None:
    findings = (
        _TaggedFinding("API1"),
        _TaggedFinding("API1", "API3"),
        _TaggedFinding(),
    )

    slices = owasp_distribution(findings)

    assert [(s.category, s.count) for s in slices] == [
        ("API1", 2),
        ("API3", 1),
        ("unclassified", 1),
    ]
    assert sum(s.ring_fraction for s in slices) == 1.0


def test_owasp_distribution_is_deterministic_and_handles_empty() -> None:
    assert owasp_distribution(()) == ()

    first = owasp_distribution((_TaggedFinding("API7"), _TaggedFinding("API2")))
    second = owasp_distribution((_TaggedFinding("API7"), _TaggedFinding("API2")))

    assert first == second
    # Equal counts are ordered by category name.
    assert [s.category for s in first] == ["API2", "API7"]


def test_svg_donut_is_deterministic_and_draws_one_path_per_slice() -> None:
    slices = (
        OwaspSlice("API1", 6, 0.6),
        OwaspSlice("API3", 4, 0.4),
    )

    first = render_owasp_donut_svg(slices, total_findings=10)
    second = render_owasp_donut_svg(slices, total_findings=10)

    assert first == second
    assert first.count("<path") == 2
    assert ">10</text>" in first
    assert category_title("API1") in first


def test_svg_donut_splits_single_slice_into_two_halves() -> None:
    svg = render_owasp_donut_svg((OwaspSlice("API5", 3, 1.0),), total_findings=3)

    assert svg.count("<path") == 2


def test_svg_donut_draws_empty_ring_without_findings() -> None:
    svg = render_owasp_donut_svg((), total_findings=0)

    assert svg.count("<path") == 1
    assert ">0</text>" in svg


def test_ascii_donut_renders_total_and_ring_characters() -> None:
    slices = (
        OwaspSlice("API1", 7, 0.7),
        OwaspSlice("API8", 3, 0.3),
    )

    text = render_owasp_ascii_donut(slices, total_findings=10)

    assert "10" in text
    assert "findings" in text
    assert "█" in text
    assert "▓" in text


def test_ascii_donut_reports_empty_distribution() -> None:
    assert render_owasp_ascii_donut((), total_findings=0) == "(no findings to chart)"
