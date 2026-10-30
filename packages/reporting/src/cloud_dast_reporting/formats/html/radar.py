"""Deterministic OWASP API radar projection for the HTML report.

The catalog keeps compact API codes; this module owns the 2019-to-2023
nomenclature mapping used for presentation.  No benchmark identifiers or
per-class detection rules live here.
"""

from __future__ import annotations

import html
import math
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from cloud_dast.api import DEFAULT_CATALOG
from cloud_dast_reporting import ReportBundle

_OWASP_API_2023: dict[str, tuple[str, str]] = {
    "API1": ("API1:2023", "Broken Object Level Authorization"),
    "API2": ("API2:2023", "Broken Authentication"),
    "API3": ("API3:2023", "Broken Object Property Level Authorization"),
    "API4": ("API4:2023", "Unrestricted Resource Consumption"),
    "API5": ("API5:2023", "Broken Function Level Authorization"),
    "API6": ("API6:2023", "Unrestricted Access to Sensitive Business Flows"),
    "API7": ("API7:2023", "Server Side Request Forgery"),
    "API8": ("API8:2023", "Security Misconfiguration"),
    "API9": ("API9:2023", "Improper Inventory Management"),
    "API10": ("API10:2023", "Unsafe Consumption of APIs"),
}

_OWASP_API_2019_TO_2023: dict[str, str] = {
    "API1": "API1",
    "API2": "API2",
    "API3": "API3",
    "API4": "API4",
    "API5": "API5",
    "API6": "API3",
    "API7": "API8",
    "API9": "API9",
}
_API_CODE = re.compile(r"^API(?P<number>[1-9][0-9]*)$")

_SVG_WIDTH = 760
_SVG_HEIGHT = 620
_CENTER_X = 380.0
_CENTER_Y = 315.0
_RADIUS = 205.0
_LABEL_RADIUS = 242.0
_RING_LEVELS = (0.25, 0.50, 0.75, 1.00)


@dataclass(frozen=True, slots=True)
class OwaspRadarPoint:
    """One radar axis with its normalized value and supporting counts."""

    code: str
    title: str
    value: float
    findings: int
    expected: int | None = None
    matched: int | None = None


def canonical_owasp_api(category: str) -> tuple[str, str]:
    """Map compact or 2019 API codes to the 2023 code and title."""

    if category in _OWASP_API_2023:
        return _OWASP_API_2023[category]
    if category.endswith(":2019"):
        compact = category[: -len(":2019")]
        mapped = _OWASP_API_2019_TO_2023.get(compact)
        if mapped is not None:
            return _OWASP_API_2023[mapped]
    if category.endswith(":2023"):
        compact = category[: -len(":2023")]
        if compact in _OWASP_API_2023:
            return _OWASP_API_2023[compact]
    return category, category


def owasp_radar_axes() -> tuple[tuple[str, str], ...]:
    """Return API axes declared by ``classes.yaml`` in numeric order."""

    codes = sorted(
        {
            entry.owasp_api
            for entry in DEFAULT_CATALOG.entries
            if _API_CODE.fullmatch(entry.owasp_api)
        },
        key=_api_number,
    )
    return tuple(_OWASP_API_2023[code] for code in codes)


def owasp_radar_points(bundle: ReportBundle) -> tuple[OwaspRadarPoint, ...]:
    """Project findings or ground-truth recall onto the catalog API axes."""

    axes = owasp_radar_axes()
    axis_codes = {code for code, _title in axes}
    finding_counts = Counter()
    for finding in bundle.findings:
        codes = {
            code
            for category in finding.owasp
            if (code := canonical_owasp_api(category)[0]) in axis_codes
        }
        finding_counts.update(codes)

    if bundle.owasp_ground_truth is None:
        total_findings = len(bundle.findings)
        return tuple(
            OwaspRadarPoint(
                code=code,
                title=title,
                value=finding_counts[code] / total_findings if total_findings else 0.0,
                findings=finding_counts[code],
            )
            for code, title in axes
        )

    expected = Counter()
    matched = Counter()
    for score in bundle.owasp_ground_truth:
        code = canonical_owasp_api(score.axis)[0]
        if code not in axis_codes:
            continue
        expected[code] += score.expected
        matched[code] += score.matched

    return tuple(
        OwaspRadarPoint(
            code=code,
            title=title,
            value=matched[code] / expected[code] if expected[code] else 0.0,
            findings=finding_counts[code],
            expected=expected[code],
            matched=matched[code],
        )
        for code, title in axes
    )


def render_owasp_radar_svg(
    points: Sequence[OwaspRadarPoint],
    *,
    value_label: str,
) -> str:
    """Render a deterministic, dependency-free SVG radar chart."""

    if not points:
        raise ValueError("OWASP radar requires at least one axis")
    if any(not 0.0 <= point.value <= 1.0 for point in points):
        raise ValueError("OWASP radar values must be between 0 and 1")

    labels = " ".join(f"{point.code} {point.value:.0%}" for point in points)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{_SVG_WIDTH}" '
        f'height="{_SVG_HEIGHT}" viewBox="0 0 {_SVG_WIDTH} {_SVG_HEIGHT}" '
        f'role="img" aria-label="OWASP API Top 10 radar, {html.escape(value_label)}">',
        f"<title>OWASP API Top 10 — {html.escape(value_label)}</title>",
        f"<desc>{html.escape(labels)}</desc>",
        f'<rect width="{_SVG_WIDTH}" height="{_SVG_HEIGHT}" fill="#ffffff" rx="16"/>',
        *_ring_elements(points),
        *_axis_elements(points),
        *_value_elements(points),
        *_label_elements(points),
        "</svg>",
    ]
    return "\n".join(parts)


def _api_number(category: str) -> int:
    match = _API_CODE.fullmatch(category)
    if match is None:
        return 10_000
    return int(match.group("number"))


def _point(
    index: int,
    total: int,
    radius: float,
) -> tuple[float, float]:
    angle = math.radians(-90.0 + 360.0 * index / total)
    return (
        _CENTER_X + radius * math.cos(angle),
        _CENTER_Y + radius * math.sin(angle),
    )


def _polygon(
    count: int,
    radius: float,
    *,
    fill: str,
    stroke: str,
    stroke_width: float = 1.0,
) -> str:
    coordinates = " ".join(
        f"{x:.2f},{y:.2f}" for x, y in (_point(i, count, radius) for i in range(count))
    )
    return (
        f'<polygon points="{coordinates}" fill="{fill}" stroke="{stroke}" '
        f'stroke-width="{stroke_width:.1f}" stroke-linejoin="round"/>'
    )


def _ring_elements(points: Sequence[OwaspRadarPoint]) -> list[str]:
    count = len(points)
    return [
        _polygon(count, _RADIUS * level, fill="none", stroke="#d8dce4")
        for level in _RING_LEVELS
    ]


def _axis_elements(points: Sequence[OwaspRadarPoint]) -> list[str]:
    parts = []
    for index in range(len(points)):
        x, y = _point(index, len(points), _RADIUS)
        parts.append(
            f'<line x1="{_CENTER_X:.2f}" y1="{_CENTER_Y:.2f}" '
            f'x2="{x:.2f}" y2="{y:.2f}" stroke="#d8dce4" '
            f'stroke-width="1"/>'
        )
    return parts


def _value_elements(points: Sequence[OwaspRadarPoint]) -> list[str]:
    count = len(points)
    coordinates = " ".join(
        f"{x:.2f},{y:.2f}"
        for x, y in (
            _point(index, count, _RADIUS * point.value)
            for index, point in enumerate(points)
        )
    )
    parts = [
        f'<polygon points="{coordinates}" fill="rgba(62,99,221,0.18)" '
        f'stroke="#3e63dd" stroke-width="2.0" stroke-linejoin="round"/>'
    ]
    for index, point in enumerate(points):
        x, y = _point(index, count, _RADIUS * point.value)
        parts.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="4" fill="#3e63dd"/>')
    return parts


def _label_elements(points: Sequence[OwaspRadarPoint]) -> list[str]:
    parts = []
    for index, point in enumerate(points):
        x, y = _point(index, len(points), _LABEL_RADIUS)
        anchor = "middle"
        if x < _CENTER_X - 20:
            anchor = "end"
        elif x > _CENTER_X + 20:
            anchor = "start"
        parts.append(
            f'<text x="{x:.2f}" y="{y:.2f}" text-anchor="{anchor}" '
            f'font-family="system-ui, sans-serif" font-size="12" '
            f'font-weight="600" fill="#27272a">{html.escape(point.code)}</text>'
        )
    return parts


__all__ = [
    "OwaspRadarPoint",
    "canonical_owasp_api",
    "owasp_radar_axes",
    "owasp_radar_points",
    "render_owasp_radar_svg",
]
