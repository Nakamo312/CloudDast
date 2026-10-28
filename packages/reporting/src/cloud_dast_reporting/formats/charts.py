"""Deterministic radial charts for taxonomy read models.

Renderers are pure functions over read models: fixed palettes, stable
geometry, no external assets, so the same slices always produce the same
chart in any offline environment.
"""

from __future__ import annotations

import html
import math
from collections.abc import Sequence

from cloud_dast_reporting import OwaspSlice, ReportBundle

OWASP_API_TITLES: dict[str, str] = {
    "API1": "Broken Object Level Authorization",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Function Level Authorization",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
    "unclassified": "Unclassified",
}

_OWASP_COLORS: dict[str, str] = {
    "API1": "#e5484d",
    "API2": "#f76b15",
    "API3": "#ffc53d",
    "API4": "#46a758",
    "API5": "#12a594",
    "API6": "#00a2c7",
    "API7": "#3e63dd",
    "API8": "#8e4ec6",
    "API9": "#d6409f",
    "API10": "#e93d82",
    "unclassified": "#8b8d98",
}
_FALLBACK_COLORS = ("#8a7f4e", "#5f7a8a", "#7a5f8a", "#6e8a5f", "#8a5f5f")

_ASCII_FILLS = "█▓▒░◆●■▲★◉▣"

_SVG_WIDTH = 690
_DONUT_CX = 132.0
_DONUT_CY = 140.0
_DONUT_R_OUT = 98.0
_DONUT_R_IN = 60.0
_LEGEND_X = 262.0
_LEGEND_ROW_HEIGHT = 21.0
_LEGEND_START_Y = 64.0


class OwaspSvgRenderer:
    """Render the OWASP report projection as a standalone SVG artifact."""

    def render(self, bundle: ReportBundle) -> str:
        return render_owasp_donut_svg(
            bundle.owasp,
            total_findings=len(bundle.findings),
        )


def category_title(category: str) -> str:
    """Return the human title for one OWASP API category."""

    return OWASP_API_TITLES.get(category, category)


def category_color(category: str, index: int) -> str:
    """Return the deterministic chart color for one category."""

    if category in _OWASP_COLORS:
        return _OWASP_COLORS[category]
    return _FALLBACK_COLORS[index % len(_FALLBACK_COLORS)]


def render_owasp_donut_svg(
    slices: Sequence[OwaspSlice],
    *,
    total_findings: int,
    title: str = "OWASP API Top 10 — findings distribution",
) -> str:
    """Render the OWASP distribution as a self-contained SVG donut."""

    height = max(280, int(_LEGEND_START_Y + _LEGEND_ROW_HEIGHT * len(slices)) + 16)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{_SVG_WIDTH}" '
        f'height="{height}" viewBox="0 0 {_SVG_WIDTH} {height}" '
        f'role="img" aria-label="{html.escape(title)}">',
        f'<rect width="{_SVG_WIDTH}" height="{height}" fill="#101216"/>',
        f'<text x="{_DONUT_CX}" y="34" text-anchor="middle" '
        f'font-family="system-ui, sans-serif" font-size="15" '
        f'font-weight="600" fill="#f4f4f5">{html.escape(title)}</text>',
    ]
    parts.extend(_donut_sector_elements(slices))
    parts.append(
        f'<text x="{_DONUT_CX}" y="{_DONUT_CY + 8}" text-anchor="middle" '
        f'font-family="system-ui, sans-serif" font-size="30" '
        f'font-weight="700" fill="#f4f4f5">{total_findings}</text>'
    )
    parts.append(
        f'<text x="{_DONUT_CX}" y="{_DONUT_CY + 28}" text-anchor="middle" '
        f'font-family="system-ui, sans-serif" font-size="11" '
        f'fill="#8b8d98">findings</text>'
    )
    parts.extend(_legend_elements(slices))
    parts.append("</svg>")
    return "\n".join(parts)


def render_owasp_ascii_donut(
    slices: Sequence[OwaspSlice],
    *,
    total_findings: int,
    width: int = 45,
    height: int = 21,
) -> str:
    """Render the OWASP distribution as an inline text donut."""

    if not slices:
        return "(no findings to chart)"
    cx = (width - 1) / 2
    cy = (height - 1) / 2
    rx = (width - 1) / 2
    ry = (height - 1) / 2
    bounds = [0.0]
    for slice_ in slices:
        bounds.append(bounds[-1] + slice_.ring_fraction)
    grid: list[list[str]] = []
    for y in range(height):
        row: list[str] = []
        for x in range(width):
            dx = (x - cx) / rx
            dy = (y - cy) / ry
            squared = dx * dx + dy * dy
            if 0.30 <= squared <= 1.02:
                fraction = ((math.atan2(dy, dx) + math.pi / 2) / (2 * math.pi)) % 1.0
                index = _sector_index(fraction, bounds)
                row.append(_ASCII_FILLS[index % len(_ASCII_FILLS)])
            else:
                row.append(" ")
        grid.append(row)
    _overlay_center_text(grid, str(total_findings), round(cy) - 1)
    _overlay_center_text(grid, "findings", round(cy) + 1)
    return "\n".join("".join(row).rstrip() for row in grid)


def owasp_legend_line(slice_: OwaspSlice, index: int) -> str:
    """Return one deterministic legend line for an ASCII context."""

    fill = _ASCII_FILLS[index % len(_ASCII_FILLS)]
    share = f"{slice_.ring_fraction:.1%}"
    return (
        f"{fill} {slice_.category:<12} {slice_.count:>3}  {share:>6}  "
        f"{category_title(slice_.category)}"
    )


def _sector_index(fraction: float, bounds: Sequence[float]) -> int:
    for index in range(len(bounds) - 1):
        if fraction < bounds[index + 1]:
            return index
    return max(0, len(bounds) - 2)


def _overlay_center_text(grid: list[list[str]], text: str, row: int) -> None:
    if not 0 <= row < len(grid):
        return
    start = (len(grid[row]) - len(text)) // 2
    if start < 0:
        return
    for offset, character in enumerate(text):
        grid[row][start + offset] = character


def _donut_sector_elements(slices: Sequence[OwaspSlice]) -> list[str]:
    if not slices:
        ring = _ring_path(_DONUT_CX, _DONUT_CY, _DONUT_R_OUT, _DONUT_R_IN)
        return [f'<path d="{ring}" fill="#3f4149"/>']
    parts: list[str] = []
    if len(slices) == 1:
        # A single arc path cannot cover 360°; split it into two halves.
        for start, end in ((-90.0, 90.0), (90.0, 270.0)):
            parts.append(
                _sector_element(
                    _DONUT_CX,
                    _DONUT_CY,
                    _DONUT_R_OUT,
                    _DONUT_R_IN,
                    start,
                    end,
                    category_color(slices[0].category, 0),
                )
            )
        return parts
    angle = -90.0
    for index, slice_ in enumerate(slices):
        sweep = 360.0 * slice_.ring_fraction
        end = angle + sweep
        parts.append(
            _sector_element(
                _DONUT_CX,
                _DONUT_CY,
                _DONUT_R_OUT,
                _DONUT_R_IN,
                angle,
                end,
                category_color(slice_.category, index),
            )
        )
        angle = end
    return parts


def _sector_element(
    cx: float,
    cy: float,
    r_out: float,
    r_in: float,
    start: float,
    end: float,
    color: str,
) -> str:
    path = _donut_sector_path(cx, cy, r_out, r_in, start, end)
    return f'<path d="{path}" fill="{color}" stroke="#101216" stroke-width="1.5"/>'


def _donut_sector_path(
    cx: float, cy: float, r_out: float, r_in: float, start: float, end: float
) -> str:
    large = 1 if end - start > 180.0 else 0
    x0, y0 = _polar(cx, cy, r_out, start)
    x1, y1 = _polar(cx, cy, r_out, end)
    x2, y2 = _polar(cx, cy, r_in, end)
    x3, y3 = _polar(cx, cy, r_in, start)
    return (
        f"M{x0:.2f},{y0:.2f} "
        f"A{r_out:.2f},{r_out:.2f} 0 {large} 1 {x1:.2f},{y1:.2f} "
        f"L{x2:.2f},{y2:.2f} "
        f"A{r_in:.2f},{r_in:.2f} 0 {large} 0 {x3:.2f},{y3:.2f} "
        f"Z"
    )


def _ring_path(cx: float, cy: float, r_out: float, r_in: float) -> str:
    return _donut_sector_path(cx, cy, r_out, r_in, -90.0, 270.0)


def _polar(cx: float, cy: float, radius: float, angle: float) -> tuple[float, float]:
    radians = math.radians(angle)
    return cx + radius * math.cos(radians), cy + radius * math.sin(radians)


def _legend_elements(slices: Sequence[OwaspSlice]) -> list[str]:
    parts: list[str] = []
    for index, slice_ in enumerate(slices):
        y = _LEGEND_START_Y + _LEGEND_ROW_HEIGHT * index
        color = category_color(slice_.category, index)
        share = f"{slice_.ring_fraction:.1%}"
        title = html.escape(category_title(slice_.category))
        parts.append(
            f'<rect x="{_LEGEND_X}" y="{y - 11}" width="12" height="12" '
            f'rx="2" fill="{color}"/>'
        )
        parts.append(
            f'<text x="{_LEGEND_X + 20}" y="{y}" '
            f'font-family="system-ui, sans-serif" font-size="11" fill="#f4f4f5">'
            f'<tspan font-weight="700">{html.escape(slice_.category)}</tspan> '
            f"{slice_.count} · {share} — {title}</text>"
        )
    if slices:
        parts.append(
            f'<text x="{_LEGEND_X}" y="{_LEGEND_START_Y - 28}" '
            f'font-family="system-ui, sans-serif" font-size="10" '
            f'fill="#8b8d98">multi-tag findings count in every category</text>'
        )
    return parts
