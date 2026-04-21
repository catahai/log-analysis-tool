from __future__ import annotations

from collections import Counter
from pathlib import Path

from .models import Alert, AuthEvent, FAILED_LOGIN


def _escape_svg_text(text: str) -> str:
    """Escape a small subset of characters for inline SVG text."""

    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _write_bar_chart(
    title: str,
    subtitle: str,
    items: list[tuple[str, int]],
    output_path: Path,
    bar_color: str,
) -> None:
    """Write a simple SVG bar chart to disk."""

    width = 960
    height = 420
    left_margin = 220
    top_margin = 96
    row_height = 58
    bar_height = 28
    chart_width = 640
    max_value = max((count for _, count in items), default=1)
    safe_items = items or [("No data", 0)]

    rows: list[str] = []
    for index, (label, count) in enumerate(safe_items):
        y = top_margin + index * row_height
        bar_width = 0 if max_value == 0 else int((count / max_value) * chart_width)
        rows.extend(
            [
                f'<text x="48" y="{y + 20}" fill="#e5e7eb" font-family="Menlo, Consolas, monospace" font-size="20">{_escape_svg_text(label)}</text>',
                f'<rect x="{left_margin}" y="{y}" width="{chart_width}" height="{bar_height}" rx="6" fill="#1f2937"/>',
                f'<rect x="{left_margin}" y="{y}" width="{bar_width}" height="{bar_height}" rx="6" fill="{bar_color}"/>',
                f'<text x="{left_margin + chart_width + 20}" y="{y + 20}" fill="#cbd5e1" font-family="Menlo, Consolas, monospace" font-size="20">{count}</text>',
            ]
        )

    svg = "\n".join(
        [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img">',
            f'  <rect width="{width}" height="{height}" fill="#0f172a"/>',
            '  <rect x="18" y="18" width="924" height="384" rx="18" fill="#111827" stroke="#334155" stroke-width="2"/>',
            f'  <text x="40" y="58" fill="#f8fafc" font-family="Menlo, Consolas, monospace" font-size="28">{_escape_svg_text(title)}</text>',
            f'  <text x="40" y="86" fill="#94a3b8" font-family="Menlo, Consolas, monospace" font-size="16">{_escape_svg_text(subtitle)}</text>',
            *rows,
            "</svg>",
        ]
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(svg, encoding="utf-8")


def generate_charts(
    alerts: list[Alert],
    events: list[AuthEvent],
    report_dir: str | Path,
) -> list[Path]:
    """Generate lightweight SVG charts for the current analysis run."""

    output_dir = Path(report_dir)
    alerts_by_type = Counter(alert.alert_type for alert in alerts)
    failed_login_counts = Counter(
        event.source_ip for event in events if event.event_type == FAILED_LOGIN
    )

    alert_type_chart = output_dir / "alerts_by_type.svg"
    top_ip_chart = output_dir / "top_offending_ips.svg"

    _write_bar_chart(
        title="Alerts by Type",
        subtitle="Count of generated alerts grouped by detector name",
        items=alerts_by_type.most_common(),
        output_path=alert_type_chart,
        bar_color="#38bdf8",
    )
    _write_bar_chart(
        title="Top Offending IPs",
        subtitle="Top source IPs ranked by failed SSH login volume",
        items=failed_login_counts.most_common(5),
        output_path=top_ip_chart,
        bar_color="#f97316",
    )

    return [alert_type_chart, top_ip_chart]
