from __future__ import annotations

from collections import Counter
from datetime import datetime
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
    left_margin = 260
    top_margin = 96
    row_height = 58
    bar_height = 28
    chart_width = 580
    max_value = max((count for _, count in items), default=1)
    safe_items = items or [("No data", 0)]

    rows: list[str] = []
    for index, (label, count) in enumerate(safe_items):
        y = top_margin + index * row_height
        bar_width = 0 if max_value == 0 else int((count / max_value) * chart_width)
        rows.extend(
            [
                f'<text x="48" y="{y + 20}" fill="#e5e7eb" font-family="Menlo, Consolas, monospace" font-size="18">{_escape_svg_text(label)}</text>',
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


def _write_line_chart(
    title: str,
    subtitle: str,
    items: list[tuple[datetime, int]],
    output_path: Path,
    line_color: str,
) -> None:
    """Write a simple SVG line chart to disk."""

    width = 960
    height = 420
    plot_left = 90
    plot_top = 96
    plot_width = 800
    plot_height = 220
    plot_bottom = plot_top + plot_height
    safe_items = items or [(datetime.min, 0)]
    max_value = max((count for _, count in safe_items), default=1)

    if len(safe_items) == 1:
        points = [(plot_left + plot_width // 2, plot_bottom)]
    else:
        step_x = plot_width / (len(safe_items) - 1)
        points = []
        for index, (_, count) in enumerate(safe_items):
            x = int(plot_left + index * step_x)
            y_offset = 0 if max_value == 0 else int((count / max_value) * plot_height)
            y = plot_bottom - y_offset
            points.append((x, y))

    point_string = " ".join(f"{x},{y}" for x, y in points)
    x_labels: list[str] = []
    for x, (minute, _) in zip((point[0] for point in points), safe_items):
        x_labels.append(
            f'<text x="{x}" y="{plot_bottom + 38}" text-anchor="middle" fill="#94a3b8" '
            f'font-family="Menlo, Consolas, monospace" font-size="14">{minute.strftime("%H:%M")}</text>'
        )

    y_axis_labels: list[str] = []
    for index in range(0, max_value + 1):
        y = plot_bottom - int((index / max(max_value, 1)) * plot_height)
        y_axis_labels.extend(
            [
                f'<line x1="{plot_left}" y1="{y}" x2="{plot_left + plot_width}" y2="{y}" stroke="#1f2937" stroke-width="1"/>',
                f'<text x="{plot_left - 16}" y="{y + 5}" text-anchor="end" fill="#94a3b8" '
                f'font-family="Menlo, Consolas, monospace" font-size="14">{index}</text>',
            ]
        )

    svg = "\n".join(
        [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img">',
            f'  <rect width="{width}" height="{height}" fill="#0f172a"/>',
            '  <rect x="18" y="18" width="924" height="384" rx="18" fill="#111827" stroke="#334155" stroke-width="2"/>',
            f'  <text x="40" y="58" fill="#f8fafc" font-family="Menlo, Consolas, monospace" font-size="28">{_escape_svg_text(title)}</text>',
            f'  <text x="40" y="86" fill="#94a3b8" font-family="Menlo, Consolas, monospace" font-size="16">{_escape_svg_text(subtitle)}</text>',
            *y_axis_labels,
            f'  <line x1="{plot_left}" y1="{plot_bottom}" x2="{plot_left + plot_width}" y2="{plot_bottom}" stroke="#475569" stroke-width="2"/>',
            f'  <line x1="{plot_left}" y1="{plot_top}" x2="{plot_left}" y2="{plot_bottom}" stroke="#475569" stroke-width="2"/>',
            f'  <polyline fill="none" stroke="{line_color}" stroke-width="4" points="{point_string}"/>',
            *[
                f'<circle cx="{x}" cy="{y}" r="5" fill="{line_color}"/>'
                for x, y in points
            ],
            *x_labels,
            f'  <text x="{plot_left + plot_width // 2}" y="{height - 22}" text-anchor="middle" fill="#cbd5e1" font-family="Menlo, Consolas, monospace" font-size="16">Time (grouped by minute)</text>',
            f'  <text x="30" y="{plot_top - 18}" fill="#cbd5e1" font-family="Menlo, Consolas, monospace" font-size="16">Failed logins</text>',
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
    failed_logins_by_minute = Counter(
        event.timestamp.replace(second=0, microsecond=0)
        for event in events
        if event.event_type == FAILED_LOGIN
    )

    alert_type_chart = output_dir / "alerts_by_type.svg"
    top_ip_chart = output_dir / "top_offending_ips.svg"
    failed_over_time_chart = output_dir / "failed_logins_over_time.svg"

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
    _write_line_chart(
        title="Failed Logins Over Time",
        subtitle="Count of failed SSH login events grouped by minute",
        items=sorted(failed_logins_by_minute.items()),
        output_path=failed_over_time_chart,
        line_color="#22c55e",
    )

    return [alert_type_chart, top_ip_chart, failed_over_time_chart]
