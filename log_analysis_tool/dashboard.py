from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

from flask import Flask, abort, render_template, send_from_directory


def _load_alert_rows(csv_path: Path) -> list[dict[str, str]]:
    """Load alert rows from a generated CSV file."""

    if not csv_path.exists():
        return []

    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def create_app(
    csv_path: str | Path = "output/alerts.csv",
    report_dir: str | Path = "output/report",
) -> Flask:
    """Create a minimal dashboard app for reviewing alert output."""

    app = Flask(__name__, template_folder="templates")
    alerts_csv = Path(csv_path)
    chart_dir = Path(report_dir)

    @app.route("/")
    def index() -> str:
        alert_rows = _load_alert_rows(alerts_csv)
        severity_counts = Counter(row["severity"] for row in alert_rows)
        alert_type_counts = Counter(row["alert_type"] for row in alert_rows)
        top_offending_ips = Counter()
        for row in alert_rows:
            try:
                top_offending_ips[row["source_ip"]] += int(row["count"])
            except (KeyError, ValueError):
                continue
        ordered_severities = [
            (severity, severity_counts[severity])
            for severity in ["high", "medium", "low"]
            if severity in severity_counts
        ]
        ordered_severities.extend(
            (severity, count)
            for severity, count in severity_counts.items()
            if severity not in {"high", "medium", "low"}
        )
        chart_names = [
            name
            for name in [
                "alerts-by-type.svg",
                "top-offending-ips.svg",
                "failed-logins-over-time.svg",
            ]
            if (chart_dir / name).exists()
        ]
        return render_template(
            "dashboard.html",
            total_alerts=len(alert_rows),
            severity_counts=ordered_severities,
            alert_type_counts=alert_type_counts.most_common(),
            top_offending_ips=top_offending_ips.most_common(5),
            alerts=alert_rows,
            charts=chart_names,
        )

    @app.route("/charts/<path:filename>")
    def chart(filename: str):
        chart_path = chart_dir / filename
        if not chart_path.exists():
            abort(404)
        return send_from_directory(chart_dir, filename)

    return app


app = create_app()


def main() -> None:
    """Run the dashboard directly for local review."""

    parser = argparse.ArgumentParser(description="Run the Log Analysis Tool dashboard.")
    parser.add_argument("--csv", default="output/alerts.csv", help="Path to the alerts CSV file")
    parser.add_argument(
        "--report-dir",
        default="output/report",
        help="Directory containing generated SVG chart files",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind the Flask server to")
    parser.add_argument("--port", type=int, default=5000, help="Port for the Flask server")
    args = parser.parse_args()

    create_app(csv_path=args.csv, report_dir=args.report_dir).run(
        host=args.host,
        port=args.port,
        debug=False,
    )


if __name__ == "__main__":
    main()
