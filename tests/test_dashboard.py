import csv
from pathlib import Path

from log_analysis_tool.dashboard import create_app


def test_dashboard_displays_summary_alerts_and_charts(tmp_path: Path) -> None:
    csv_path = tmp_path / "alerts.csv"
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    for filename in [
        "alerts_by_type.svg",
        "top_offending_ips.svg",
        "failed_logins_over_time.svg",
    ]:
        (report_dir / filename).write_text("<svg></svg>", encoding="utf-8")

    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "timestamp",
                "alert_type",
                "severity",
                "source_ip",
                "username",
                "count",
                "description",
                "reasoning",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-01-12 10:00:00",
                "alert_type": "brute_force",
                "severity": "medium",
                "source_ip": "203.0.113.10",
                "username": "admin",
                "count": "5",
                "description": "5 failed logins from 203.0.113.10 within 10 minutes",
                "reasoning": "Threshold exceeded",
            }
        )

    app = create_app(csv_path=csv_path, report_dir=report_dir)

    with app.test_client() as client:
        response = client.get("/")

    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Log Analysis Tool Dashboard" in text
    assert "Lightweight review page" in text
    assert "Total Alerts" in text
    assert "Medium Severity" in text
    assert "brute_force" in text
    assert "203.0.113.10" in text
    assert "failed_logins_over_time.svg" in text
