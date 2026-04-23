import csv
import json
import subprocess
import sys
from pathlib import Path


def test_cli_creates_exports_and_prints_summary(tmp_path: Path) -> None:
    log_file = tmp_path / "auth.log"
    json_out = tmp_path / "alerts.json"
    csv_out = tmp_path / "alerts.csv"

    log_file.write_text(
        "\n".join(
            [
                "Jan 12 10:00:00 host sshd[1000]: Failed password for admin from 10.0.0.8 port 50000 ssh2",
                "Jan 12 10:01:00 host sshd[1001]: Failed password for admin from 10.0.0.8 port 50001 ssh2",
                "Jan 12 10:02:00 host sshd[1002]: Failed password for admin from 10.0.0.8 port 50002 ssh2",
                "Jan 12 10:03:00 host sshd[1003]: Failed password for admin from 10.0.0.8 port 50003 ssh2",
                "Jan 12 10:04:00 host sshd[1004]: Failed password for admin from 10.0.0.8 port 50004 ssh2",
                "Jan 12 10:05:00 host sshd[1005]: Accepted password for admin from 10.0.0.8 port 50005 ssh2",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_analysis_tool.main",
            str(log_file),
            "--year",
            "2026",
            "--json-out",
            str(json_out),
            "--csv-out",
            str(csv_out),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "Total events processed : 6" in result.stdout
    assert "Total alerts           : 2" in result.stdout
    assert "Alerts by Type" in result.stdout
    assert "Alerts by Severity" in result.stdout
    assert "Top Offending IPs" in result.stdout
    assert "[MEDIUM] brute_force" in result.stdout
    assert "[HIGH] success_after_failures" in result.stdout
    assert json_out.exists()
    assert csv_out.exists()

    alerts = json.loads(json_out.read_text(encoding="utf-8"))
    assert len(alerts) == 2
    assert {alert["alert_type"] for alert in alerts} == {
        "brute_force",
        "success_after_failures",
    }
    assert {alert["severity"] for alert in alerts} == {"medium", "high"}

    with csv_out.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert set(rows[0].keys()) == {
        "timestamp",
        "alert_type",
        "severity",
        "source_ip",
        "username",
        "count",
        "description",
        "reasoning",
    }
    assert rows[0]["alert_type"] == "brute_force"
    assert rows[0]["count"] == "5"


def test_cli_handles_missing_log_file(tmp_path: Path) -> None:
    missing_log = tmp_path / "missing.log"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_analysis_tool.main",
            str(missing_log),
            "--year",
            "2026",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "Log file not found" in result.stderr


def test_cli_generates_optional_report_charts(tmp_path: Path) -> None:
    log_file = tmp_path / "auth.log"
    csv_out = tmp_path / "alerts.csv"
    report_dir = tmp_path / "report"

    log_file.write_text(
        "\n".join(
            [
                "Jan 12 10:00:00 host sshd[1000]: Failed password for admin from 10.0.0.8 port 50000 ssh2",
                "Jan 12 10:01:00 host sshd[1001]: Failed password for admin from 10.0.0.8 port 50001 ssh2",
                "Jan 12 10:02:00 host sshd[1002]: Failed password for admin from 10.0.0.8 port 50002 ssh2",
                "Jan 12 10:03:00 host sshd[1003]: Failed password for admin from 10.0.0.8 port 50003 ssh2",
                "Jan 12 10:04:00 host sshd[1004]: Failed password for admin from 10.0.0.8 port 50004 ssh2",
                "Jan 12 10:05:00 host sshd[1005]: Accepted password for admin from 10.0.0.8 port 50005 ssh2",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_analysis_tool.main",
            "--input",
            str(log_file),
            "--year",
            "2026",
            "--output-csv",
            str(csv_out),
            "--generate-report",
            "--report-dir",
            str(report_dir),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "Report charts:" in result.stdout
    assert (report_dir / "alerts_by_type.svg").exists()
    assert (report_dir / "top_offending_ips.svg").exists()
    assert (report_dir / "failed_logins_over_time.svg").exists()


def test_cli_accepts_custom_detection_thresholds(tmp_path: Path) -> None:
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "\n".join(
            [
                "Jan 12 10:00:00 host sshd[1000]: Failed password for admin from 10.0.0.8 port 50000 ssh2",
                "Jan 12 10:01:00 host sshd[1001]: Failed password for admin from 10.0.0.8 port 50001 ssh2",
                "Jan 12 10:02:00 host sshd[1002]: Accepted password for admin from 10.0.0.8 port 50002 ssh2",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "log_analysis_tool.main",
            "--input",
            str(log_file),
            "--year",
            "2026",
            "--brute-force-threshold",
            "10",
            "--success-threshold",
            "2",
            "--success-window",
            "5",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "Total alerts           : 1" in result.stdout
    assert "[HIGH] success_after_failures" in result.stdout
