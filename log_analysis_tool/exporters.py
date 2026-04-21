from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import Alert


def _alert_csv_row(alert: Alert) -> dict[str, str | int | None]:
    """Convert an alert into a flat CSV-friendly row."""

    return {
        "timestamp": alert.first_seen.isoformat(sep=" "),
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "username": alert.username,
        "count": alert.event_count,
        "description": alert.description,
        "reasoning": alert.reasoning,
    }


def export_alerts_to_json(alerts: list[Alert], path: str | Path) -> None:
    """Write alerts to a JSON file."""

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump([alert.to_dict() for alert in alerts], handle, indent=2)


def export_alerts_to_csv(alerts: list[Alert], path: str | Path) -> None:
    """Write alerts to a CSV file."""

    output_path = Path(path)
    fieldnames = [
        "timestamp",
        "alert_type",
        "severity",
        "source_ip",
        "username",
        "count",
        "description",
        "reasoning",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            writer.writerow(_alert_csv_row(alert))
