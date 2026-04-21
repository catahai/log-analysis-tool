from __future__ import annotations

from collections import Counter
from pathlib import Path
import sys

from .charts import generate_charts
from .cli import build_parser
from .detectors import run_all_detectors
from .exporters import export_alerts_to_csv, export_alerts_to_json
from .models import Alert, AuthEvent, FAILED_LOGIN, SUCCESSFUL_LOGIN
from .parser import parse_auth_log_file


def _print_count_section(title: str, counts: Counter[str]) -> None:
    """Print a labeled count section for terminal output."""

    print(title)
    if not counts:
        print("  None")
        return

    for name, count in counts.items():
        print(f"  - {name}: {count}")


def _top_offending_ips(events: list[AuthEvent]) -> list[tuple[str, int]]:
    """Return the top IPs ranked by failed login count."""

    failed_login_counts = Counter(
        event.source_ip for event in events if event.event_type == FAILED_LOGIN
    )
    return failed_login_counts.most_common(3)


def _resolve_input_path(args) -> Path | None:
    """Resolve the input log path from positional or named CLI arguments."""

    return args.input_path or args.logfile


def _print_summary(events: list[AuthEvent], alerts: list[Alert]) -> None:
    """Print a CLI summary with counts that are easy to scan."""

    failed_count = sum(1 for event in events if event.event_type == FAILED_LOGIN)
    success_count = sum(1 for event in events if event.event_type == SUCCESSFUL_LOGIN)
    alerts_by_type = Counter(alert.alert_type for alert in alerts)
    alerts_by_severity = Counter(alert.severity for alert in alerts)
    top_ips = _top_offending_ips(events)

    print("Log Analysis Summary")
    print("====================")
    print(f"Total events processed : {len(events)}")
    print(f"Failed logins          : {failed_count}")
    print(f"Successful logins      : {success_count}")
    print(f"Total alerts           : {len(alerts)}")
    print()
    _print_count_section("Alerts by Type", alerts_by_type)
    print()
    _print_count_section("Alerts by Severity", alerts_by_severity)
    print()
    print("Top Offending IPs")
    if not top_ips:
        print("  None")
    else:
        for ip_address, count in top_ips:
            print(f"  - {ip_address}: {count} failed login(s)")


def main() -> int:
    """Parse a log file, run detections, and export results."""

    parser = build_parser()
    args = parser.parse_args()
    input_path = _resolve_input_path(args)

    if input_path is None:
        parser.print_usage(sys.stderr)
        print("error: an input log file is required", file=sys.stderr)
        return 2

    if not input_path.exists():
        print(f"Log file not found: {input_path}", file=sys.stderr)
        return 1

    try:
        events = parse_auth_log_file(input_path, year=args.year)
        alerts = run_all_detectors(events)
        export_alerts_to_json(alerts, args.json_out)
        export_alerts_to_csv(alerts, args.csv_out)
        chart_paths = generate_charts(alerts, events, args.report_dir) if args.generate_report else []
    except OSError as exc:
        print(f"File error: {exc}", file=sys.stderr)
        return 1

    _print_summary(events, alerts)

    if alerts:
        print("\nAlerts")
        print("------")
        for alert in alerts:
            print(
                f"[{alert.severity.upper()}] {alert.alert_type} "
                f"ip={alert.source_ip} count={alert.event_count} "
                f"window={alert.first_seen} -> {alert.last_seen}"
            )
            print(f"  Reason: {alert.reasoning}")
            print(f"  Detail: {alert.description}")

    print(f"\nJSON export: {args.json_out}")
    print(f"CSV export: {args.csv_out}")
    if chart_paths:
        print("Report charts:")
        for chart_path in chart_paths:
            print(f"  - {chart_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
