# Log Analysis Tool

A Python command-line tool that parses Linux `auth.log` SSH authentication events and flags suspicious patterns. Built an entry-level cybersecurity portfolio project, practical enough to demonstrate real SOC-adjacent skills: structured log parsing, rule-based detection, edge-case testing, and exportable results.

## Quick Demo

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --output-json output/alerts.json \
  --output-csv output/alerts.csv \
  --generate-report \
  --report-dir output/report
```

## Project Overview

This tool reads SSH authentication events from Linux `auth.log`, detects suspicious behavior, prints a terminal summary, exports results to JSON and CSV, and can optionally generate simple SVG charts and a lightweight Flask dashboard.

## Cybersecurity Relevance

This project demonstrates:

- parsing authentication logs into structured events
- detecting repeated failed logins that may indicate brute-force activity
- correlating failed logins with a later successful login from the same IP
- exporting alerts for manual review or downstream tooling
- generating simple visual summaries that support investigation

## Key Features

- CLI-first workflow for parsing, detection, exports, and optional reporting
- configurable detection thresholds and time windows
- JSON and CSV exports for structured review
- SVG charts for alert types, top offending IPs, and failed logins over time
- optional Flask dashboard that reads generated files without a database
- unit tests and end-to-end CLI coverage

## Architecture

```text
log_analysis_tool/
├── parser.py       # parses SSH auth.log events
├── detectors.py    # detection rules and runtime configuration
├── models.py       # shared event and alert data models
├── exporters.py    # JSON and CSV output
├── charts.py       # optional SVG chart generation
├── dashboard.py    # optional Flask dashboard
├── cli.py          # command-line argument handling
└── main.py         # application entry point
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Usage

### Analyze a sample log

```bash
python3 -m log_analysis_tool.main --input samples/suspicious_activity.log --year 2026
```

### Export JSON and CSV

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --output-json output/alerts.json \
  --output-csv output/alerts.csv
```

### Configure detection thresholds

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --brute-force-threshold 5 \
  --brute-force-window 10 \
  --success-threshold 3 \
  --success-window 15
```

Available rule options:

- `--brute-force-threshold`: failed login count required for the brute-force rule
- `--brute-force-window`: brute-force time window in minutes
- `--success-threshold`: failed login count required before a success triggers the second rule
- `--success-window`: success-after-failures time window in minutes

### Generate charts

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --output-json output/alerts.json \
  --output-csv output/alerts.csv \
  --generate-report \
  --report-dir output/report
```

### Start the optional dashboard

Generate the CSV and charts first, then run:

```bash
python3 -m flask --app log_analysis_tool.dashboard run
```

The dashboard reads:

- `output/alerts.csv`
- `output/report/alerts_by_type.svg`
- `output/report/top_offending_ips.svg`
- `output/report/failed_logins_over_time.svg`

## Testing

See [TESTING.md](./TESTING.md) for detailed validation steps and expected outcomes.

## Roadmap

See [ROADMAP.md](./ROADMAP.md) for realistic future enhancements.

## CSV Fields

| Field | Description |
|---|---|
| `timestamp` | Timestamp associated with the alert |
| `alert_type` | Detection rule that triggered |
| `severity` | Alert severity |
| `source_ip` | Source IP address |
| `username` | Username involved in the event |
| `count` | Number of related events |
| `description` | Human-readable alert summary |
| `reasoning` | Short explanation of why the alert fired |

## Screenshots and Charts

![CLI screenshot](docs/cli-summary.svg)
![Alerts by Type chart](docs/alerts-by-type.svg)
![Top Offending IPs chart](docs/top-offending-ips.svg)

## Sample Output

```text
Log Analysis Summary
====================
Total events processed : 9
Failed logins          : 8
Successful logins      : 1
Total alerts           : 2

Alerts by Type
  - brute_force: 1
  - success_after_failures: 1

Alerts by Severity
  - medium: 1
  - high: 1

Top Offending IPs
  - 203.0.113.10: 5 failed login(s)
  - 198.51.100.20: 3 failed login(s)

Alerts
------
[MEDIUM] brute_force ip=203.0.113.10 count=5 window=2026-01-12 10:00:00 -> 2026-01-12 10:04:00
  Reason: The IP reached the brute-force threshold of 5 failed logins inside a 10-minute window.
  Detail: 5 failed logins from 203.0.113.10 within 10 minutes
[HIGH] success_after_failures ip=203.0.113.10 count=5 window=2026-01-12 10:00:00 -> 2026-01-12 10:06:00
  Reason: The IP had at least 3 failed logins and then a successful login inside a 15-minute window.
  Detail: 5 failed logins followed by a success from 203.0.113.10 within 15 minutes

JSON export: output/alerts.json
CSV export: output/alerts.csv
Report charts:
  - output/report/alerts_by_type.svg
  - output/report/top_offending_ips.svg
  - output/report/failed_logins_over_time.svg
```

## Limitations

- supports only Linux SSH `Failed password` and `Accepted password` events from `auth.log`
- uses simple threshold-based rules rather than external enrichment or reputation data
- skips unsupported and malformed lines without separate parse warnings
- keeps the dashboard optional and read-only instead of making it the main interface

## Why This Works as a Portfolio Project

## Potential Improvements

- Support additional SSH event types (e.g. public-key authentication)
- Make detection thresholds configurable via CLI flags
- Add per-username and per-IP summary statistics
- Package the tool with a `console_scripts` entry point for cleaner invocation
- Add an optional lightweight Flask dashboard on top of the existing CLI output


