# Log Analysis & Threat Detection Tool

Python CLI for SSH authentication log analysis and SOC-style alert generation

## Overview

Log Analysis & Threat Detection Tool is a Python-based cybersecurity portfolio project that analyses Linux SSH authentication logs, detects suspicious login activity, generates structured alerts, exports JSON and CSV results, creates SVG reports, and can optionally display the generated outputs in a lightweight Flask dashboard. It is designed for defensive security learning and portfolio presentation, not as a replacement for a SIEM, EDR, or production SOC platform.

## What This Demonstrates

- Linux SSH authentication log analysis
- Log parsing and event normalisation
- Rule-based detection logic
- Brute-force detection
- Successful login after repeated failures detection
- Suspicious authentication pattern triage
- Alert generation with reasoning
- JSON and CSV export
- SVG report generation
- Optional Flask dashboard visualisation
- Python CLI design
- Modular architecture
- Automated testing

## High-Level Workflow

```text
Raw auth.log
→ Parse SSH events
→ Normalise event data
→ Apply detection rules
→ Generate alerts
→ Export JSON/CSV
→ Generate reports
→ Optional dashboard review
```

## Features

### Parser

- Parses supported Linux SSH `auth.log` password authentication events
- Extracts timestamp, username, source IP, event type, and invalid-user context
- Skips malformed or unsupported lines safely

### Detection Engine

- Applies configurable threshold and time-window rules
- Supports CLI overrides and optional JSON config loading
- Keeps rule logic lightweight and easy to explain

### Alert Generation

- Produces structured alerts with type, severity, source IP, username, count, description, and reasoning
- Includes related raw log lines for additional context in JSON output

### CLI

- Provides the primary analysis workflow
- Runs parsing, detections, exports, and optional report generation from one command

### Exports

- Writes alert data to JSON
- Writes alert data to CSV for manual review or downstream tooling

### Reporting

- Generates SVG charts for alert types, top offending IPs, and failed logins over time
- Supports reproducible sample outputs for portfolio display

### Dashboard

- Optional Flask dashboard that reads generated files
- Displays summary metrics, alert data, and charts in a read-only view

### Testing

- Includes parser, detector, CLI, export, and dashboard tests
- Covers malformed log input and threshold edge cases

## Detection Rules

| Detection | Signal | Why it matters | Severity |
|---|---|---|---|
| Failed login tracking | Counts failed SSH logins in the current dataset | Provides baseline suspicious authentication visibility and supports higher-level detections | Informational in summary output |
| Brute-force detection | Repeated failed logins from one IP within a short window | May indicate credential guessing against SSH access | Medium |
| Successful login after failures | Multiple failed logins followed by a successful login from the same IP | Can suggest guessed, reused, or compromised credentials | High |
| Invalid user enumeration | Repeated invalid username attempts from one IP | Can indicate account discovery or username probing | Medium |
| Password spraying style behaviour | Multiple usernames targeted from one IP within a short window | Can indicate a password spraying style attack pattern | Medium |
| Root login attempt | Authentication attempts involving the `root` account | Root access attempts are higher-risk and worth review | Low for failed attempts, High if successful |

## Mapped ATT&CK Themes

These detections are mapped to relevant MITRE ATT&CK themes for learning and documentation purposes.

| Detection | Relevant ATT&CK themes |
|---|---|
| Brute-force detection | `T1110 Brute Force`, `T1021.004 SSH` |
| Password spraying style behaviour | `T1110.003 Password Spraying`, `T1021.004 SSH` |
| Successful login after failures | `T1078 Valid Accounts`, `T1110 Brute Force`, `T1021.004 SSH` |
| Invalid user enumeration | `T1087 Account Discovery`, `T1110 Brute Force` |
| Root login attempt | `T1078 Valid Accounts`, `T1021.004 SSH` |

This project does not claim full ATT&CK coverage.

## Quick Start

### Clone the repository

```bash
git clone <your-repo-url>
cd log-analysis-tool
```

### Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install requirements

```bash
python3 -m pip install -r requirements.txt
```

### Run tests

```bash
python3 -m pytest
```

### Run a sample analysis

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --config config/detection-rules.json \
  --output-json outputs/sample-alerts.json \
  --output-csv outputs/sample-alerts.csv \
  --generate-report \
  --report-dir reports
```

## Example Command

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --config config/detection-rules.json \
  --json-out outputs/sample-alerts.json \
  --csv-out outputs/sample-alerts.csv \
  --generate-report \
  --report-dir reports
```

## Example Output

```text
Log Analysis Summary
====================
Total events processed : 13
Failed logins          : 12
Successful logins      : 1
Total alerts           : 5

Alerts by Type
  - brute_force: 1
  - success_after_failures: 1
  - invalid_user_enumeration: 1
  - password_spraying: 1
  - root_login_attempt: 1

Alerts by Severity
  - medium: 3
  - high: 1
  - low: 1

Top Offending IPs
  - 203.0.113.10: 5 failed login(s)
  - 198.51.100.20: 3 failed login(s)
  - 198.51.100.30: 3 failed login(s)

JSON export: outputs/sample-alerts.json
CSV export: outputs/sample-alerts.csv
Report charts:
  - reports/alerts-by-type.svg
  - reports/top-offending-ips.svg
  - reports/failed-logins-over-time.svg
```

## Output Files

- JSON alert export: `outputs/sample-alerts.json`
- CSV alert export: `outputs/sample-alerts.csv`
- SVG reports:
  - `reports/alerts-by-type.svg`
  - `reports/top-offending-ips.svg`
  - `reports/failed-logins-over-time.svg`
- Optional dashboard view based on generated CSV and SVG files
- Sample investigation report: [docs/sample-investigation-report.md](./docs/sample-investigation-report.md)

## Dashboard

The Flask dashboard is optional and read-only.

It:

- reads previously generated alert CSV data
- displays summary metrics
- displays severity counts
- displays alert type counts
- displays top offending IPs
- displays the generated charts
- displays the alerts table

It does not:

- use authentication
- use a database
- provide editing features
- provide production deployment features

Run it with:

```bash
python3 -m log_analysis_tool.dashboard
```

## Repository Structure

```text
log-analysis-tool/
├── config/
│   └── detection-rules.json
├── docs/
│   ├── cli-summary.svg
│   ├── detection-rules.md
│   └── sample-investigation-report.md
├── log_analysis_tool/
│   ├── charts.py
│   ├── cli.py
│   ├── dashboard.py
│   ├── detectors.py
│   ├── exporters.py
│   ├── main.py
│   ├── models.py
│   ├── parser.py
│   └── templates/
├── outputs/
│   ├── sample-alerts.csv
│   └── sample-alerts.json
├── reports/
│   ├── alerts-by-type.svg
│   ├── failed-logins-over-time.svg
│   └── top-offending-ips.svg
├── samples/
├── tests/
├── README.md
├── TESTING.md
└── ROADMAP.md
```

## Testing

Run:

```bash
python3 -m pytest
```

Tests cover:

- parser valid lines
- parser malformed lines
- brute-force threshold boundaries
- success after failures
- invalid user enumeration
- multiple usernames from one IP
- root login attempt detection
- export JSON and CSV behavior
- CLI command behavior
- dashboard route rendering

For more detailed validation steps, see [TESTING.md](./TESTING.md).

## Limitations

- Linux SSH `auth.log` events only
- threshold and rule-based detection only
- no live monitoring in the current project workflow
- no SIEM integration
- no external threat intelligence
- no IP reputation enrichment
- no authentication or database in the dashboard
- lab and sample-data focused

## Future Improvements

- more SSH event types
- configurable rule files
- Windows Security log support
- IP reputation enrichment
- geolocation enrichment
- more report formats
- live log monitoring
- better dashboard filtering
- Sigma-style rule mapping later if the project scope expands

See [ROADMAP.md](./ROADMAP.md) for the short public roadmap.

## Portfolio Relevance

This project supports applications for:

- SOC Analyst
- Junior Cybersecurity Analyst
- Security Monitoring Analyst
- Detection Engineering Graduate
- Python Automation roles
- Technical Support roles with cybersecurity focus

## Ethical and Safe-Use Note

This project is intended for defensive security learning, log review, and portfolio demonstration using authorised or sample log data.
