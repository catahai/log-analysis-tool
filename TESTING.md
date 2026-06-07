# Testing Guide

## Overview

This document describes how to validate the Log Analysis & Threat Detection Tool.

The goal is to confirm that the project:

- correctly parses supported Linux SSH authentication events
- safely skips malformed and unsupported lines
- triggers expected detections at the right thresholds
- exports JSON and CSV correctly
- generates SVG reports correctly
- keeps the optional dashboard aligned with generated outputs

## Commands and Paths

- Main CLI: `python3 -m log_analysis_tool.main`
- Dashboard: `python3 -m log_analysis_tool.dashboard`
- Config file: `config/detection-rules.json`
- Sample outputs: `outputs/sample-alerts.json`, `outputs/sample-alerts.csv`
- Sample report charts: `reports/`

## Run the Test Suite

```bash
python3 -m pytest
```

Expected result:

- all tests pass
- coverage includes parser behavior, threshold boundaries, new detections, exports, CLI behavior, and dashboard rendering

## Parser Validation

Covered by automated tests:

- valid failed password lines
- valid accepted password lines
- invalid user parsing
- malformed line handling
- empty file handling

## Detection Validation

Covered by automated tests:

- brute force threshold boundaries
- success after failures
- invalid username enumeration
- multiple usernames from one IP / password spraying style activity
- root login attempt detection
- CLI custom threshold handling
- optional JSON config loading

## Manual CLI Checks

### Main demo flow

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --config config/detection-rules.json \
  --output-json output/alerts.json \
  --output-csv output/alerts.csv \
  --generate-report \
  --report-dir output/report
```

Expected:

- alerts are generated
- JSON and CSV files are created
- charts are generated:
  - `alerts_by_type.svg`
  - `top_offending_ips.svg`
  - `failed_logins_over_time.svg`

### Missing file handling

```bash
python3 -m log_analysis_tool.main --input samples/missing.log --year 2026
```

Expected:

- clean error message
- no traceback

### Empty file handling

```bash
python3 -m log_analysis_tool.main --input samples/empty.log --year 2026
```

Expected:

- `0` events processed
- `0` alerts
- clean exit

## Dashboard Validation

After generating CSV and charts:

```bash
python3 -m log_analysis_tool.dashboard
```

Expected:

- dashboard starts cleanly
- summary cards render
- alert type and severity counts render
- top offending IPs render
- alerts table renders
- generated SVG charts display

## Reproducing Committed Sample Artifacts

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

Expected:

- `outputs/sample-alerts.json`
- `outputs/sample-alerts.csv`
- `reports/alerts-by-type.svg`
- `reports/top-offending-ips.svg`
- `reports/failed-logins-over-time.svg`

## Regression Workflow

After changes:

1. Run `python3 -m pytest`
2. Run the main CLI demo command
3. Start the optional dashboard
4. Compare generated outputs with expected sample artifacts if needed
