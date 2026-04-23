# Testing Guide

## Overview

This document explains how to validate the Log Analysis Tool through unit tests and end-to-end CLI checks.

The goals are to confirm that the tool:

- correctly parses SSH authentication logs
- detects brute-force activity and success-after-failures patterns
- handles malformed input safely
- exports accurate JSON and CSV data
- generates the expected SVG charts when reporting is enabled
- keeps the optional dashboard aligned with generated files

## Commands and Paths

- Entry command: `python3 -m log_analysis_tool.main`
- Module name: `log_analysis_tool`
- Default CSV output: `output/alerts.csv`
- Default report output: `output/report/`
- Dashboard entry: `python3 -m flask --app log_analysis_tool.dashboard run`

## Run the Automated Tests

```bash
python3 -m pytest
```

Expected result:

- all tests pass
- coverage includes parser logic, detection rules, configurable thresholds, CLI behavior, CSV export shape, chart generation, and dashboard rendering

## Sample Log Files

Located in `samples/`:

- `normal_activity.log`
- `suspicious_activity.log`
- `noisy_input.log`
- `empty.log`

## CLI Validation Scenarios

### Normal Activity

```bash
python3 -m log_analysis_tool.main --input samples/normal_activity.log --year 2026
```

Expected:

- command runs successfully
- summary is displayed
- zero alerts or minimal alerts depending on the sample

### Suspicious Activity

```bash
python3 -m log_analysis_tool.main --input samples/suspicious_activity.log --year 2026
```

Expected:

- alerts are generated
- summary includes total events, total alerts, alerts by type, alerts by severity, and top offending IPs
- detailed alert output includes severity and reasoning

### Noisy Input

```bash
python3 -m log_analysis_tool.main --input samples/noisy_input.log --year 2026
```

Expected:

- malformed lines are skipped
- valid SSH lines are still processed
- the tool does not crash

### Custom Thresholds

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --brute-force-threshold 5 \
  --brute-force-window 10 \
  --success-threshold 3 \
  --success-window 15
```

Expected:

- command runs successfully
- rule settings are applied through the CLI without code changes

## Export Validation

### JSON Export

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --output-json output/alerts.json
```

Expected:

- `output/alerts.json` is created
- JSON is valid
- exported alerts match terminal output

### CSV Export

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --output-csv output/alerts.csv
```

Expected:

- `output/alerts.csv` is created
- columns are:

```text
timestamp,alert_type,severity,source_ip,username,count,description,reasoning
```

- rows match the generated alerts

## Report Generation Validation

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --output-json output/alerts.json \
  --output-csv output/alerts.csv \
  --generate-report \
  --report-dir output/report
```

Expected:

- `output/report/` is created
- SVG charts generated:
  - `alerts_by_type.svg`
  - `top_offending_ips.svg`
  - `failed_logins_over_time.svg`
- terminal prints the generated chart paths

## Dashboard Validation

After generating CSV and charts, run:

```bash
python3 -m flask --app log_analysis_tool.dashboard run
```

Expected:

- dashboard starts cleanly
- page shows a summary section, alerts table, and available charts
- dashboard uses the generated CSV and SVG files without a database

## Error Handling Checks

### Missing File

```bash
python3 -m log_analysis_tool.main --input samples/missing.log --year 2026
```

Expected:

- clean error message
- no traceback

### Empty File

```bash
python3 -m log_analysis_tool.main --input samples/empty.log --year 2026
```

Expected:

- `0` events processed
- `0` alerts
- clean exit

## Regression Workflow

After any code change:

1. Run the test suite

```bash
python3 -m pytest
```

2. Run the main demo command

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --output-json output/alerts.json \
  --output-csv output/alerts.csv \
  --generate-report \
  --report-dir output/report
```

3. Start the dashboard

```bash
python3 -m flask --app log_analysis_tool.dashboard run
```

Verify:

- terminal summary is correct
- exports are correct
- charts are generated
- dashboard reads the generated files successfully
