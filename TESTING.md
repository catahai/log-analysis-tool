# Testing Guide

## Overview

This document explains how to test the Log Analysis Tool, including unit tests and end-to-end CLI validation.

The goals are to verify that the tool:

- correctly parses SSH authentication logs
- detects suspicious behavior such as brute-force activity and success-after-failures patterns
- handles malformed input safely
- exports accurate JSON and CSV data
- generates correct SVG report charts when enabled

## Project Structure

```text
log-analysis-tool/
├── docs/
├── log_analysis_tool/
├── output/
├── samples/
├── tests/
├── README.md
├── TESTING.md
└── requirements.txt
```

## Commands and Paths

- Entry command: `python3 -m log_analysis_tool.main`
- Module name: `log_analysis_tool`
- Default chart output directory: `output/report/`

## Running Automated Tests

Run the full test suite:

```bash
python3 -m pytest
```

Expected result:

- all tests pass
- coverage includes parser logic, detection rules, CLI behavior, CSV export shape, and optional report generation

## Sample Logs

Located in:

```text
samples/
```

Files:

- `normal_activity.log` -> expected minimal or no alerts
- `suspicious_activity.log` -> triggers detection rules
- `noisy_input.log` -> contains malformed lines and noise
- `empty.log` -> contains no events

## CLI Test Scenarios

### 1. Normal Activity

```bash
python3 -m log_analysis_tool.main --input samples/normal_activity.log --year 2026
```

Expected:

- program runs successfully
- summary is displayed
- zero alerts or minimal alerts depending on the sample contents

### 2. Suspicious Activity

```bash
python3 -m log_analysis_tool.main --input samples/suspicious_activity.log --year 2026
```

Expected:

- alerts are generated
- summary includes:
  - total events processed
  - total alerts
  - alerts by type
  - alerts by severity
  - top offending IPs
- each alert includes severity and reasoning

### 3. Malformed or Noisy Input

```bash
python3 -m log_analysis_tool.main --input samples/noisy_input.log --year 2026
```

Expected:

- invalid lines are skipped
- valid lines are still processed
- the tool does not crash

## Export Testing

### JSON Export

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --output-json output/alerts.json
```

Expected:

- file created at `output/alerts.json`
- JSON structure is valid
- exported alerts match the terminal summary

### CSV Export

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --output-csv output/alerts.csv
```

Expected:

- file created at `output/alerts.csv`
- columns include:

```text
timestamp,alert_type,severity,source_ip,username,count,description,reasoning
```

- exported rows match the detected alerts shown in the terminal

## Report Generation Testing

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

- report directory created at `output/report/`
- SVG charts generated:
  - `alerts_by_type.svg`
  - `top_offending_ips.svg`
- terminal displays the generated file paths
- chart values match the summary and exported data

## Error Handling Tests

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

## Regression Testing Workflow

After any code change:

1. Run the automated tests

```bash
python3 -m pytest
```

2. Run the suspicious sample through the CLI

```bash
python3 -m log_analysis_tool.main --input samples/suspicious_activity.log --year 2026
```

3. Run the full export and reporting pipeline

```bash
python3 -m log_analysis_tool.main \
  --input samples/suspicious_activity.log \
  --year 2026 \
  --output-json output/alerts.json \
  --output-csv output/alerts.csv \
  --generate-report \
  --report-dir output/report
```

Verify:

- summary output is correct
- exports are correct
- charts match the alert data

## Testing Strategy

This project uses two testing layers.

Unit testing covers:

- parser correctness
- detection logic
- edge cases
- CLI and export behavior

End-to-end validation covers:

- command-line usability
- realistic sample logs
- export and reporting workflow

This keeps the project technically correct while also showing practical usability.
