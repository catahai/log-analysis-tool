# Sample Investigation Report

## Scenario

This sample review uses `samples/suspicious_activity.log` to demonstrate how the Log Analysis & Threat Detection Tool can support a junior analyst workflow for SSH authentication events.

## Inputs Analysed

- Linux SSH authentication log sample: `samples/suspicious_activity.log`
- Generated alerts:
  - `outputs/sample-alerts.json`
  - `outputs/sample-alerts.csv`
- Generated charts:
  - `reports/alerts-by-type.svg`
  - `reports/top-offending-ips.svg`
  - `reports/failed-logins-over-time.svg`

## Key Findings

- One source IP (`203.0.113.10`) triggered both brute-force and success-after-failures alerts.
- One source IP (`198.51.100.20`) attempted several invalid usernames in a short window, which is consistent with username enumeration.
- One source IP (`198.51.100.30`) attempted multiple usernames from the same host in a short period, which is consistent with a password spraying style pattern.
- One source IP (`192.0.2.55`) attempted to authenticate as `root`, which is unusual enough to deserve review even though the attempt was not successful in this sample.

## Highest Priority Alert

`success_after_failures` from `203.0.113.10`

Why it matters:

- repeated failed logins were followed by a successful login from the same IP
- this pattern can suggest that credentials were guessed, reused successfully, or otherwise compromised
- it represents the strongest compromise signal in the sample dataset

## Triage Questions

- Was the successful login from `203.0.113.10` expected for this user or environment?
- Is the source IP known, internal, or previously observed?
- Were there additional successful logins, lateral movement attempts, or privileged actions after the SSH access?
- Are the invalid usernames being probed meaningful for the target environment?
- Is `root` login normally disabled or heavily restricted on the system being reviewed?

## Recommended Next Actions

- validate whether the successful SSH login from `203.0.113.10` was legitimate
- check host and user activity immediately after the successful login
- review whether the targeted usernames are real, sensitive, or commonly abused
- confirm whether SSH hardening controls are in place, such as disabled root login or MFA where applicable
- block or monitor the suspicious source IPs if the activity is confirmed to be unauthorized

## Limitations

- this sample uses a small static log file rather than a live environment
- detections are intentionally rule-based and do not use external enrichment
- the tool focuses on a narrow SSH authentication use case and does not provide full endpoint context
