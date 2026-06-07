# Detection Rules

This document maps the current rules to relevant MITRE ATT&CK themes where appropriate. These are practical portfolio-oriented mappings rather than formal ATT&CK coverage claims.

## Severity Logic

- `Low`: suspicious but relatively common activity that deserves review
- `Medium`: repeated suspicious behavior or scanning-style activity
- `High`: activity that may indicate successful compromise or privileged access risk

## Detection Rules

| Detection rule | Signal | Why it matters | Severity | Mapped to relevant MITRE ATT&CK themes |
|---|---|---|---|---|
| `brute_force` | Repeated failed logins from one IP within a short window | Repeated password guessing can indicate direct credential attack activity | Medium | `T1110 Brute Force`, `T1021.004 SSH` |
| `success_after_failures` | Multiple failed logins followed by a success from the same IP | This can indicate guessed credentials, credential reuse, or other account compromise activity | High | `T1078 Valid Accounts`, `T1110 Brute Force`, `T1021.004 SSH` |
| `invalid_user_enumeration` | Multiple invalid username attempts from one IP | Repeated attempts against non-existent usernames can suggest account discovery or reconnaissance | Medium | `T1087 Account Discovery`, `T1110 Brute Force` |
| `password_spraying` | Multiple usernames targeted from the same IP in a short window | One source trying many usernames can reflect password spraying behavior | Medium | `T1110.003 Password Spraying`, `T1021.004 SSH` |
| `root_login_attempt` | Authentication attempt involving the `root` account | Root account targeting is often higher risk because it involves privileged access | Low for failed attempts, High if successful | `T1078 Valid Accounts`, `T1021.004 SSH` |

## Notes

- These detections are intentionally simple and explainable.
- Thresholds and windows are configurable through CLI flags and optional JSON config.
- The goal is to show practical SOC-style alert generation, not formal ATT&CK coverage or production-grade detection engineering.
