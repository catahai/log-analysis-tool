from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from pathlib import Path

from .models import Alert, AuthEvent, FAILED_LOGIN, SUCCESSFUL_LOGIN


@dataclass(frozen=True)
class DetectionConfig:
    """Runtime configuration for the built-in detection rules."""

    brute_force_threshold: int = 5
    brute_force_window_minutes: int = 10
    success_after_failures_threshold: int = 3
    success_after_failures_window_minutes: int = 15
    invalid_user_threshold: int = 3
    invalid_user_window_minutes: int = 10
    password_spray_username_threshold: int = 3
    password_spray_window_minutes: int = 10
    root_login_threshold: int = 1
    root_login_window_minutes: int = 15

    @classmethod
    def from_json_file(cls, path: str | Path) -> "DetectionConfig":
        """Load detector settings from a JSON file."""

        with Path(path).open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return cls(**data)


def _related_messages(events: list[AuthEvent], limit: int = 5) -> list[str]:
    """Return a short list of related raw log messages for alert context."""

    return [event.raw_message for event in events[:limit]]


def _trim_old_events(events: deque[AuthEvent], current_time: datetime, window: timedelta) -> None:
    """Remove events that fall outside the current rolling time window."""

    while events and current_time - events[0].timestamp > window:
        events.popleft()


def detect_brute_force(
    events: list[AuthEvent], threshold: int = 5, window_minutes: int = 10
) -> list[Alert]:
    """Alert on repeated failed logins from one IP within a short time window."""

    failures_by_ip: dict[str, deque[AuthEvent]] = defaultdict(deque)
    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)
    alerted_ips: set[str] = set()

    for event in sorted(events, key=lambda item: item.timestamp):
        if event.event_type != FAILED_LOGIN:
            continue

        failures = failures_by_ip[event.source_ip]
        failures.append(event)
        _trim_old_events(failures, event.timestamp, window)

        if len(failures) < threshold or event.source_ip in alerted_ips:
            continue

        alerts.append(
            Alert(
                alert_type="brute_force",
                severity="medium",
                source_ip=event.source_ip,
                event_count=len(failures),
                first_seen=failures[0].timestamp,
                last_seen=failures[-1].timestamp,
                username=failures[-1].username,
                description=(
                    f"{len(failures)} failed logins from {event.source_ip} "
                    f"within {window_minutes} minutes"
                ),
                reasoning=(
                    f"The IP reached the brute-force threshold of {threshold} failed "
                    f"logins inside a {window_minutes}-minute window."
                ),
                related_events=_related_messages(list(failures)),
            )
        )
        alerted_ips.add(event.source_ip)

    return alerts


def detect_success_after_failures(
    events: list[AuthEvent], threshold: int = 3, window_minutes: int = 15
) -> list[Alert]:
    """Alert when several failed logins are followed by a success from the same IP."""

    recent_events_by_ip: dict[str, deque[AuthEvent]] = defaultdict(deque)
    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)

    for event in sorted(events, key=lambda item: item.timestamp):
        recent_events = recent_events_by_ip[event.source_ip]
        recent_events.append(event)
        _trim_old_events(recent_events, event.timestamp, window)

        if event.event_type != SUCCESSFUL_LOGIN:
            continue

        failed_events = [item for item in recent_events if item.event_type == FAILED_LOGIN]
        if len(failed_events) < threshold:
            continue

        alerts.append(
            Alert(
                alert_type="success_after_failures",
                severity="high",
                source_ip=event.source_ip,
                event_count=len(failed_events),
                first_seen=failed_events[0].timestamp,
                last_seen=event.timestamp,
                username=event.username,
                description=(
                    f"{len(failed_events)} failed logins followed by a success "
                    f"from {event.source_ip} within {window_minutes} minutes"
                ),
                reasoning=(
                    f"The IP had at least {threshold} failed logins and then a "
                    f"successful login inside a {window_minutes}-minute window."
                ),
                related_events=_related_messages(failed_events + [event]),
            )
        )
        recent_events.clear()

    return alerts


def detect_invalid_user_enumeration(
    events: list[AuthEvent], threshold: int = 3, window_minutes: int = 10
) -> list[Alert]:
    """Alert on repeated invalid-user attempts that suggest account discovery."""

    invalid_events_by_ip: dict[str, deque[AuthEvent]] = defaultdict(deque)
    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)
    alerted_ips: set[str] = set()

    for event in sorted(events, key=lambda item: item.timestamp):
        if event.event_type != FAILED_LOGIN or not event.is_invalid_user:
            continue

        invalid_events = invalid_events_by_ip[event.source_ip]
        invalid_events.append(event)
        _trim_old_events(invalid_events, event.timestamp, window)

        if len(invalid_events) < threshold or event.source_ip in alerted_ips:
            continue

        alerts.append(
            Alert(
                alert_type="invalid_user_enumeration",
                severity="medium",
                source_ip=event.source_ip,
                event_count=len(invalid_events),
                first_seen=invalid_events[0].timestamp,
                last_seen=invalid_events[-1].timestamp,
                username=invalid_events[-1].username,
                description=(
                    f"{len(invalid_events)} invalid username attempts from {event.source_ip} "
                    f"within {window_minutes} minutes"
                ),
                reasoning=(
                    f"The source IP repeatedly attempted usernames that do not exist, which "
                    f"can indicate username enumeration or account discovery activity."
                ),
                related_events=_related_messages(list(invalid_events)),
            )
        )
        alerted_ips.add(event.source_ip)

    return alerts


def detect_password_spraying(
    events: list[AuthEvent], username_threshold: int = 3, window_minutes: int = 10
) -> list[Alert]:
    """Alert when one IP tries several usernames in a short time window."""

    failures_by_ip: dict[str, deque[AuthEvent]] = defaultdict(deque)
    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)
    alerted_ips: set[str] = set()

    for event in sorted(events, key=lambda item: item.timestamp):
        if event.event_type != FAILED_LOGIN or event.is_invalid_user:
            continue

        failures = failures_by_ip[event.source_ip]
        failures.append(event)
        _trim_old_events(failures, event.timestamp, window)
        distinct_usernames = {item.username for item in failures}

        if len(distinct_usernames) < username_threshold or event.source_ip in alerted_ips:
            continue

        alerts.append(
            Alert(
                alert_type="password_spraying",
                severity="medium",
                source_ip=event.source_ip,
                event_count=len(distinct_usernames),
                first_seen=failures[0].timestamp,
                last_seen=failures[-1].timestamp,
                username=None,
                description=(
                    f"{len(distinct_usernames)} usernames targeted from {event.source_ip} "
                    f"within {window_minutes} minutes"
                ),
                reasoning=(
                    f"The source IP attempted multiple usernames in a short window, which "
                    f"is consistent with a password spraying style pattern."
                ),
                related_events=_related_messages(list(failures)),
            )
        )
        alerted_ips.add(event.source_ip)

    return alerts


def detect_root_login_attempts(
    events: list[AuthEvent], threshold: int = 1, window_minutes: int = 15
) -> list[Alert]:
    """Alert on attempts to authenticate as root, especially if successful."""

    root_events_by_ip: dict[str, deque[AuthEvent]] = defaultdict(deque)
    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)
    alerted_ips: set[str] = set()

    for event in sorted(events, key=lambda item: item.timestamp):
        if event.username != "root" or event.event_type not in {FAILED_LOGIN, SUCCESSFUL_LOGIN}:
            continue

        root_events = root_events_by_ip[event.source_ip]
        root_events.append(event)
        _trim_old_events(root_events, event.timestamp, window)

        if len(root_events) < threshold or event.source_ip in alerted_ips:
            continue

        has_success = any(item.event_type == SUCCESSFUL_LOGIN for item in root_events)
        severity = "high" if has_success else "low"
        description = (
            f"Root login succeeded from {event.source_ip}"
            if has_success
            else f"Root login attempt(s) observed from {event.source_ip}"
        )
        reasoning = (
            "A successful root login is high priority because it suggests privileged access "
            "may have been obtained."
            if has_success
            else "Root login attempts are uncommon in many environments and can indicate "
            "targeting of privileged access."
        )

        alerts.append(
            Alert(
                alert_type="root_login_attempt",
                severity=severity,
                source_ip=event.source_ip,
                event_count=len(root_events),
                first_seen=root_events[0].timestamp,
                last_seen=root_events[-1].timestamp,
                username="root",
                description=description,
                reasoning=reasoning,
                related_events=_related_messages(list(root_events)),
            )
        )
        alerted_ips.add(event.source_ip)

    return alerts


def run_all_detectors(events: list[AuthEvent]) -> list[Alert]:
    """Run every detector and return alerts in a stable display order."""

    return run_detectors(events, DetectionConfig())


def run_detectors(events: list[AuthEvent], config: DetectionConfig) -> list[Alert]:
    """Run every detector using the provided configuration."""

    alerts: list[Alert] = []
    alerts.extend(
        detect_brute_force(
            events,
            threshold=config.brute_force_threshold,
            window_minutes=config.brute_force_window_minutes,
        )
    )
    alerts.extend(
        detect_success_after_failures(
            events,
            threshold=config.success_after_failures_threshold,
            window_minutes=config.success_after_failures_window_minutes,
        )
    )
    alerts.extend(
        detect_invalid_user_enumeration(
            events,
            threshold=config.invalid_user_threshold,
            window_minutes=config.invalid_user_window_minutes,
        )
    )
    alerts.extend(
        detect_password_spraying(
            events,
            username_threshold=config.password_spray_username_threshold,
            window_minutes=config.password_spray_window_minutes,
        )
    )
    alerts.extend(
        detect_root_login_attempts(
            events,
            threshold=config.root_login_threshold,
            window_minutes=config.root_login_window_minutes,
        )
    )
    return sorted(alerts, key=lambda alert: (alert.first_seen, alert.alert_type))
