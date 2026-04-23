from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from .models import Alert, AuthEvent, FAILED_LOGIN, SUCCESSFUL_LOGIN


@dataclass(frozen=True)
class DetectionConfig:
    """Runtime configuration for the built-in detection rules."""

    brute_force_threshold: int = 5
    brute_force_window_minutes: int = 10
    success_after_failures_threshold: int = 3
    success_after_failures_window_minutes: int = 15


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
            )
        )
        recent_events.clear()

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
    return sorted(alerts, key=lambda alert: (alert.first_seen, alert.alert_type))
