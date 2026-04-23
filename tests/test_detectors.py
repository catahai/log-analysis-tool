from datetime import datetime

from log_analysis_tool.detectors import (
    DetectionConfig,
    detect_brute_force,
    detect_success_after_failures,
    run_detectors,
)
from log_analysis_tool.models import AuthEvent, FAILED_LOGIN, SUCCESSFUL_LOGIN


def build_event(
    minute: int, event_type: str, ip: str = "10.0.0.8", username: str = "alice"
) -> AuthEvent:
    return AuthEvent(
        timestamp=datetime(2026, 1, 12, 10, minute, 0),
        username=username,
        source_ip=ip,
        event_type=event_type,
        raw_message=f"{event_type} {ip}",
    )


def test_detect_brute_force_alert_when_threshold_reached() -> None:
    events = [build_event(minute, FAILED_LOGIN) for minute in [0, 1, 2, 3, 4]]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "brute_force"
    assert alert.severity == "medium"
    assert alert.source_ip == "10.0.0.8"
    assert alert.event_count == 5
    assert alert.first_seen == datetime(2026, 1, 12, 10, 0, 0)
    assert alert.last_seen == datetime(2026, 1, 12, 10, 4, 0)
    assert "threshold" in alert.reasoning


def test_detect_brute_force_skips_events_outside_window() -> None:
    events = [build_event(minute, FAILED_LOGIN) for minute in [0, 3, 6, 9, 20]]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_detect_brute_force_does_not_alert_below_threshold() -> None:
    events = [build_event(minute, FAILED_LOGIN) for minute in [0, 1, 2, 3]]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_detect_brute_force_separates_multiple_ips() -> None:
    events = [
        build_event(0, FAILED_LOGIN, ip="10.0.0.8"),
        build_event(1, FAILED_LOGIN, ip="10.0.0.8"),
        build_event(2, FAILED_LOGIN, ip="10.0.0.8"),
        build_event(3, FAILED_LOGIN, ip="10.0.0.8"),
        build_event(4, FAILED_LOGIN, ip="10.0.0.8"),
        build_event(0, FAILED_LOGIN, ip="10.0.0.9"),
        build_event(1, FAILED_LOGIN, ip="10.0.0.9"),
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0].source_ip == "10.0.0.8"


def test_detect_success_after_failures_alert() -> None:
    events = [
        build_event(0, FAILED_LOGIN),
        build_event(2, FAILED_LOGIN),
        build_event(4, FAILED_LOGIN),
        build_event(10, SUCCESSFUL_LOGIN),
    ]

    alerts = detect_success_after_failures(events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "success_after_failures"
    assert alert.severity == "high"
    assert alert.source_ip == "10.0.0.8"
    assert alert.event_count == 3
    assert alert.first_seen == datetime(2026, 1, 12, 10, 0, 0)
    assert alert.last_seen == datetime(2026, 1, 12, 10, 10, 0)
    assert "successful login" in alert.reasoning


def test_detect_success_after_failures_requires_window() -> None:
    events = [
        build_event(0, FAILED_LOGIN),
        build_event(2, FAILED_LOGIN),
        build_event(4, FAILED_LOGIN),
        build_event(21, SUCCESSFUL_LOGIN),
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []


def test_detect_success_after_failures_is_isolated_per_ip() -> None:
    events = [
        build_event(0, FAILED_LOGIN, ip="10.0.0.8"),
        build_event(1, FAILED_LOGIN, ip="10.0.0.8"),
        build_event(2, FAILED_LOGIN, ip="10.0.0.8"),
        build_event(3, SUCCESSFUL_LOGIN, ip="10.0.0.9"),
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []


def test_detect_success_after_failures_does_not_alert_below_threshold() -> None:
    events = [
        build_event(0, FAILED_LOGIN),
        build_event(2, FAILED_LOGIN),
        build_event(10, SUCCESSFUL_LOGIN),
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []


def test_detect_success_after_failures_ignores_success_before_failures() -> None:
    events = [
        build_event(0, SUCCESSFUL_LOGIN),
        build_event(1, FAILED_LOGIN),
        build_event(2, FAILED_LOGIN),
        build_event(3, FAILED_LOGIN),
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []


def test_run_detectors_uses_custom_config() -> None:
    events = [
        build_event(0, FAILED_LOGIN),
        build_event(1, FAILED_LOGIN),
        build_event(2, FAILED_LOGIN),
        build_event(3, SUCCESSFUL_LOGIN),
    ]

    alerts = run_detectors(
        events,
        DetectionConfig(
            brute_force_threshold=10,
            brute_force_window_minutes=10,
            success_after_failures_threshold=2,
            success_after_failures_window_minutes=5,
        ),
    )

    assert len(alerts) == 1
    assert alerts[0].alert_type == "success_after_failures"
