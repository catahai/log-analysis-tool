from datetime import datetime
from pathlib import Path

from log_analysis_tool.models import FAILED_LOGIN, SUCCESSFUL_LOGIN
from log_analysis_tool.parser import parse_auth_log_file, parse_auth_log_line


def test_parse_failed_password_line() -> None:
    line = (
        "Jan 12 10:15:31 host sshd[1234]: Failed password for invalid user admin "
        "from 192.168.1.10 port 51234 ssh2"
    )

    event = parse_auth_log_line(line, year=2026)

    assert event is not None
    assert event.timestamp == datetime(2026, 1, 12, 10, 15, 31)
    assert event.username == "admin"
    assert event.source_ip == "192.168.1.10"
    assert event.event_type == FAILED_LOGIN


def test_parse_successful_password_line() -> None:
    line = (
        "Jan 12 10:20:01 host sshd[1235]: Accepted password for alice "
        "from 192.168.1.10 port 51235 ssh2"
    )

    event = parse_auth_log_line(line, year=2026)

    assert event is not None
    assert event.timestamp == datetime(2026, 1, 12, 10, 20, 1)
    assert event.username == "alice"
    assert event.source_ip == "192.168.1.10"
    assert event.event_type == SUCCESSFUL_LOGIN


def test_ignore_non_ssh_auth_lines() -> None:
    line = "Jan 12 10:15:31 host sudo: pam_unix(sudo:session): session opened for user root"

    event = parse_auth_log_line(line, year=2026)

    assert event is None


def test_ignore_malformed_ssh_lines() -> None:
    line = "Jan 12 10:20:01 host sshd[1235]: Failed password from 192.168.1.10"

    event = parse_auth_log_line(line, year=2026)

    assert event is None


def test_parse_auth_log_file_skips_noise(tmp_path: Path) -> None:
    log_path = tmp_path / "noisy.log"
    log_path.write_text(
        "\n".join(
            [
                "bad line",
                "Jan 12 10:15:31 host sshd[1234]: Failed password for admin from 192.168.1.10 port 51234 ssh2",
                "Jan 12 10:16:31 host cron[1]: job started",
                "Jan 12 10:17:31 host sshd[1235]: Accepted password for alice from 192.168.1.11 port 51235 ssh2",
            ]
        ),
        encoding="utf-8",
    )

    events = parse_auth_log_file(log_path, year=2026)

    assert len(events) == 2
    assert [event.source_ip for event in events] == ["192.168.1.10", "192.168.1.11"]


def test_parse_auth_log_file_handles_empty_file(tmp_path: Path) -> None:
    log_path = tmp_path / "empty.log"
    log_path.write_text("", encoding="utf-8")

    events = parse_auth_log_file(log_path, year=2026)

    assert events == []
