from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from .models import AuthEvent, FAILED_LOGIN, SUCCESSFUL_LOGIN

FAILED_PATTERN = re.compile(
    r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+sshd\[\d+\]:\sFailed password for (?:invalid user )?"
    r"(?P<username>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)

SUCCESS_PATTERN = re.compile(
    r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+sshd\[\d+\]:\sAccepted password for "
    r"(?P<username>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)


def parse_auth_log_line(line: str, year: int | None = None) -> AuthEvent | None:
    """Parse one SSH auth.log line into an AuthEvent.

    Returns None when the line does not contain a supported SSH login event.
    """

    failed_match = FAILED_PATTERN.match(line)
    success_match = SUCCESS_PATTERN.match(line)
    match = failed_match or success_match
    if not match:
        return None

    event_type = FAILED_LOGIN if failed_match else SUCCESSFUL_LOGIN
    inferred_year = year if year is not None else datetime.now().year
    timestamp = datetime.strptime(
        f"{inferred_year} {match.group('stamp')}", "%Y %b %d %H:%M:%S"
    )
    return AuthEvent(
        timestamp=timestamp,
        username=match.group("username"),
        source_ip=match.group("ip"),
        event_type=event_type,
        raw_message=line.strip(),
    )


def parse_auth_log_file(path: str | Path, year: int | None = None) -> list[AuthEvent]:
    """Parse a log file and return supported SSH events in timestamp order."""

    events: list[AuthEvent] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            event = parse_auth_log_line(line, year=year)
            if event is not None:
                events.append(event)
    return sorted(events, key=lambda event: event.timestamp)
