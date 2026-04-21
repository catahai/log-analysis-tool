from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

FAILED_LOGIN = "failed_login"
SUCCESSFUL_LOGIN = "successful_login"


@dataclass(frozen=True)
class AuthEvent:
    """A parsed SSH authentication event from auth.log."""

    timestamp: datetime
    username: str
    source_ip: str
    event_type: str
    raw_message: str


@dataclass(frozen=True)
class Alert:
    """A detector result ready for CLI display and export."""

    alert_type: str
    severity: str
    source_ip: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    username: str | None
    description: str
    reasoning: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the alert using string timestamps for JSON and CSV output."""

        data = asdict(self)
        data["first_seen"] = self.first_seen.isoformat(sep=" ")
        data["last_seen"] = self.last_seen.isoformat(sep=" ")
        return data
