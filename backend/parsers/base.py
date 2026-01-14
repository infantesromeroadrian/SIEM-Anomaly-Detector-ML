"""
Base parser for log files.

Abstract base class for all log parsers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ParsedLog:
    """
    Standardized parsed log entry.

    All parsers return this structure for consistent feature extraction.
    """

    # Required fields
    timestamp: datetime
    raw_log: str

    # Source information
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None

    # Request/Event information
    event_type: str | None = None  # ssh_login, http_request, firewall_block, etc.
    method: str | None = None  # GET, POST, etc. (HTTP)
    endpoint: str | None = None  # /api/users (HTTP)
    protocol: str | None = None  # HTTP/1.1, SSH2, TCP, etc.

    # Status/Result
    status_code: int | None = None  # HTTP status or custom status
    status_message: str | None = None  # OK, Failed, Denied, etc.
    success: bool | None = None  # True/False/None

    # User information
    username: str | None = None
    user_id: str | None = None

    # Data transfer
    bytes_sent: int = 0
    bytes_received: int = 0

    # Network information
    hostname: str | None = None
    process_name: str | None = None
    process_id: int | None = None

    # HTTP-specific
    user_agent: str | None = None
    referer: str | None = None

    # Payload/Message
    payload: str | None = None
    message: str | None = None

    # Geographic (optional, can be enriched later)
    country: str | None = None
    city: str | None = None

    # Metadata
    severity: str | None = None  # INFO, WARNING, ERROR, CRITICAL
    facility: str | None = None  # auth, kern, user, etc. (syslog)
    tags: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for feature extraction."""
        return {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip or "unknown",
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "event_type": self.event_type or "unknown",
            "method": self.method,
            "endpoint": self.endpoint or "",
            "protocol": self.protocol,
            "status_code": self.status_code or 0,
            "status_message": self.status_message,
            "success": self.success,
            "username": self.username or "",
            "user_id": self.user_id,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "hostname": self.hostname,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "user_agent": self.user_agent or "",
            "referer": self.referer,
            "payload": self.payload or self.raw_log,
            "message": self.message or "",
            "country": self.country,
            "city": self.city,
            "severity": self.severity,
            "facility": self.facility,
            "tags": self.tags,
            "extra": self.extra,
        }


class LogParser(ABC):
    """
    Abstract base class for log parsers.

    All parsers must implement the parse() method.
    """

    @abstractmethod
    def parse(self, log_line: str) -> ParsedLog:
        """
        Parse a single log line.

        Args:
            log_line: Raw log line string

        Returns:
            ParsedLog object with extracted fields

        Raises:
            ValueError: If log line cannot be parsed
        """
        pass

    def parse_batch(self, log_lines: list[str]) -> list[ParsedLog]:
        """
        Parse multiple log lines.

        Args:
            log_lines: List of raw log line strings

        Returns:
            List of ParsedLog objects
        """
        results = []
        for line in log_lines:
            try:
                results.append(self.parse(line))
            except ValueError:
                # Skip unparseable lines
                continue
        return results

    @staticmethod
    def _parse_timestamp(timestamp_str: str, year: int | None = None) -> datetime:
        """
        Parse timestamp string to datetime.

        Args:
            timestamp_str: Timestamp string (various formats)
            year: Year to use if not in timestamp (syslog format)

        Returns:
            datetime object (UTC)
        """
        import calendar
        from datetime import datetime, timezone

        # Common syslog format: "Jan 13 12:00:00"
        if year is None:
            year = datetime.now(timezone.utc).year

        month_map = {
            "Jan": 1,
            "Feb": 2,
            "Mar": 3,
            "Apr": 4,
            "May": 5,
            "Jun": 6,
            "Jul": 7,
            "Aug": 8,
            "Sep": 9,
            "Oct": 10,
            "Nov": 11,
            "Dec": 12,
        }

        # Try syslog format: "Jan 13 12:00:00"
        parts = timestamp_str.split()
        if len(parts) >= 3 and parts[0] in month_map:  # noqa: PLR2004
            month = month_map[parts[0]]
            day = int(parts[1])
            time_parts = parts[2].split(":")
            hour = int(time_parts[0])
            minute = int(time_parts[1])
            second = int(time_parts[2]) if len(time_parts) > 2 else 0  # noqa: PLR2004

            return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)

        # Try ISO format: "2026-01-13T12:00:00Z"
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except ValueError:
            pass

        # Fallback: use current time
        return datetime.now(timezone.utc)
