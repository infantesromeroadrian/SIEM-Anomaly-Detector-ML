"""
Nginx log parser (access and error logs).

Parses Nginx access logs and error logs.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from backend.parsers.base import LogParser, ParsedLog


class NginxParser(LogParser):
    """
    Parser for Nginx access and error logs.

    Supports:
    - Access log (combined format)
    - Error log
    """

    # Access log pattern (combined format):
    # 192.168.1.1 - user [13/Jan/2026:12:00:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0..."
    ACCESS_PATTERN = re.compile(
        r"^(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+"
        r"\[(?P<timestamp>[^\]]+)\]\s+"
        r'"(?P<method>\S+)\s+(?P<endpoint>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r"(?P<status>\d+)\s+(?P<bytes>\d+)\s+"
        r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    )

    # Error log pattern:
    # 2026/01/13 12:00:00 [error] 12345#0: *67890 connect() failed (111: Connection refused)
    ERROR_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"\[(?P<level>\w+)\]\s+"
        r"(?P<pid>\d+)#\d+:\s+"
        r"(?:\*(?P<conn_id>\d+)\s+)?"
        r"(?P<message>.+)$"
    )

    def parse(self, log_line: str) -> ParsedLog:
        """
        Parse Nginx log line.

        Args:
            log_line: Raw Nginx log line

        Returns:
            ParsedLog object

        Raises:
            ValueError: If line cannot be parsed
        """
        # Try access log format
        match = self.ACCESS_PATTERN.match(log_line)
        if match:
            return self._parse_access_log(log_line, match)

        # Try error log format
        match = self.ERROR_PATTERN.match(log_line)
        if match:
            return self._parse_error_log(log_line, match)

        # Fallback
        return ParsedLog(
            timestamp=datetime.now(timezone.utc),
            raw_log=log_line,
            message=log_line,
            event_type="nginx_generic",
        )

    def _parse_access_log(self, log_line: str, match: re.Match) -> ParsedLog:
        """Parse Nginx access log."""
        source_ip = match.group("ip")
        user = match.group("user")
        timestamp_str = match.group("timestamp")
        method = match.group("method")
        endpoint = match.group("endpoint")
        protocol = match.group("protocol")
        status = int(match.group("status"))
        bytes_sent = int(match.group("bytes"))
        referer = match.group("referer")
        user_agent = match.group("user_agent")

        # Parse timestamp: "13/Jan/2026:12:00:00 +0000"
        timestamp = self._parse_nginx_timestamp(timestamp_str)

        # Determine success
        success = 200 <= status < 400

        # Determine event type
        event_type = self._determine_access_event_type(method, endpoint, status)

        return ParsedLog(
            timestamp=timestamp,
            raw_log=log_line,
            source_ip=source_ip,
            username=user if user != "-" else None,
            method=method,
            endpoint=endpoint,
            protocol=protocol,
            status_code=status,
            bytes_sent=bytes_sent,
            referer=referer if referer and referer != "-" else None,
            user_agent=user_agent if user_agent and user_agent != "-" else None,
            event_type=event_type,
            success=success,
            severity=self._determine_severity_from_status(status),
        )

    def _parse_error_log(self, log_line: str, match: re.Match) -> ParsedLog:
        """Parse Nginx error log."""
        timestamp_str = match.group("timestamp")
        level = match.group("level")
        pid = int(match.group("pid"))
        conn_id_str = match.group("conn_id")
        message = match.group("message")

        # Parse timestamp: "2026/01/13 12:00:00"
        timestamp = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )

        conn_id = int(conn_id_str) if conn_id_str else None

        # Extract IP from message if present
        source_ip = self._extract_ip(message)

        return ParsedLog(
            timestamp=timestamp,
            raw_log=log_line,
            source_ip=source_ip,
            process_name="nginx",
            process_id=pid,
            message=message,
            event_type="nginx_error",
            success=False,
            severity=self._map_nginx_level(level),
            extra={"connection_id": conn_id},
        )

    @staticmethod
    def _parse_nginx_timestamp(timestamp_str: str) -> datetime:
        """Parse Nginx timestamp: '13/Jan/2026:12:00:00 +0000'"""
        # Remove timezone part for simplicity
        timestamp_str = timestamp_str.split()[0]
        return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc)

    @staticmethod
    def _determine_access_event_type(method: str, endpoint: str, status: int) -> str:
        """Determine event type from access log fields."""
        endpoint_lower = endpoint.lower()

        # Authentication endpoints
        if any(path in endpoint_lower for path in ["/login", "/auth", "/signin", "/signup"]):
            if status < 400:  # noqa: PLR2004
                return "http_auth_success"
            return "http_auth_failed"

        # Admin endpoints
        if "/admin" in endpoint_lower:
            return "http_admin_access"

        # API endpoints
        if "/api/" in endpoint_lower:
            return "http_api_request"

        # File uploads
        if method in ("POST", "PUT") and any(
            ext in endpoint_lower for ext in [".php", ".jsp", ".asp"]
        ):
            return "http_file_upload"

        # SQL injection indicators
        if any(
            pattern in endpoint_lower for pattern in ["union", "select", "drop", "insert", "' or "]
        ):
            return "http_sql_injection_attempt"

        # Path traversal
        if "../" in endpoint or "..%2f" in endpoint_lower:
            return "http_path_traversal_attempt"

        # XSS
        if any(pattern in endpoint_lower for pattern in ["<script", "javascript:", "onerror="]):
            return "http_xss_attempt"

        # Generic HTTP request
        return "http_request"

    @staticmethod
    def _determine_severity_from_status(status: int) -> str:
        """Map HTTP status to severity."""
        if status >= 500:  # noqa: PLR2004
            return "ERROR"
        if status >= 400:  # noqa: PLR2004
            return "WARNING"
        return "INFO"

    @staticmethod
    def _map_nginx_level(level: str) -> str:
        """Map Nginx log level to standard severity."""
        mapping = {
            "emerg": "EMERGENCY",
            "alert": "ALERT",
            "crit": "CRITICAL",
            "error": "ERROR",
            "warn": "WARNING",
            "notice": "NOTICE",
            "info": "INFO",
            "debug": "DEBUG",
        }
        return mapping.get(level.lower(), "INFO")

    @staticmethod
    def _extract_ip(message: str) -> str | None:
        """Extract IP address from error message."""
        match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)
        return match.group(0) if match else None
