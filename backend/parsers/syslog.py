"""
Syslog parser (RFC 3164 and RFC 5424).

Parses standard syslog messages from Unix/Linux systems.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from backend.parsers.base import LogParser, ParsedLog


class SyslogParser(LogParser):
    """
    Parser for syslog messages (RFC 3164, RFC 5424).

    Supports formats:
    - RFC 3164: "Jan 13 12:00:00 hostname process[pid]: message"
    - RFC 5424: "<priority>version timestamp hostname app-name procid msgid structured-data msg"
    """

    # Syslog facilities (RFC 3164)
    FACILITIES = {
        0: "kern",
        1: "user",
        2: "mail",
        3: "daemon",
        4: "auth",
        5: "syslog",
        6: "lpr",
        7: "news",
        8: "uucp",
        9: "cron",
        10: "authpriv",
        11: "ftp",
        16: "local0",
        17: "local1",
        18: "local2",
        19: "local3",
        20: "local4",
        21: "local5",
        22: "local6",
        23: "local7",
    }

    # Severity levels (RFC 3164)
    SEVERITIES = {
        0: "EMERGENCY",
        1: "ALERT",
        2: "CRITICAL",
        3: "ERROR",
        4: "WARNING",
        5: "NOTICE",
        6: "INFO",
        7: "DEBUG",
    }

    # RFC 3164 pattern: "Jan 13 12:00:00 hostname process[pid]: message"
    RFC3164_PATTERN = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*"
        r"(?P<message>.+)$"
    )

    # RFC 5424 pattern: "<priority>version timestamp hostname app procid msgid structured-data msg"
    RFC5424_PATTERN = re.compile(
        r"^<(?P<priority>\d+)>"
        r"(?P<version>\d+)\s+"
        r"(?P<timestamp>\S+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<app>\S+)\s+"
        r"(?P<procid>\S+)\s+"
        r"(?P<msgid>\S+)\s+"
        r"(?P<structured_data>\S+)\s+"
        r"(?P<message>.+)$"
    )

    def parse(self, log_line: str) -> ParsedLog:
        """
        Parse syslog message.

        Args:
            log_line: Raw syslog line

        Returns:
            ParsedLog object

        Raises:
            ValueError: If line cannot be parsed
        """
        # Try RFC 5424 first (has priority prefix)
        if log_line.startswith("<"):
            return self._parse_rfc5424(log_line)

        # Try RFC 3164
        match = self.RFC3164_PATTERN.match(log_line)
        if match:
            return self._parse_rfc3164(log_line, match)

        # Fallback: treat as generic message
        return ParsedLog(
            timestamp=datetime.now(timezone.utc),
            raw_log=log_line,
            message=log_line,
            event_type="syslog_generic",
        )

    def _parse_rfc3164(self, log_line: str, match: re.Match) -> ParsedLog:
        """Parse RFC 3164 format."""
        timestamp_str = match.group("timestamp")
        hostname = match.group("hostname")
        process = match.group("process")
        pid_str = match.group("pid")
        message = match.group("message")

        timestamp = self._parse_timestamp(timestamp_str)
        pid = int(pid_str) if pid_str else None

        # Determine event type from process name
        event_type = self._determine_event_type(process, message)

        # Extract additional fields from message
        username = self._extract_username(message)
        source_ip = self._extract_ip(message)
        success = self._determine_success(message)

        return ParsedLog(
            timestamp=timestamp,
            raw_log=log_line,
            hostname=hostname,
            process_name=process,
            process_id=pid,
            message=message,
            event_type=event_type,
            username=username,
            source_ip=source_ip,
            success=success,
            facility="syslog",
            severity=self._determine_severity(message),
        )

    def _parse_rfc5424(self, log_line: str) -> ParsedLog:
        """Parse RFC 5424 format."""
        match = self.RFC5424_PATTERN.match(log_line)
        if not match:
            msg = f"Invalid RFC 5424 format: {log_line[:100]}"
            raise ValueError(msg)

        priority = int(match.group("priority"))
        version = int(match.group("version"))
        timestamp_str = match.group("timestamp")
        hostname = match.group("hostname")
        app = match.group("app")
        procid_str = match.group("procid")
        msgid = match.group("msgid")
        message = match.group("message")

        # Decode priority into facility and severity
        facility_code = priority // 8
        severity_code = priority % 8

        facility = self.FACILITIES.get(facility_code, f"unknown_{facility_code}")
        severity = self.SEVERITIES.get(severity_code, f"unknown_{severity_code}")

        timestamp = self._parse_timestamp(timestamp_str)
        pid = int(procid_str) if procid_str.isdigit() else None

        event_type = self._determine_event_type(app, message)
        username = self._extract_username(message)
        source_ip = self._extract_ip(message)
        success = self._determine_success(message)

        return ParsedLog(
            timestamp=timestamp,
            raw_log=log_line,
            hostname=hostname,
            process_name=app,
            process_id=pid,
            message=message,
            event_type=event_type,
            username=username,
            source_ip=source_ip,
            success=success,
            facility=facility,
            severity=severity,
            extra={"version": version, "msgid": msgid},
        )

    @staticmethod
    def _determine_event_type(process: str, message: str) -> str:
        """Determine event type from process name and message."""
        process_lower = process.lower()
        message_lower = message.lower()

        # SSH events
        if "sshd" in process_lower:
            if "failed password" in message_lower or "authentication failure" in message_lower:
                return "ssh_auth_failed"
            if "accepted" in message_lower:
                return "ssh_auth_success"
            if "invalid user" in message_lower:
                return "ssh_invalid_user"
            if "connection closed" in message_lower:
                return "ssh_connection_closed"
            return "ssh_event"

        # Sudo events
        if "sudo" in process_lower:
            if "command" in message_lower:
                return "sudo_command"
            if "authentication failure" in message_lower:
                return "sudo_auth_failed"
            return "sudo_event"

        # Kernel events
        if "kernel" in process_lower:
            return "kernel_event"

        # Cron events
        if "cron" in process_lower:
            return "cron_event"

        # Systemd events
        if "systemd" in process_lower:
            return "systemd_event"

        return "syslog_generic"

    @staticmethod
    def _extract_username(message: str) -> str | None:
        """Extract username from message."""
        # Pattern: "for <username>"
        match = re.search(r"\bfor\s+(\S+)", message)
        if match:
            username = match.group(1)
            # Filter out common non-username words
            if username not in ("invalid", "illegal", "unknown"):
                return username

        # Pattern: "user=<username>"
        match = re.search(r"\buser=(\S+)", message, re.IGNORECASE)
        if match:
            return match.group(1)

        return None

    @staticmethod
    def _extract_ip(message: str) -> str | None:
        """Extract IP address from message."""
        # IPv4 pattern
        match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)
        if match:
            return match.group(0)

        # IPv6 pattern (simplified)
        match = re.search(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", message)
        if match:
            return match.group(0)

        return None

    @staticmethod
    def _determine_success(message: str) -> bool | None:
        """Determine if event was successful."""
        message_lower = message.lower()

        # Success indicators
        if any(word in message_lower for word in ["accepted", "success", "granted", "allowed"]):
            return True

        # Failure indicators
        if any(
            word in message_lower
            for word in [
                "failed",
                "failure",
                "denied",
                "rejected",
                "invalid",
                "illegal",
                "error",
            ]
        ):
            return False

        return None

    @staticmethod
    def _determine_severity(message: str) -> str:
        """Determine severity from message content."""
        message_lower = message.lower()

        if any(word in message_lower for word in ["emergency", "panic"]):
            return "EMERGENCY"
        if any(word in message_lower for word in ["alert", "critical"]):
            return "CRITICAL"
        if any(word in message_lower for word in ["error", "failed", "failure"]):
            return "ERROR"
        if any(word in message_lower for word in ["warning", "warn"]):
            return "WARNING"

        return "INFO"
