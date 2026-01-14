"""
Firewall log parser (iptables, pfSense, etc.).

Parses firewall logs for network traffic analysis.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from backend.parsers.base import LogParser, ParsedLog


class FirewallParser(LogParser):
    """
    Parser for firewall logs (iptables, pfSense, etc.).

    Supports:
    - iptables logs
    - pfSense logs
    - Generic firewall formats
    """

    # iptables pattern:
    # Jan 13 12:00:00 hostname kernel: [12345.678] IN=eth0 OUT= SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=80 ...
    IPTABLES_PATTERN = re.compile(
        r"IN=(?P<in_interface>\S*)\s+"
        r"OUT=(?P<out_interface>\S*)\s+"
        r".*?SRC=(?P<src_ip>[\d\.]+)\s+"
        r"DST=(?P<dst_ip>[\d\.]+)\s+"
        r".*?PROTO=(?P<protocol>\S+)\s+"
        r"(?:SPT=(?P<src_port>\d+)\s+)?"
        r"(?:DPT=(?P<dst_port>\d+))?"
    )

    def parse(self, log_line: str) -> ParsedLog:
        """
        Parse firewall log line.

        Args:
            log_line: Raw firewall log line

        Returns:
            ParsedLog object

        Raises:
            ValueError: If line cannot be parsed
        """
        # Try iptables format
        match = self.IPTABLES_PATTERN.search(log_line)
        if match:
            return self._parse_iptables(log_line, match)

        # Fallback: generic firewall event
        return ParsedLog(
            timestamp=datetime.now(timezone.utc),
            raw_log=log_line,
            message=log_line,
            event_type="firewall_generic",
        )

    def _parse_iptables(self, log_line: str, match: re.Match) -> ParsedLog:
        """Parse iptables log."""
        in_interface = match.group("in_interface") or None
        out_interface = match.group("out_interface") or None
        src_ip = match.group("src_ip")
        dst_ip = match.group("dst_ip")
        protocol = match.group("protocol")
        src_port_str = match.group("src_port")
        dst_port_str = match.group("dst_port")

        src_port = int(src_port_str) if src_port_str else None
        dst_port = int(dst_port_str) if dst_port_str else None

        # Extract timestamp from syslog prefix (if present)
        timestamp = self._extract_timestamp(log_line)

        # Determine action (ACCEPT, DROP, REJECT)
        action = self._determine_action(log_line)

        # Determine event type
        event_type = self._determine_firewall_event_type(action, protocol, dst_port, log_line)

        # Determine success (accepted = success, blocked = failure)
        success = action == "ACCEPT"

        return ParsedLog(
            timestamp=timestamp,
            raw_log=log_line,
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=protocol,
            event_type=event_type,
            success=success,
            status_message=action,
            severity="WARNING" if action != "ACCEPT" else "INFO",
            extra={
                "in_interface": in_interface,
                "out_interface": out_interface,
                "action": action,
            },
        )

    @staticmethod
    def _extract_timestamp(log_line: str) -> datetime:
        """Extract timestamp from syslog prefix."""
        # Try syslog format: "Jan 13 12:00:00"
        match = re.match(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", log_line)
        if match:
            from backend.parsers.base import LogParser

            return LogParser._parse_timestamp(match.group(1))

        # Fallback: current time
        return datetime.now(timezone.utc)

    @staticmethod
    def _determine_action(log_line: str) -> str:
        """Determine firewall action (ACCEPT, DROP, REJECT)."""
        line_upper = log_line.upper()

        if "ACCEPT" in line_upper:
            return "ACCEPT"
        if "DROP" in line_upper:
            return "DROP"
        if "REJECT" in line_upper:
            return "REJECT"

        # Default: assume blocked
        return "DROP"

    @staticmethod
    def _determine_firewall_event_type(
        action: str, protocol: str, dst_port: int | None, log_line: str
    ) -> str:
        """Determine specific firewall event type."""
        # Port-based detection
        if dst_port:
            # SSH
            if dst_port == 22:  # noqa: PLR2004
                return f"firewall_ssh_{action.lower()}"

            # HTTP/HTTPS
            if dst_port in (80, 443, 8080, 8443):
                return f"firewall_http_{action.lower()}"

            # RDP
            if dst_port == 3389:  # noqa: PLR2004
                return f"firewall_rdp_{action.lower()}"

            # SMB
            if dst_port in (139, 445):
                return f"firewall_smb_{action.lower()}"

            # DNS
            if dst_port == 53:  # noqa: PLR2004
                return f"firewall_dns_{action.lower()}"

            # Database ports
            if dst_port in (3306, 5432, 1433, 27017):
                return f"firewall_database_{action.lower()}"

        # Protocol-based detection
        protocol_lower = protocol.lower()

        if protocol_lower == "icmp":
            return f"firewall_icmp_{action.lower()}"

        if protocol_lower == "tcp":
            return f"firewall_tcp_{action.lower()}"

        if protocol_lower == "udp":
            return f"firewall_udp_{action.lower()}"

        # Generic
        return f"firewall_{action.lower()}"
