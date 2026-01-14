"""
Log parsers for SIEM Anomaly Detector.

Supports multiple log formats:
- Syslog (RFC 3164, RFC 5424)
- Nginx (access, error logs)
- Auth logs (/var/log/auth.log)
- Firewall logs (iptables, pfSense)
"""

from __future__ import annotations

from backend.parsers.base import LogParser, ParsedLog
from backend.parsers.syslog import SyslogParser
from backend.parsers.nginx import NginxParser
from backend.parsers.auth import AuthLogParser
from backend.parsers.firewall import FirewallParser

__all__ = [
    "LogParser",
    "ParsedLog",
    "SyslogParser",
    "NginxParser",
    "AuthLogParser",
    "FirewallParser",
    "get_parser",
]


def get_parser(source: str) -> LogParser:
    """
    Get appropriate parser for log source.

    Args:
        source: Log source type (syslog, nginx, auth, firewall, custom)

    Returns:
        LogParser instance

    Raises:
        ValueError: If source type is not supported

    Example:
        >>> parser = get_parser("syslog")
        >>> parsed = parser.parse("Jan 13 12:00:00 server sshd[123]: Failed password")
    """
    parsers = {
        "syslog": SyslogParser(),
        "nginx": NginxParser(),
        "auth": AuthLogParser(),
        "firewall": FirewallParser(),
    }

    if source not in parsers:
        msg = f"Unsupported log source: {source}. Supported: {', '.join(parsers.keys())}"
        raise ValueError(msg)

    return parsers[source]
