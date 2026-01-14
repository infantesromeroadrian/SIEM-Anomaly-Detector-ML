"""
Authentication log parser (/var/log/auth.log).

Parses Linux authentication logs (SSH, sudo, su, PAM, etc.).
"""

from __future__ import annotations

from backend.parsers.syslog import SyslogParser
from backend.parsers.base import ParsedLog


class AuthLogParser(SyslogParser):
    """
    Parser for /var/log/auth.log (authentication events).

    Extends SyslogParser with auth-specific event detection.
    """

    def parse(self, log_line: str) -> ParsedLog:
        """
        Parse auth log line.

        Args:
            log_line: Raw auth.log line

        Returns:
            ParsedLog object with enhanced auth event detection
        """
        # Use parent syslog parser
        parsed = super().parse(log_line)

        # Enhance event type detection for auth-specific events
        parsed.event_type = self._refine_auth_event_type(
            parsed.process_name or "", parsed.message or ""
        )

        # Tag as authentication event
        if "auth" not in parsed.tags:
            parsed.tags.append("authentication")

        return parsed

    @staticmethod
    def _refine_auth_event_type(process: str, message: str) -> str:
        """Refine event type for authentication events."""
        process_lower = process.lower()
        message_lower = message.lower()

        # SSH authentication
        if "sshd" in process_lower:
            if "failed password" in message_lower:
                return "ssh_password_failed"
            if "authentication failure" in message_lower:
                return "ssh_auth_failure"
            if "accepted password" in message_lower or "accepted publickey" in message_lower:
                return "ssh_auth_success"
            if "invalid user" in message_lower:
                return "ssh_invalid_user"
            if "connection closed" in message_lower:
                return "ssh_disconnect"
            if "received disconnect" in message_lower:
                return "ssh_disconnect"
            if "pam" in message_lower and "authentication failure" in message_lower:
                return "ssh_pam_auth_failure"
            return "ssh_event"

        # Sudo events
        if "sudo" in process_lower:
            if "command" in message_lower:
                return "sudo_command_executed"
            if "incorrect password" in message_lower or "authentication failure" in message_lower:
                return "sudo_auth_failed"
            if "pam" in message_lower:
                return "sudo_pam_event"
            return "sudo_event"

        # Su (switch user) events
        if process in ("su", "su["):
            if "authentication failure" in message_lower or "incorrect password" in message_lower:
                return "su_auth_failed"
            if "session opened" in message_lower:
                return "su_session_opened"
            if "session closed" in message_lower:
                return "su_session_closed"
            return "su_event"

        # PAM (Pluggable Authentication Module) events
        if "pam" in process_lower or "pam_" in message_lower:
            if "authentication failure" in message_lower:
                return "pam_auth_failure"
            if "session opened" in message_lower:
                return "pam_session_opened"
            if "session closed" in message_lower:
                return "pam_session_closed"
            return "pam_event"

        # Login events
        if "login" in process_lower or "login" in message_lower:
            if "failed" in message_lower or "failure" in message_lower:
                return "login_failed"
            if "logged in" in message_lower or "session opened" in message_lower:
                return "login_success"
            return "login_event"

        # User management
        if any(cmd in message_lower for cmd in ["useradd", "userdel", "usermod", "groupadd"]):
            return "user_management"

        # Password changes
        if any(cmd in message_lower for cmd in ["passwd", "chpasswd", "password changed"]):
            return "password_change"

        # Account lockout
        if "locked" in message_lower or "account locked" in message_lower:
            return "account_locked"

        # Generic authentication event
        return "auth_event"
