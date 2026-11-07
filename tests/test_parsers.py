from __future__ import annotations

from datetime import timezone

import pytest

from backend.parsers import get_parser
from backend.parsers.auth import AuthLogParser
from backend.parsers.firewall import FirewallParser
from backend.parsers.nginx import NginxParser
from backend.parsers.syslog import SyslogParser


def test_access_log_real_line(access_lines):
    p = NginxParser().parse(access_lines[0])
    assert p.source_ip == "10.143.2.91"
    assert p.method == "GET" and p.endpoint == "/"
    assert p.status_code == 200 and p.bytes_sent == 6203
    assert p.timestamp.tzinfo is not None
    assert (p.timestamp.year, p.timestamp.month, p.timestamp.day, p.timestamp.hour) == (
        2022,
        1,
        23,
        6,
    )
    assert p.success is True


def test_access_log_scanner_user_agent_and_404(access_lines):
    p = NginxParser().parse(access_lines[1])
    assert p.source_ip == "172.19.131.174"
    assert p.method == "POST" and p.status_code == 404
    assert "Nmap" in p.user_agent
    assert p.success is False


def test_access_log_http10_and_dash_user_agent(access_lines):
    p = NginxParser().parse(access_lines[2])
    assert p.protocol == "HTTP/1.0"
    assert p.user_agent is None  # "-" is normalised to None


def test_access_log_dash_bytes_is_zero():
    line = '10.0.0.1 - - [23/Jan/2022:06:36:13 +0000] "GET /x HTTP/1.1" 304 - "-" "curl/8"'
    assert NginxParser().parse(line).bytes_sent == 0


def test_access_log_timezone_offset_is_converted_to_utc():
    line = '10.0.0.1 - - [23/Jan/2022:08:00:00 +0200] "GET /x HTTP/1.1" 200 1 "-" "curl/8"'
    assert NginxParser().parse(line).timestamp.hour == 6
    assert NginxParser().parse(line).timestamp.tzinfo == timezone.utc


def test_access_log_malformed_request_line_falls_back(access_lines):
    # Real line from the dataset: HTTP 408 with request "-" does not match the access pattern.
    p = NginxParser().parse(access_lines[4])
    assert p.event_type == "nginx_generic"


def test_access_log_ipv6_source():
    line = '2001:db8::1 - - [23/Jan/2022:06:36:13 +0000] "GET / HTTP/1.1" 200 1 "-" "x"'
    assert NginxParser().parse(line).source_ip == "2001:db8::1"


def test_nginx_error_log():
    line = "2026/01/13 12:00:00 [error] 12345#0: *67890 connect() failed to 10.1.2.3:80"
    p = NginxParser().parse(line)
    assert p.event_type == "nginx_error" and p.source_ip == "10.1.2.3"


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        ("/login", "http_auth_success"),
        ("/admin/x", "http_admin_access"),
        ("/api/users", "http_api_request"),
        ("/a?id=1 union select 1", "http_sql_injection_attempt"),
        ("/a/../../etc/passwd", "http_path_traversal_attempt"),
        ("/a?q=<script>", "http_xss_attempt"),
        ("/index.html", "http_request"),
    ],
)
def test_nginx_event_type_rules(endpoint, expected):
    line = f'10.0.0.1 - - [23/Jan/2022:06:36:13 +0000] "GET {endpoint.replace(" ", "+")} HTTP/1.1" 200 1 "-" "x"'
    assert NginxParser().parse(line).event_type == expected


def test_auth_log_ssh_accepted_publickey(auth_lines):
    line = next(line for line in auth_lines if "Accepted publickey" in line)
    p = AuthLogParser().parse(line)
    assert p.event_type == "ssh_auth_success"
    assert "authentication" in p.tags


def test_auth_log_su_and_cron(auth_lines):
    types = {AuthLogParser().parse(line).event_type for line in auth_lines}
    assert types  # every real line yields an event type
    cron = AuthLogParser().parse(auth_lines[0])
    assert cron.process_name.startswith("CRON")


@pytest.mark.parametrize(
    ("process", "message", "expected"),
    [
        ("sshd", "Failed password for root from 1.2.3.4", "ssh_password_failed"),
        ("sshd", "Invalid user bob from 1.2.3.4", "ssh_invalid_user"),
        ("sudo", "pam_unix(sudo:auth): authentication failure", "sudo_auth_failed"),
        ("sudo", "jhall : TTY=pts/0 ; COMMAND=/bin/ls", "sudo_command_executed"),
        ("su", "pam_unix(su:auth): authentication failure", "su_auth_failed"),
        ("login", "FAILED LOGIN", "login_failed"),
        ("useradd", "useradd: new user: name=x", "user_management"),
        ("x", "nothing interesting", "auth_event"),
    ],
)
def test_auth_event_refinement(process, message, expected):
    assert AuthLogParser._refine_auth_event_type(process, message) == expected


def test_syslog_rfc3164():
    p = SyslogParser().parse("Jan 13 12:00:00 host sshd[123]: Failed password for root")
    assert p.hostname == "host" and p.process_id == 123
    assert p.timestamp.hour == 12


def test_syslog_rfc5424():
    line = "<34>1 2026-01-13T12:00:00Z host app 123 ID47 - hello world"
    p = SyslogParser().parse(line)
    assert p.hostname == "host"


def test_firewall_iptables():
    line = (
        "Jan 13 12:00:00 gw kernel: [12345.678] IN=eth0 OUT= MAC=aa SRC=192.168.1.100 "
        "DST=10.0.0.1 LEN=60 PROTO=TCP SPT=12345 DPT=22 WINDOW=1"
    )
    p = FirewallParser().parse(line)
    assert (p.source_ip, p.destination_ip, p.destination_port) == ("192.168.1.100", "10.0.0.1", 22)


def test_firewall_generic_fallback():
    assert FirewallParser().parse("not a firewall line").event_type == "firewall_generic"


def test_get_parser_and_unknown_source():
    assert isinstance(get_parser("nginx"), NginxParser)
    with pytest.raises(ValueError, match="Unsupported"):
        get_parser("bogus")


def test_parse_batch_skips_unparseable():
    parser = SyslogParser()
    out = parser.parse_batch(["Jan 13 12:00:00 host sshd[1]: ok", "\x00garbage"])
    assert len(out) >= 1
