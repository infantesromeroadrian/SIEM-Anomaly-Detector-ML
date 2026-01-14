#!/usr/bin/env python3
"""
Send test logs to the API to populate the interface.

This script simulates real log ingestion by sending logs via HTTP POST
to the /api/v1/logs/analyze endpoint. The analyzed logs are stored in
PostgreSQL and displayed in the frontend interface.
"""

import time
from datetime import datetime
import requests
import random

API_URL = "http://localhost:8000/api/v1/logs/analyze"

# Test log samples (realistic security logs)
TEST_LOGS = [
    # Normal logs
    {
        "log_line": f"Jan 14 {datetime.now().hour:02d}:30:15 server sshd[1234]: Accepted password for john from 192.168.1.50 port 52341 ssh2",
        "source": "auth",
        "description": "✅ Normal SSH login",
    },
    {
        "log_line": f'Jan 14 {datetime.now().hour:02d}:31:20 web nginx: 192.168.1.100 - - [14/Jan/2026:10:31:20 +0000] "GET /api/users HTTP/1.1" 200 2048',
        "source": "nginx",
        "description": "✅ Normal web request",
    },
    {
        "log_line": f"Jan 14 {datetime.now().hour:02d}:32:10 app kernel: [12345.678901] eth0: link up",
        "source": "syslog",
        "description": "✅ Normal system event",
    },
    # Anomalous logs (attacks)
    {
        "log_line": f"Jan 14 03:45:12 server sshd[5678]: Failed password for admin from 185.234.219.45 port 60001 ssh2",
        "source": "auth",
        "description": "🔴 Brute force attempt (3 AM, foreign IP)",
    },
    {
        "log_line": f"Jan 14 03:45:13 server sshd[5679]: Failed password for root from 185.234.219.45 port 60002 ssh2",
        "source": "auth",
        "description": "🔴 Brute force attempt (targeting root)",
    },
    {
        "log_line": f'Jan 14 22:15:30 web nginx: 45.132.246.198 - - [14/Jan/2026:22:15:30 +0000] "GET /admin\' OR 1=1-- HTTP/1.1" 403 156',
        "source": "nginx",
        "description": "🔴 SQL Injection attempt",
    },
    {
        "log_line": f"Jan 14 04:10:45 server sudo: john : command not allowed ; USER=john ; COMMAND=/bin/bash /etc/shadow",
        "source": "auth",
        "description": "🔴 Privilege escalation attempt",
    },
    {
        "log_line": f"Jan 14 02:20:15 server systemd[1]: Started cryptominer service",
        "source": "syslog",
        "description": "🔴 Cryptomining malware",
    },
]


def send_log(log_data: dict) -> dict:
    """
    Send a single log to the API for analysis.

    Args:
        log_data: Dictionary with log_line, source, and description

    Returns:
        API response (analysis result)
    """
    payload = {
        "log_line": log_data["log_line"],
        "source": log_data["source"],
    }

    try:
        response = requests.post(API_URL, json=payload, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        print("❌ ERROR: Cannot connect to API. Make sure the server is running:")
        print("   uvicorn backend.main:app --reload")
        exit(1)
    except requests.exceptions.Timeout:
        print(f"⚠️  TIMEOUT: Log analysis took too long")
        return {"error": "timeout"}
    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP ERROR: {e}")
        print(f"   Response: {response.text}")
        return {"error": str(e)}
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return {"error": str(e)}


def main():
    """Send test logs to populate the interface."""
    print("=" * 80)
    print("📤 SENDING TEST LOGS TO API")
    print("=" * 80)
    print(f"\n🎯 Target API: {API_URL}")
    print(f"📊 Sending {len(TEST_LOGS)} test logs...\n")

    # Health check first
    try:
        health_response = requests.get("http://localhost:8000/api/v1/health", timeout=5)
        if health_response.status_code == 200:
            health = health_response.json()
            print(f"✅ API is healthy (version: {health.get('version', 'unknown')})\n")
        else:
            print("⚠️  API health check failed, but continuing...\n")
    except Exception:
        print("❌ ERROR: API is not responding. Start it with:")
        print("   uvicorn backend.main:app --reload")
        print()
        exit(1)

    results = {
        "normal": 0,
        "anomalies": 0,
        "errors": 0,
    }

    for i, log_data in enumerate(TEST_LOGS, 1):
        print(f"{'─' * 80}")
        print(f"[{i}/{len(TEST_LOGS)}] {log_data['description']}")
        print(f"{'─' * 80}")
        print(f"📝 Log: {log_data['log_line'][:100]}...")

        # Send to API
        result = send_log(log_data)

        if "error" in result:
            print(f"❌ Failed to analyze\n")
            results["errors"] += 1
            continue

        # Extract analysis
        is_anomaly = result.get("is_anomaly", False)
        risk_score = result.get("risk_score", 0.0)
        risk_level = result.get("risk_level", "unknown")
        reasons = result.get("reasons", [])
        action = result.get("recommended_action", "NO_ACTION")

        # Display result
        if is_anomaly:
            emoji = "🔴" if risk_score >= 0.8 else "🟠" if risk_score >= 0.6 else "🟡"
            print(f"\n{emoji} ANOMALY DETECTED!")
            results["anomalies"] += 1
        else:
            emoji = "🟢"
            print(f"\n{emoji} NORMAL")
            results["normal"] += 1

        print(f"   • Risk Score: {risk_score:.3f}")
        print(f"   • Risk Level: {risk_level}")
        print(f"   • Action: {action}")

        if reasons:
            print(f"   • Reasons:")
            for reason in reasons[:3]:  # Show top 3
                print(f"      - {reason}")

        print()

        # Small delay to avoid overwhelming the API
        time.sleep(0.5)

    # Summary
    print("=" * 80)
    print("📊 SUMMARY")
    print("=" * 80)
    print(f"✅ Normal logs:      {results['normal']}")
    print(f"🔴 Anomalies found:  {results['anomalies']}")
    print(f"❌ Errors:           {results['errors']}")
    print(f"\n📈 Anomaly rate:     {results['anomalies'] / len(TEST_LOGS):.1%}")
    print("=" * 80)
    print("\n💡 Next steps:")
    print("   1. Open frontend: http://localhost:5173")
    print("   2. Check dashboard to see the logs analyzed")
    print("   3. View anomaly list to see detected threats")
    print("   4. The data is now in PostgreSQL and visible in the UI!")
    print()
    print("🔄 Run this script multiple times to generate more data")
    print("=" * 80)


if __name__ == "__main__":
    main()
