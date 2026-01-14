#!/usr/bin/env bash
#
# Test SIEM Anomaly Detector API
#
# Usage:
#   ./scripts/test_api.sh
#
# Requirements:
#   - API server running on http://localhost:8000
#   - curl and jq installed

set -euo pipefail

API_URL="${API_URL:-http://localhost:8000}"

echo "=================================================="
echo "SIEM Anomaly Detector API Testing"
echo "=================================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
test_endpoint() {
    local name=$1
    local method=$2
    local endpoint=$3
    local data=$4

    echo -e "${YELLOW}▶ Testing:${NC} $name"
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "$API_URL$endpoint")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$API_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d "$data")
    fi

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)

    if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
        echo -e "${GREEN}✓ Success${NC} (HTTP $http_code)"
        echo "$body" | python3 -m json.tool | head -30
    else
        echo -e "${RED}✗ Failed${NC} (HTTP $http_code)"
        echo "$body"
        return 1
    fi
    echo ""
}

# ============================================================================
# 1. Health Check
# ============================================================================
echo "1. Health Check"
echo "----------------"
test_endpoint "Health Check" "GET" "/api/v1/health" ""

# ============================================================================
# 2. Statistics
# ============================================================================
echo "2. System Statistics"
echo "---------------------"
test_endpoint "Stats" "GET" "/api/v1/stats" ""

# ============================================================================
# 3. Analyze Single Log - Normal
# ============================================================================
echo "3. Analyze Normal Log"
echo "----------------------"
test_endpoint "Normal SSH Login" "POST" "/api/v1/logs/analyze" '{
  "log_line": "Jan 13 14:30:00 server sshd[5678]: Accepted publickey for john.doe from 192.168.1.1 port 45123 ssh2",
  "source": "auth",
  "metadata": {
    "source_ip": "192.168.1.1",
    "username": "john.doe",
    "status_code": 200
  }
}'

# ============================================================================
# 4. Analyze Single Log - Brute Force Attack
# ============================================================================
echo "4. Analyze Brute Force Attack"
echo "-------------------------------"
test_endpoint "Brute Force Attack" "POST" "/api/v1/logs/analyze" '{
  "log_line": "Jan 13 03:45:12 server sshd[1234]: Failed password for admin from 45.142.212.61 port 52341 ssh2",
  "source": "auth",
  "metadata": {
    "source_ip": "45.142.212.61",
    "username": "admin",
    "status_code": 401
  }
}'

# ============================================================================
# 5. Analyze Single Log - SQL Injection
# ============================================================================
echo "5. Analyze SQL Injection Attempt"
echo "----------------------------------"
test_endpoint "SQL Injection" "POST" "/api/v1/logs/analyze" '{
  "log_line": "GET /api/users?id=1 OR 1=1-- HTTP/1.1",
  "source": "nginx",
  "metadata": {
    "source_ip": "203.0.113.45",
    "endpoint": "/api/users",
    "status_code": 500
  }
}'

# ============================================================================
# 6. Analyze Single Log - DDoS
# ============================================================================
echo "6. Analyze DDoS Attack"
echo "-----------------------"
test_endpoint "DDoS Attack" "POST" "/api/v1/logs/analyze" '{
  "log_line": "GET / HTTP/1.1 from 198.51.100.23",
  "source": "nginx",
  "metadata": {
    "source_ip": "198.51.100.23",
    "endpoint": "/",
    "status_code": 200
  }
}'

# ============================================================================
# 7. Batch Analysis
# ============================================================================
echo "7. Batch Analysis (3 logs)"
echo "---------------------------"
test_endpoint "Batch Analysis" "POST" "/api/v1/logs/batch" '{
  "logs": [
    {
      "log_line": "Jan 13 14:30:00 server sshd[5678]: Accepted publickey for john.doe from 192.168.1.1",
      "source": "auth",
      "metadata": {"source_ip": "192.168.1.1", "username": "john.doe", "status_code": 200}
    },
    {
      "log_line": "Jan 13 03:45:12 server sshd[1234]: Failed password for admin from 45.142.212.61",
      "source": "auth",
      "metadata": {"source_ip": "45.142.212.61", "username": "admin", "status_code": 401}
    },
    {
      "log_line": "GET /api/users?id=1 OR 1=1-- HTTP/1.1",
      "source": "nginx",
      "metadata": {"source_ip": "203.0.113.45", "endpoint": "/api/users", "status_code": 500}
    }
  ]
}'

# ============================================================================
# 8. Anomalies List
# ============================================================================
echo "8. List Anomalies"
echo "------------------"
test_endpoint "Get Anomalies" "GET" "/api/v1/anomalies?limit=5&min_risk_score=0.5" ""

echo ""
echo "=================================================="
echo -e "${GREEN}All tests completed!${NC}"
echo "=================================================="
