# 🚀 SIEM Anomaly Detector - Quickstart Guide

**Get up and running in 5 minutes!**

---

## ⚡ TL;DR (Docker - Fastest)

```bash
# 1. Clone and enter directory
cd src/SIEM-Anomaly-Detector

# 2. Copy environment variables
cp .env.example .env

# 3. Start all services
docker-compose up -d

# 4. Check API is running
curl http://localhost:8000/api/v1/health

# 5. Open Swagger docs
open http://localhost:8000/docs
```

**Services available:**
- API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Grafana: http://localhost:3000 (admin/admin)
- Flower: http://localhost:5555 (Celery monitoring)

---

## 📋 Prerequisites

### Option 1: Docker (Recommended)
- Docker 20.10+
- Docker Compose 2.0+

### Option 2: Local Development
- Python 3.10+
- PostgreSQL 15+
- Redis 7+

---

## 🐳 Option 1: Docker Compose (Production-like)

### Step 1: Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit configuration (optional)
nano .env

# Key settings to review:
# - POSTGRES_PASSWORD (change in production!)
# - SECRET_KEY (change in production!)
# - ALERT_THRESHOLD_HIGH (default: 0.8)
# - MODEL_CONTAMINATION (default: 0.03 = 3% anomalies expected)
```

### Step 2: Build and Start

```bash
# Build images
docker-compose build

# Start all services in background
docker-compose up -d

# View logs
docker-compose logs -f api

# Check service status
docker-compose ps
```

### Step 3: Verify Installation

```bash
# Health check
curl http://localhost:8000/api/v1/health | jq

# Expected output:
# {
#   "status": "healthy",
#   "version": "1.0.0",
#   "uptime_seconds": 12.34,
#   ...
# }
```

### Step 4: Test Analysis

```bash
# Analyze a suspicious log
curl -X POST "http://localhost:8000/api/v1/logs/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "log_line": "Jan 13 03:45:12 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2",
    "source": "auth"
  }' | jq

# Expected output:
# {
#   "is_anomaly": true,
#   "risk_score": 0.87,
#   "risk_level": "high",
#   "reasons": [
#     "Login attempt at unusual hour (3 AM)",
#     "15 failed attempts in 1 minute (DDoS indicator)",
#     ...
#   ],
#   "recommended_action": "BLOCK_IP"
# }
```

---

## 💻 Option 2: Local Development

### Step 1: Install Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install package in editable mode
pip install -e ".[dev]"

# Verify installation
python -c "import backend; print(backend.__version__)"
```

### Step 2: Start External Services

```bash
# Start PostgreSQL (example with Docker)
docker run -d \
  --name siem-postgres \
  -e POSTGRES_PASSWORD=changeme \
  -e POSTGRES_USER=siem_user \
  -e POSTGRES_DB=siem_db \
  -p 5432:5432 \
  postgres:15

# Start Redis
docker run -d \
  --name siem-redis \
  -p 6379:6379 \
  redis:7-alpine
```

### Step 3: Configure Environment

```bash
# Copy .env template
cp .env.example .env

# Edit to use localhost services
nano .env

# Set:
# POSTGRES_HOST=localhost
# REDIS_HOST=localhost
```

### Step 4: Initialize Database

```bash
# Run migrations (if implemented)
# alembic upgrade head

# Or manually create tables
# python scripts/init_db.py
```

### Step 5: Train Initial Model

```bash
# Train model with sample logs
python scripts/train_initial_model.py

# Output:
# ✅ Dataset loaded: 10,000 samples
# ✅ Models trained: Isolation Forest, DBSCAN, GMM
# ✅ Model saved: models/ensemble_20260113_230512.joblib
```

### Step 6: Start API Server

```bash
# Development mode (auto-reload)
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Production mode (4 workers)
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers 4

# Access:
# - API: http://localhost:8000
# - Docs: http://localhost:8000/docs
# - Metrics: http://localhost:8000/metrics
```

---

## 🧪 Testing the API

### 1. Interactive API Docs

```
Open browser: http://localhost:8000/docs

Try the endpoints:
✅ GET /api/v1/health - Health check
✅ POST /api/v1/logs/analyze - Analyze single log
✅ GET /api/v1/anomalies - Get detected anomalies
✅ GET /api/v1/stats - System statistics
```

### 2. Command Line Examples

```bash
# Health check
curl http://localhost:8000/api/v1/health

# Analyze SSH failed login
curl -X POST "http://localhost:8000/api/v1/logs/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "log_line": "Jan 13 03:45:12 server sshd[1234]: Failed password for admin from 192.168.1.100",
    "source": "auth"
  }'

# Analyze Nginx access log
curl -X POST "http://localhost:8000/api/v1/logs/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "log_line": "192.168.1.100 - - [13/Jan/2026:03:45:12 +0000] \"GET /admin HTTP/1.1\" 404 162",
    "source": "nginx"
  }'

# Get anomalies from last 24 hours
curl "http://localhost:8000/api/v1/anomalies?limit=10&hours=24&min_risk_score=0.7"

# Get system statistics
curl http://localhost:8000/api/v1/stats
```

### 3. Python Client Example

```python
import requests

# Analyze log
response = requests.post(
    "http://localhost:8000/api/v1/logs/analyze",
    json={
        "log_line": "Jan 13 03:45:12 server sshd: Failed password for admin",
        "source": "auth"
    }
)

result = response.json()
print(f"Risk Score: {result['risk_score']}")
print(f"Is Anomaly: {result['is_anomaly']}")
print(f"Reasons: {result['reasons']}")
```

---

## 📊 Accessing Monitoring Dashboards

### Grafana (Visualization)

```
URL: http://localhost:3000
Username: admin
Password: admin (change on first login)

Pre-configured dashboards:
- SIEM Overview: Logs processed, anomalies detected
- ML Models: Model performance metrics
- System Health: API latency, error rates
```

### Flower (Celery Tasks)

```
URL: http://localhost:5555

Monitor:
- Active tasks
- Task history
- Worker status
- Task execution times
```

### Prometheus (Metrics)

```
URL: http://localhost:9090

Example queries:
- siem_logs_analyzed_total
- siem_anomalies_detected_total
- siem_request_duration_seconds
```

---

## 🛑 Stopping Services

### Docker Compose

```bash
# Stop all services
docker-compose stop

# Stop and remove containers
docker-compose down

# Stop and remove volumes (⚠️ deletes data)
docker-compose down -v
```

### Local Development

```bash
# Stop API server
Ctrl+C

# Stop external services
docker stop siem-postgres siem-redis
```

---

## 🔧 Troubleshooting

### Issue: "Port already in use"

```bash
# Find process using port 8000
lsof -ti:8000

# Kill process
kill -9 $(lsof -ti:8000)

# Or change port in .env
API_PORT=8001
```

### Issue: "Database connection failed"

```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Check connectivity
pg_isready -h localhost -p 5432

# View logs
docker logs siem-postgres
```

### Issue: "Models not loaded"

```bash
# Ensure models directory exists
mkdir -p models

# Train initial model
python scripts/train_initial_model.py

# Check model files
ls -lh models/
```

### Issue: "Import errors"

```bash
# Reinstall dependencies
pip install -e ".[dev]" --force-reinstall

# Verify installation
pip list | grep siem
```

---

## 📚 Next Steps

1. **Configure Alerts**: Set up Slack/Email notifications in `.env`
2. **Ingest Real Logs**: Configure file watchers or syslog listeners
3. **Tune Models**: Adjust `MODEL_CONTAMINATION` based on your environment
4. **Set up Monitoring**: Import Grafana dashboards from `docs/`
5. **Read Full Docs**: See `README.md` for comprehensive documentation

---

## 🤝 Need Help?

- **Documentation**: See `README.md` and `docs/`
- **Issues**: Check existing issues or create new one
- **API Reference**: http://localhost:8000/docs (interactive Swagger UI)

---

**🎉 Congratulations!** You now have a working SIEM with ML-based anomaly detection.

Start sending logs and watch it detect suspicious behavior in real-time! 🛡️
