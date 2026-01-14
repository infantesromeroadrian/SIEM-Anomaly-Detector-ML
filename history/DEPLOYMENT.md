# SIEM Anomaly Detector - Deployment Guide

**Status**: ✅ Production-Ready Full Stack  
**Version**: 1.0.0  
**Date**: 2026-01-14

---

## 🚀 Quick Start (Docker Compose)

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum
- 10GB disk space

### One-Command Deployment

```bash
cd /path/to/SIEM-Anomaly-Detector
docker-compose -f docker-compose.simple.yml up -d
```

**Services started**:
- PostgreSQL (port 5432) - Database
- Redis (port 6379) - Cache
- FastAPI (port 8000) - Backend API
- React (port 3000) - Frontend

### Access the Application

```bash
# Frontend (React Dashboard)
http://localhost:3000

# Backend API (Swagger UI)
http://localhost:8000/docs

# Health Check
curl http://localhost:8000/api/v1/health
```

---

## 📦 What's Included

### Backend Services

**FastAPI API** (`http://localhost:8000`):
- ✅ ML Ensemble (Isolation Forest + DBSCAN + GMM)
- ✅ Log Parsers (syslog, nginx, auth, firewall)
- ✅ PostgreSQL integration (4 tables)
- ✅ Redis cache (feature aggregation)
- ✅ Prometheus metrics (`/metrics`)
- ✅ Swagger UI (`/docs`)

**PostgreSQL**:
- Tables: `anomalies`, `logs`, `feedback`, `alerts`
- TimescaleDB extension (time-series optimization)
- Persistent volume

**Redis**:
- Feature aggregation cache
- Session management
- Real-time counters
- Persistent append-only file

### Frontend

**React Dashboard** (`http://localhost:3000`):
- ✅ Real-time anomaly detection stats
- ✅ Anomaly list with filters
- ✅ Risk score visualization (Recharts)
- ✅ Modal details view
- ✅ Auto-refresh every 30-60s
- ✅ Responsive design

---

## 🔧 Configuration

### Environment Variables

Edit `docker-compose.simple.yml` or create `.env` file:

```bash
# Database
POSTGRES_DB=siem_db
POSTGRES_USER=siem_user
POSTGRES_PASSWORD=changeme  # ⚠️ CHANGE IN PRODUCTION

# Redis
REDIS_PASSWORD=  # Optional

# ML Model
MODEL_PATH=./models/ensemble_20260113_233849.joblib
ENSEMBLE_WEIGHTS=0.5,0.3,0.2

# Alert Thresholds
ALERT_THRESHOLD_LOW=0.4
ALERT_THRESHOLD_MEDIUM=0.6
ALERT_THRESHOLD_HIGH=0.8
```

---

## 🛠️ Management Commands

### Start Services

```bash
# Start all services
docker-compose -f docker-compose.simple.yml up -d

# Start specific service
docker-compose -f docker-compose.simple.yml up -d api

# View logs
docker-compose -f docker-compose.simple.yml logs -f api
docker-compose -f docker-compose.simple.yml logs -f frontend
```

### Stop Services

```bash
# Stop all
docker-compose -f docker-compose.simple.yml down

# Stop and remove volumes (⚠️ deletes data)
docker-compose -f docker-compose.simple.yml down -v
```

### Restart Services

```bash
# Restart all
docker-compose -f docker-compose.simple.yml restart

# Restart specific service
docker-compose -f docker-compose.simple.yml restart api
```

### View Status

```bash
docker-compose -f docker-compose.simple.yml ps
docker-compose -f docker-compose.simple.yml logs --tail=50 api
```

---

## 🧪 Testing

### Test API

```bash
# Health check
curl http://localhost:8000/api/v1/health

# Get stats
curl http://localhost:8000/api/v1/stats

# Analyze log
curl -X POST http://localhost:8000/api/v1/logs/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "log_line": "Jan 14 03:45:12 server sshd[1234]: Failed password for admin from 45.142.212.61",
    "source": "auth",
    "metadata": {
      "source_ip": "45.142.212.61",
      "username": "admin",
      "status_code": 401
    }
  }'
```

### Test Frontend

```bash
# Open browser
open http://localhost:3000

# Or with curl
curl http://localhost:3000
```

---

## 📊 Database Access

### PostgreSQL

```bash
# Connect to PostgreSQL
docker exec -it siem-postgres psql -U siem_user -d siem_db

# Query anomalies
SELECT id, risk_score, risk_level, source_ip, event_type, created_at
FROM anomalies
ORDER BY created_at DESC
LIMIT 10;

# Count anomalies by risk level
SELECT risk_level, COUNT(*) 
FROM anomalies 
GROUP BY risk_level;
```

### Redis

```bash
# Connect to Redis
docker exec -it siem-redis redis-cli

# Check keys
KEYS *

# Get unique IPs
SMEMBERS unique_ips

# Get login attempts for IP
ZRANGE login_attempts:192.168.1.100 0 -1 WITHSCORES
```

---

## 🔒 Security Considerations

### Production Checklist

- [ ] Change default PostgreSQL password
- [ ] Set Redis password
- [ ] Enable HTTPS (add Nginx reverse proxy)
- [ ] Configure firewall rules
- [ ] Set up log rotation
- [ ] Enable database backups
- [ ] Configure monitoring (Prometheus + Grafana)
- [ ] Set resource limits (CPU, memory)
- [ ] Use Docker secrets instead of environment variables
- [ ] Regular security updates

### Recommended: Add Nginx Reverse Proxy

```yaml
# Add to docker-compose.simple.yml
nginx:
  image: nginx:alpine
  ports:
    - "80:80"
    - "443:443"
  volumes:
    - ./nginx.conf:/etc/nginx/nginx.conf:ro
    - ./certs:/etc/nginx/certs:ro
  depends_on:
    - api
    - frontend
  networks:
    - siem-network
```

---

## 📈 Monitoring

### Prometheus Metrics

```bash
# Scrape metrics
curl http://localhost:8000/metrics

# Sample metrics:
# - siem_requests_total
# - siem_logs_analyzed_total
# - siem_anomalies_detected_total
# - siem_request_duration_seconds
# - siem_analysis_duration_seconds
```

### Health Checks

```bash
# API health
curl http://localhost:8000/api/v1/health

# Readiness probe (K8s)
curl http://localhost:8000/api/v1/ready

# Liveness probe (K8s)
curl http://localhost:8000/api/v1/live
```

---

## 🐛 Troubleshooting

### API won't start

```bash
# Check logs
docker-compose -f docker-compose.simple.yml logs api

# Common issues:
# 1. PostgreSQL not ready → Wait 30s, check: docker-compose ps
# 2. Model file missing → Check: ls -la models/
# 3. Port 8000 in use → Change port in docker-compose.yml
```

### Database connection errors

```bash
# Check PostgreSQL health
docker-compose -f docker-compose.simple.yml ps postgres

# Test connection
docker exec -it siem-postgres pg_isready -U siem_user

# Reset database (⚠️ deletes data)
docker-compose -f docker-compose.simple.yml down -v
docker-compose -f docker-compose.simple.yml up -d postgres
```

### Redis connection errors

```bash
# Check Redis health
docker exec -it siem-redis redis-cli ping

# Restart Redis
docker-compose -f docker-compose.simple.yml restart redis
```

### Frontend not loading

```bash
# Check frontend logs
docker-compose -f docker-compose.simple.yml logs frontend

# Common issues:
# 1. npm install failed → Restart: docker-compose restart frontend
# 2. API not accessible → Check API health first
# 3. Port 3000 in use → Change port in docker-compose.yml
```

---

## 🔄 Backup & Restore

### Backup PostgreSQL

```bash
# Backup database
docker exec siem-postgres pg_dump -U siem_user siem_db > backup_$(date +%Y%m%d).sql

# Automated daily backup
echo "0 2 * * * docker exec siem-postgres pg_dump -U siem_user siem_db > /backups/siem_backup_\$(date +\%Y\%m\%d).sql" | crontab -
```

### Restore PostgreSQL

```bash
# Restore from backup
cat backup_20260114.sql | docker exec -i siem-postgres psql -U siem_user -d siem_db
```

---

## 📚 Additional Resources

- **API Documentation**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI Spec**: http://localhost:8000/openapi.json
- **README**: `README.md`
- **ML Architecture**: `docs/ML_ARCHITECTURE.md`

---

## 🎯 Performance Tuning

### Resource Limits (Production)

Edit `docker-compose.simple.yml`:

```yaml
services:
  api:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G
```

### PostgreSQL Tuning

```sql
-- Connect to PostgreSQL
docker exec -it siem-postgres psql -U siem_user -d siem_db

-- Create indexes for performance
CREATE INDEX CONCURRENTLY idx_anomalies_created_risk 
  ON anomalies(created_at, risk_score);

-- Enable TimescaleDB (if not already)
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Convert anomalies table to hypertable
SELECT create_hypertable('anomalies', 'created_at', if_not_exists => TRUE);
```

---

**Version**: 1.0.0  
**Maintainer**: Adrian Infantes Romero  
**Status**: ✅ Production-Ready
