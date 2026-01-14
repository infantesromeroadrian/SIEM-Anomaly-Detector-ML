# 🛡️ SIEM Anomaly Detector

**Real-time Security Information and Event Management with ML-based Anomaly Detection**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104%2B-green)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📋 Tabla de Contenidos

- [Descripción](#-descripción)
- [Características](#-características)
- [Arquitectura](#-arquitectura)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [API Reference](#-api-reference)
- [ML Models](#-ml-models)
- [Despliegue](#-despliegue)
- [Roadmap](#-roadmap)

---

## 🎯 Descripción

**SIEM Anomaly Detector** es un sistema de detección de anomalías en logs de seguridad que utiliza **Machine Learning no supervisado** para identificar comportamientos sospechosos sin necesidad de reglas predefinidas.

### ¿Por qué este proyecto?

Los SIEM tradicionales dependen de **reglas estáticas** que:
- ❌ No detectan ataques **0-day** (nunca vistos)
- ❌ Generan **falsos positivos** excesivos
- ❌ Requieren **actualización manual constante**

Este SIEM usa **clustering ML** para:
- ✅ Detectar anomalías **sin ejemplos previos**
- ✅ Adaptarse automáticamente a **nuevos patrones**
- ✅ Proporcionar **scores de riesgo interpretables**

---

## 🚀 Características

### Core Features

- 🧠 **Ensemble ML**: Isolation Forest + DBSCAN + GMM
- 📊 **Multi-parser**: Syslog, Nginx, Auth logs, Firewall
- ⚡ **Real-time**: Análisis de logs en <100ms
- 🔄 **Online Learning**: Re-entrenamiento automático con feedback
- 📈 **Dashboard**: Visualización de anomalías en tiempo real
- 🐳 **Production-ready**: Docker + Kubernetes manifests

### ML Capabilities

| Algoritmo | Propósito | Ventaja |
|-----------|-----------|---------|
| **Isolation Forest** | Detección rápida de outliers | O(n), no requiere escalado |
| **DBSCAN** | Clusters de forma irregular | Detecta patrones de ataque complejos |
| **GMM** | Modelado probabilístico | Scores de confianza interpretables |

### Supported Log Types

- ✅ **Syslog** (RFC 3164/5424)
- ✅ **Nginx Access/Error logs**
- ✅ **SSH Auth logs** (/var/log/auth.log)
- ✅ **Firewall logs** (iptables, pfSense)
- 🚧 **Windows Event Logs** (próximamente)
- 🚧 **Custom JSON logs** (próximamente)

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                      SIEM ANOMALY DETECTOR                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [Log Sources]                                                  │
│      ├─ Syslog (UDP 514)                                        │
│      ├─ File watchers                                           │
│      └─ API ingestion                                           │
│           ↓                                                     │
│  [Parsers Layer]                                                │
│      ├─ SyslogParser                                            │
│      ├─ NginxParser                                             │
│      └─ AuthParser                                              │
│           ↓                                                     │
│  [Feature Engineering]                                          │
│      • login_attempts_per_minute                                │
│      • unique_ips_last_hour                                     │
│      • failed_auth_rate                                         │
│      • bytes_transferred                                        │
│      • geographic_distance                                      │
│      • time_since_last_activity                                 │
│           ↓                                                     │
│  [ML Ensemble]                                                  │
│      ├─ Isolation Forest  (score_1)                             │
│      ├─ DBSCAN           (score_2)                             │
│      └─ GMM              (score_3)                             │
│           ↓                                                     │
│  [Aggregation]                                                  │
│      weighted_score = 0.5*score_1 + 0.3*score_2 + 0.2*score_3  │
│           ↓                                                     │
│  [Decision Layer]                                               │
│      • risk_score > 0.8 → Alert                                 │
│      • risk_score > 0.6 → Monitor                               │
│      • risk_score < 0.6 → Normal                                │
│           ↓                                                     │
│  [Storage & Actions]                                            │
│      ├─ PostgreSQL (anomalías históricas)                       │
│      ├─ Redis (cache, rate limiting)                            │
│      └─ Webhook alerts (Slack, email, PagerDuty)               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Tech Stack

- **Backend**: FastAPI (async Python)
- **ML**: Scikit-learn, NumPy, Pandas
- **Database**: PostgreSQL 15 + TimescaleDB (time-series)
- **Cache**: Redis 7
- **Containers**: Docker + Docker Compose
- **Orchestration**: Kubernetes (optional)
- **Monitoring**: Prometheus + Grafana
- **Testing**: Pytest + Hypothesis

---

## 📦 Instalación

### Prerrequisitos

- Python 3.10+
- Docker & Docker Compose (para despliegue)
- PostgreSQL 15+ (opcional, se puede usar Docker)
- Redis 7+ (opcional, se puede usar Docker)

### Opción 1: Desarrollo Local

```bash
# Clonar repositorio
git clone https://github.com/tu-usuario/SIEM-Anomaly-Detector.git
cd SIEM-Anomaly-Detector

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -e ".[dev]"

# Configurar variables de entorno
cp .env.example .env
nano .env  # Editar según tu configuración

# Entrenar modelo inicial (usa logs de ejemplo)
python scripts/train_initial_model.py

# Iniciar servidor de desarrollo
uvicorn backend.main:app --reload --port 8000
```

### Opción 2: Docker Compose (Recomendado)

```bash
# Clonar y configurar
git clone https://github.com/tu-usuario/SIEM-Anomaly-Detector.git
cd SIEM-Anomaly-Detector
cp .env.example .env

# Construir y levantar todos los servicios
docker-compose up -d

# Verificar logs
docker-compose logs -f api

# Entrenar modelo inicial
docker-compose exec api python scripts/train_initial_model.py
```

**Servicios disponibles:**
- API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Grafana: http://localhost:3000 (admin/admin)
- Redis Commander: http://localhost:8081

---

## 🎮 Uso

### 1. Analizar un Log Individual

```bash
curl -X POST "http://localhost:8000/api/v1/logs/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "log_line": "Jan 13 03:45:12 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2",
    "source": "auth.log"
  }'
```

**Respuesta:**

```json
{
  "is_anomaly": true,
  "risk_score": 0.87,
  "confidence": "high",
  "features": {
    "login_attempts_last_minute": 15,
    "unique_ips_last_hour": 1,
    "failed_auth_rate": 1.0,
    "hour_of_day": 3,
    "is_known_ip": false
  },
  "reasons": [
    "Login attempt at unusual hour (3 AM)",
    "15 failed attempts in 1 minute (DDoS indicator)",
    "Unknown IP address (not in whitelist)",
    "Username 'admin' commonly targeted"
  ],
  "recommended_action": "BLOCK_IP",
  "similar_anomalies": 23
}
```

### 2. Obtener Top Anomalías

```bash
curl "http://localhost:8000/api/v1/anomalies?limit=10&hours=24"
```

### 3. Estadísticas del Sistema

```bash
curl "http://localhost:8000/api/v1/stats"
```

**Respuesta:**

```json
{
  "logs_analyzed_24h": 1245678,
  "anomalies_detected_24h": 342,
  "anomaly_rate": 0.027,
  "model_version": "v1.2.3",
  "last_retrain": "2026-01-13T22:15:30Z",
  "models": {
    "isolation_forest": {
      "contamination": 0.03,
      "n_estimators": 100,
      "accuracy": 0.94
    },
    "dbscan": {
      "eps": 1.5,
      "min_samples": 50,
      "n_clusters": 7
    },
    "gmm": {
      "n_components": 3,
      "bic": 12345.67
    }
  }
}
```

### 4. Re-entrenar Modelo con Feedback

```bash
curl -X POST "http://localhost:8000/api/v1/model/retrain" \
  -H "Content-Type: application/json" \
  -d '{
    "feedback": [
      {"log_id": "abc123", "is_true_positive": true},
      {"log_id": "def456", "is_true_positive": false}
    ]
  }'
```

---

## 📚 API Reference

### Endpoints

| Method | Endpoint | Descripción |
|--------|----------|-------------|
| `POST` | `/api/v1/logs/analyze` | Analizar un log individual |
| `POST` | `/api/v1/logs/batch` | Analizar múltiples logs |
| `GET` | `/api/v1/anomalies` | Obtener anomalías detectadas |
| `GET` | `/api/v1/anomalies/{id}` | Detalle de una anomalía |
| `GET` | `/api/v1/stats` | Estadísticas del sistema |
| `POST` | `/api/v1/model/retrain` | Re-entrenar con feedback |
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/metrics` | Métricas Prometheus |

**Documentación completa**: http://localhost:8000/docs (OpenAPI/Swagger)

---

## 🧠 ML Models

### Ensemble Strategy

El sistema usa un **ensemble ponderado** de 3 algoritmos:

```python
final_score = (
    0.5 * isolation_forest_score +
    0.3 * dbscan_score +
    0.2 * gmm_score
)
```

**Justificación de pesos:**
- **Isolation Forest (50%)**: Mejor para detección rápida de outliers extremos
- **DBSCAN (30%)**: Captura patrones de ataque coordinados (DDoS, port scans)
- **GMM (20%)**: Proporciona confianza probabilística para casos ambiguos

### Feature Engineering

**Features extraídas de logs:**

```python
{
    # Temporal
    'hour_of_day': int,              # 0-23
    'day_of_week': int,              # 0-6 (0=Lunes)
    'is_weekend': bool,
    
    # Frecuencia
    'login_attempts_per_minute': float,
    'requests_per_second': float,
    'unique_ips_last_hour': int,
    
    # Tasas
    'failed_auth_rate': float,       # 0.0-1.0
    'error_rate_5xx': float,
    
    # Geográfico
    'geographic_distance_km': float, # Desde IP habitual
    'is_known_country': bool,
    
    # Comportamiento
    'bytes_transferred': int,
    'time_since_last_activity_sec': float,
    'session_duration_sec': float,
    
    # Contexto
    'is_privileged_user': bool,
    'is_sensitive_endpoint': bool,
    'user_agent_entropy': float      # Detecta bots
}
```

### Retraining Strategy

El modelo se re-entrena automáticamente:
- **Scheduled**: Cada 24 horas (con logs del día)
- **Triggered**: Cuando hay 100+ feedbacks nuevos
- **Manual**: Endpoint `/api/v1/model/retrain`

---

## 🚢 Despliegue

### Producción con Docker Compose

```bash
# 1. Configurar secrets
cp .env.example .env
nano .env  # Cambiar POSTGRES_PASSWORD, SECRET_KEY, etc.

# 2. Construir para producción
docker-compose -f docker-compose.prod.yml build

# 3. Levantar servicios
docker-compose -f docker-compose.prod.yml up -d

# 4. Verificar salud
curl http://localhost:8000/api/v1/health

# 5. Ver logs
docker-compose -f docker-compose.prod.yml logs -f api
```

### Kubernetes (Producción Escalable)

```bash
# 1. Crear namespace
kubectl create namespace siem

# 2. Aplicar secrets
kubectl apply -f k8s/secrets.yaml -n siem

# 3. Desplegar base de datos (StatefulSet)
kubectl apply -f k8s/postgres.yaml -n siem
kubectl apply -f k8s/redis.yaml -n siem

# 4. Desplegar API (Deployment + HPA)
kubectl apply -f k8s/api-deployment.yaml -n siem
kubectl apply -f k8s/api-service.yaml -n siem
kubectl apply -f k8s/api-hpa.yaml -n siem

# 5. Verificar pods
kubectl get pods -n siem

# 6. Exponer servicio (Ingress)
kubectl apply -f k8s/ingress.yaml -n siem
```

### Scaling Considerations

- **API**: Auto-scaling con HPA (2-10 pods)
- **PostgreSQL**: StatefulSet con persistent volumes
- **Redis**: Redis Cluster para alta disponibilidad
- **ML Models**: Modelos cargados en memoria (considerar Redis para cache)

---

## 🔧 Configuración

### Variables de Entorno

```bash
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
LOG_LEVEL=INFO

# Database
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=siem_db
POSTGRES_USER=siem_user
POSTGRES_PASSWORD=changeme  # ⚠️ Cambiar en producción

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# ML Configuration
MODEL_CONTAMINATION=0.03
MODEL_RETRAIN_INTERVAL_HOURS=24
ENSEMBLE_WEIGHTS=0.5,0.3,0.2  # IF, DBSCAN, GMM

# Alerting
ALERT_THRESHOLD_HIGH=0.8
ALERT_THRESHOLD_MEDIUM=0.6
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
EMAIL_SMTP_HOST=smtp.gmail.com
EMAIL_RECIPIENTS=admin@example.com,security@example.com

# Security
SECRET_KEY=your-secret-key-here  # ⚠️ Generar con: openssl rand -hex 32
ALLOWED_HOSTS=localhost,127.0.0.1
CORS_ORIGINS=http://localhost:3000

# Monitoring
PROMETHEUS_ENABLED=true
PROMETHEUS_PORT=9090
```

---

## 🧪 Testing

```bash
# Instalar dependencias de testing
pip install -e ".[dev]"

# Ejecutar todos los tests
pytest

# Con coverage
pytest --cov=backend --cov-report=html

# Solo tests unitarios
pytest tests/test_ml.py

# Solo tests de integración
pytest tests/test_integration.py -v

# Tests con logs detallados
pytest -vv --log-cli-level=DEBUG
```

### Test Coverage Goal: >80%

```
backend/ml/         ✅ 95% coverage
backend/api/        ✅ 90% coverage
backend/parsers/    ✅ 85% coverage
backend/db/         ✅ 80% coverage
```

---

## 📊 Monitoreo

### Métricas Prometheus

El sistema expone métricas en `/metrics`:

```prometheus
# Logs procesados
siem_logs_processed_total{source="auth.log"} 1234567

# Anomalías detectadas
siem_anomalies_detected_total{risk_level="high"} 342

# Latencia de análisis
siem_analysis_duration_seconds{quantile="0.95"} 0.089

# Modelos cargados
siem_models_loaded{model="isolation_forest"} 1
```

### Dashboard Grafana

Importar dashboard desde: `docs/grafana-dashboard.json`

**Panels incluidos:**
- Logs procesados por minuto
- Tasa de anomalías (últimas 24h)
- Top 10 IPs anómalas
- Distribución de risk scores
- Latencia p50, p95, p99
- Uso de memoria/CPU

---

## 🗺️ Roadmap

### v1.0 (Actual)
- ✅ Ensemble ML (IF + DBSCAN + GMM)
- ✅ Parsers (Syslog, Nginx, Auth)
- ✅ API REST con FastAPI
- ✅ Docker Compose
- ✅ Tests unitarios + integración

### v1.1 (Próximo mes)
- 🚧 Dashboard web (React + Recharts)
- 🚧 Alertas por Slack/Email/Webhook
- 🚧 Parser para Windows Event Logs
- 🚧 Soporte para logs en JSON custom

### v1.2 (Q2 2026)
- 📋 Deep Learning (LSTM para sequences)
- 📋 Integración con Wazuh/Suricata
- 📋 Multi-tenancy (múltiples organizaciones)
- 📋 RBAC (control de acceso basado en roles)

### v2.0 (Q3 2026)
- 📋 Threat Intelligence feeds (MISP, AlienVault)
- 📋 Automated response (block IPs via firewall API)
- 📋 Behavioral profiling (per-user baselines)
- 📋 Cloud-native (AWS Lambda, Cloud Functions)

---

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Por favor:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

**Antes de contribuir:**
- Ejecuta `ruff format .` (formatting)
- Ejecuta `ruff check .` (linting)
- Ejecuta `mypy backend --strict` (type checking)
- Asegúrate de que `pytest` pasa al 100%

---

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Ver [LICENSE](LICENSE) para más detalles.

---

## 👤 Autor

**Adrian Infantes Romero**
- GitHub: [@tu-usuario](https://github.com/tu-usuario)
- LinkedIn: [tu-perfil](https://linkedin.com/in/tu-perfil)
- Email: tu.email@example.com

---

## 🙏 Agradecimientos

- [FastAPI](https://fastapi.tiangolo.com/) - Web framework
- [Scikit-learn](https://scikit-learn.org/) - ML library
- [Isolation Forest Paper](https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf) - Original research
- [AI-RedTeam-Course](../) - Proyecto educativo base

---

## 📚 Referencias

- [SIEM Best Practices](https://www.sans.org/white-papers/)
- [Anomaly Detection in Logs](https://arxiv.org/abs/xxxx.xxxxx)
- [ML for Cybersecurity](https://www.oreilly.com/library/view/machine-learning-and/9781492044925/)

---

**⚠️ DISCLAIMER**: Este proyecto es para fines educativos y de investigación. No usar en producción sin revisar y adaptar a tus necesidades específicas de seguridad.

**🔐 SECURITY**: Si encuentras una vulnerabilidad de seguridad, por favor **NO** abras un issue público. Envía un email a security@example.com.
