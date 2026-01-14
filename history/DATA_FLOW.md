# 📊 FLUJO DE DATA: De dónde sale y cómo llega a la interfaz

## 🎯 RESPUESTA RÁPIDA

**Script que genera logs de prueba:** `scripts/send_test_logs.py`

**Ejecución:**
```bash
# 1. Iniciar API (terminal 1)
source .venv/bin/activate
uvicorn backend.main:app --reload

# 2. Enviar logs de prueba (terminal 2)
source .venv/bin/activate
python scripts/send_test_logs.py

# 3. Ver en interfaz (navegador)
http://localhost:5173
```

---

## 🔄 FLUJO COMPLETO DE DATA

```
┌─────────────────────────────────────────────────────────────────┐
│  FASE 1: ENTRADA DE LOGS (3 vías)                               │
└─────────────────────────────────────────────────────────────────┘
         │
         ├─── 📨 API REST (HTTP POST)
         │    python scripts/send_test_logs.py
         │    curl -X POST http://localhost:8000/api/v1/logs/analyze
         │
         ├─── 📡 Syslog UDP (puerto 514)  [NO IMPLEMENTADO AÚN]
         │    rsyslog → localhost:514
         │
         └─── 📁 File Watcher  [NO IMPLEMENTADO AÚN]
              tail -f /var/log/auth.log
              
              ↓↓↓

┌─────────────────────────────────────────────────────────────────┐
│  FASE 2: API ENDPOINT → backend/api/routes/analysis.py          │
│  POST /api/v1/logs/analyze                                      │
└─────────────────────────────────────────────────────────────────┘
              ↓
    Request Body:
    {
      "log_line": "Jan 14 03:45:12 server sshd: Failed password...",
      "source": "auth"  # auth, nginx, syslog, firewall
    }
              ↓↓↓

┌─────────────────────────────────────────────────────────────────┐
│  FASE 3: PARSING → backend/parsers/                             │
│  - auth.py       (SSH, sudo, su)                                │
│  - nginx.py      (HTTP access logs)                             │
│  - syslog.py     (Generic syslog)                               │
│  - firewall.py   (iptables, ufw)                                │
└─────────────────────────────────────────────────────────────────┘
              ↓
    Parsed Data:
    {
      "timestamp": "2026-01-14T03:45:12Z",
      "source_ip": "185.234.219.45",
      "username": "admin",
      "event_type": "ssh_password_failed",
      "success": false
    }
              ↓↓↓

┌─────────────────────────────────────────────────────────────────┐
│  FASE 4: FEATURE ENGINEERING → backend/ml/features.py           │
│  Calcula 21 features en tiempo real                             │
└─────────────────────────────────────────────────────────────────┘
              ↓
    Consulta Redis para rates:
    - login_attempts_per_minute (últimos 60s)
    - failed_auth_rate (últimos 5min)
    - requests_per_second
    
    Consulta PostgreSQL para histórico:
    - time_since_last_activity
    - unique_ips_last_hour
    
    Consulta GeoIP:
    - geographic_distance_km
    - is_known_country
    
              ↓
    Features [21 números]:
    [3, 1, 0, 0, 25.0, 0.5, 2, 5, 0.95, 0.0, 0.0,
     8500.0, 0, 0, 7.2, 2.0, 5.0, 3.8, 0, 1, 0]
              ↓↓↓

┌─────────────────────────────────────────────────────────────────┐
│  FASE 5: ML ENSEMBLE → backend/ml/ensemble.py                   │
│  3 modelos en paralelo                                          │
└─────────────────────────────────────────────────────────────────┘
         │
         ├─── Isolation Forest (50% peso)
         │    → Score: 0.85 (outlier!)
         │
         ├─── DBSCAN (30% peso)
         │    → Score: 0.75 (lejos de clusters)
         │
         └─── GMM (20% peso)
              → Score: 0.92 (baja probabilidad)
              
              ↓
    Ensemble Score = 0.5×0.85 + 0.3×0.75 + 0.2×0.92
                   = 0.834 (HIGH RISK!)
              ↓↓↓

┌─────────────────────────────────────────────────────────────────┐
│  FASE 6: GUARDAR EN BASE DE DATOS → backend/db/crud.py          │
│  PostgreSQL (tabla: anomalies, logs)                            │
└─────────────────────────────────────────────────────────────────┘
              ↓
    INSERT INTO anomalies (
      log_timestamp,
      source_ip,
      username,
      event_type,
      risk_score,
      risk_level,
      reasons,
      recommended_action,
      ...
    ) VALUES (...)
              ↓↓↓

┌─────────────────────────────────────────────────────────────────┐
│  FASE 7: RESPUESTA API                                          │
└─────────────────────────────────────────────────────────────────┘
              ↓
    Response:
    {
      "is_anomaly": true,
      "risk_score": 0.834,
      "risk_level": "HIGH",
      "reasons": [
        "Activity at unusual hour (3 AM)",
        "High login attempt rate (25/min) - brute force",
        "High failed auth rate (95%)",
        "Unknown IP address"
      ],
      "recommended_action": "BLOCK_IP",
      "model_scores": {
        "isolation_forest": 0.85,
        "dbscan": 0.75,
        "gmm": 0.92
      }
    }
              ↓↓↓

┌─────────────────────────────────────────────────────────────────┐
│  FASE 8: FRONTEND CONSULTA LA DATA → frontend/src/             │
│  React + TypeScript + Vite                                      │
└─────────────────────────────────────────────────────────────────┘
         │
         ├─── GET /api/v1/stats
         │    → Dashboard: logs_analyzed_24h, anomalies_detected_24h
         │
         ├─── GET /api/v1/anomalies?limit=50
         │    → AnomalyList: últimas 50 anomalías detectadas
         │
         └─── GET /api/v1/stats/timeseries?hours=24
              → Chart: gráfico de anomalías por hora
              
              ↓↓↓

┌─────────────────────────────────────────────────────────────────┐
│  FASE 9: VISUALIZACIÓN EN INTERFAZ                              │
│  http://localhost:5173                                          │
└─────────────────────────────────────────────────────────────────┘
              ↓
    Dashboard muestra:
    ┌──────────────────────────────────────────┐
    │ 📊 Logs Analyzed: 8                      │
    │ 🚨 Anomalies: 5 (62.5%)                  │
    │ 📈 Risk Level: HIGH                      │
    └──────────────────────────────────────────┘
    
    Lista de anomalías:
    ┌──────────────────────────────────────────┐
    │ 🔴 SSH Brute Force (3:45 AM)             │
    │    185.234.219.45 → admin@server         │
    │    Risk: 0.834 | Action: BLOCK_IP        │
    ├──────────────────────────────────────────┤
    │ 🔴 SQL Injection (10:15 PM)              │
    │    45.132.246.198 → /admin' OR 1=1--     │
    │    Risk: 0.756 | Action: REQUIRE_MFA     │
    └──────────────────────────────────────────┘
```

---

## 📁 ARCHIVOS CLAVE

### **1. Script que GENERA data de prueba:**
```bash
scripts/send_test_logs.py  # ← ESTE ES EL QUE BUSCAS
```

**Qué hace:**
- Genera 8 logs de prueba (3 normales + 5 ataques)
- Los envía vía POST a `/api/v1/logs/analyze`
- Cada log se analiza, clasifica y guarda en PostgreSQL
- La interfaz consulta PostgreSQL y los muestra

### **2. Endpoint que RECIBE los logs:**
```python
backend/api/routes/analysis.py
  → POST /api/v1/logs/analyze
```

### **3. Parsers que EXTRAEN info:**
```python
backend/parsers/auth.py      # SSH, sudo, su
backend/parsers/nginx.py     # HTTP logs
backend/parsers/syslog.py    # Generic syslog
backend/parsers/firewall.py  # iptables, ufw
```

### **4. Feature engineering:**
```python
backend/ml/features.py
  → FeatureEngineer.extract()  # 21 features
```

### **5. ML Ensemble:**
```python
backend/ml/ensemble.py
  → AnomalyEnsemble.predict()  # 3 modelos
```

### **6. Base de datos:**
```python
backend/db/crud.py
  → create_anomaly()  # Guarda en PostgreSQL
  → create_log()
```

### **7. Frontend consulta data:**
```typescript
frontend/src/services/api.ts
  → getAnomalies()  # GET /api/v1/anomalies
  → getStats()      # GET /api/v1/stats
```

---

## 🚀 CÓMO USAR

### **Opción 1: Enviar logs vía script (RECOMENDADO)**

```bash
# Terminal 1: Iniciar backend
cd /path/to/SIEM-Anomaly-Detector-ML
source .venv/bin/activate
uvicorn backend.main:app --reload

# Terminal 2: Enviar logs de prueba
source .venv/bin/activate
python scripts/send_test_logs.py

# Navegador: Ver resultados
http://localhost:5173
```

### **Opción 2: Enviar logs vía curl**

```bash
# Log normal
curl -X POST http://localhost:8000/api/v1/logs/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "log_line": "Jan 14 14:30:15 server sshd: Accepted password for john from 192.168.1.50",
    "source": "auth"
  }'

# Log anómalo (brute force)
curl -X POST http://localhost:8000/api/v1/logs/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "log_line": "Jan 14 03:45:12 server sshd: Failed password for admin from 185.234.219.45",
    "source": "auth"
  }'
```

### **Opción 3: Enviar logs vía Python**

```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/logs/analyze",
    json={
        "log_line": "Jan 14 03:45:12 server sshd: Failed password for admin from 185.234.219.45",
        "source": "auth",
    }
)

print(response.json())
```

---

## 🎯 TIPOS DE LOGS SOPORTADOS

### **1. Auth Logs (SSH, sudo, su)**
```bash
# SSH login exitoso
Jan 14 14:30:15 server sshd[1234]: Accepted password for john from 192.168.1.50

# SSH login fallido (anomalía potencial)
Jan 14 03:45:12 server sshd[5678]: Failed password for admin from 185.234.219.45

# Sudo command
Jan 14 10:20:30 server sudo: john : TTY=pts/0 ; PWD=/home/john ; COMMAND=/usr/bin/apt update

# Privilege escalation (anomalía!)
Jan 14 04:10:45 server sudo: john : command not allowed ; COMMAND=/bin/bash /etc/shadow
```

### **2. Nginx Logs (HTTP)**
```bash
# Request normal
192.168.1.100 - - [14/Jan/2026:14:30:15 +0000] "GET /api/users HTTP/1.1" 200 2048

# SQL Injection (anomalía!)
45.132.246.198 - - [14/Jan/2026:22:15:30 +0000] "GET /admin' OR 1=1-- HTTP/1.1" 403 156

# DDoS (anomalía!)
178.128.45.67 - - [14/Jan/2026:15:40:20 +0000] "GET /api/search HTTP/1.1" 503 0
```

### **3. Syslog (Generic)**
```bash
# Normal system event
Jan 14 14:30:15 server kernel: [12345.678901] eth0: link up

# Cryptomining (anomalía!)
Jan 14 02:20:15 server systemd[1]: Started cryptominer service
```

### **4. Firewall Logs**
```bash
# Blocked connection
Jan 14 14:30:15 firewall kernel: [UFW BLOCK] IN=eth0 SRC=185.234.219.45 DST=192.168.1.1 PROTO=TCP DPT=22

# Port scanning (anomalía!)
Jan 14 03:00:00 firewall kernel: [UFW BLOCK] IN=eth0 SRC=45.132.246.198 DST=192.168.1.1 PROTO=TCP DPT=1-65535
```

---

## 📊 DATOS QUE VES EN LA INTERFAZ

### **Dashboard**
- **Logs analizados (24h):** Total de logs procesados
- **Anomalías detectadas:** Número de amenazas encontradas
- **Tasa de anomalías:** Porcentaje de logs anómalos
- **Gráfico temporal:** Evolución de anomalías por hora

### **Lista de Anomalías**
Cada anomalía muestra:
- **Timestamp:** Cuándo ocurrió
- **Source IP:** IP de origen
- **Event Type:** Tipo de evento (ssh_failed_login, http_request, etc.)
- **Risk Score:** Puntuación 0.0-1.0
- **Risk Level:** LOW, MEDIUM, HIGH, CRITICAL
- **Reasons:** Por qué es anómalo
  - "Activity at unusual hour (3 AM)"
  - "High login attempt rate (25/min)"
  - "Unknown IP address"
- **Recommended Action:** BLOCK_IP, REQUIRE_MFA, MONITOR, NO_ACTION
- **Model Scores:** Scores de IF, DBSCAN, GMM

---

## ❓ PREGUNTAS FRECUENTES

### **¿De dónde sale la data de ENTRENAMIENTO?**
❌ **NO HAY data real de entrenamiento.**
- El modelo se entrena con **data SINTÉTICA** generada en `scripts/train_ensemble_with_metrics.py`
- 10,000 logs normales + 500 anomalías simuladas
- Para producción, deberías reentrenar con logs REALES de tu entorno

### **¿De dónde sale la data que VEO en la interfaz?**
✅ **De los logs que TÚ envías al API.**
- Vía `scripts/send_test_logs.py` (logs de prueba)
- Vía curl/Postman (manual)
- Vía rsyslog (en producción, NO implementado aún)
- Vía file watcher (en producción, NO implementado aún)

### **¿Cómo genero MÁS data para la interfaz?**
```bash
# Ejecuta el script múltiples veces
python scripts/send_test_logs.py
python scripts/send_test_logs.py
python scripts/send_test_logs.py

# Cada ejecución añade 8 logs más a la BD
```

### **¿Cómo LIMPIO la data de prueba?**
```bash
# Conectar a PostgreSQL y truncar tablas
docker exec -it siem-postgres psql -U siem_user -d siem_db
DELETE FROM anomalies;
DELETE FROM logs;
```

---

## 🎯 RESUMEN ULTRA-RÁPIDO

```bash
# 1. Script que genera data
scripts/send_test_logs.py  # ← ESTE

# 2. Cómo ejecutarlo
python scripts/send_test_logs.py

# 3. Qué hace
Envía 8 logs → API analiza → Guarda en PostgreSQL → Frontend muestra

# 4. Dónde ver resultados
http://localhost:5173
```

**FIN. ¿Más claro imposible, no?** 😎
