# 🚀 Quick Start - Logs Continuos

## 🎯 El Problema

Un SIEM debe recibir logs **CONSTANTEMENTE**, no solo cuando ejecutas un script manual.

## ✅ Soluciones

### **Opción 1: Modo DEMO (Recomendado para empezar)**

Genera logs automáticamente para ver el SIEM en acción:

```bash
# Iniciar SIEM + Generador automático
docker compose --profile demo up -d

# Ver logs generándose en tiempo real
docker logs siem-log-generator -f

# Abrir frontend
open http://localhost:5173

# Parar generador (mantener SIEM)
docker stop siem-log-generator

# Parar todo
docker compose --profile demo down
```

**Configuración** (en `.env`):
```bash
LOG_RATE=30              # Logs por minuto
ANOMALY_RATE=0.15        # 15% de anomalías
```

---

### **Opción 2: Script Manual (Control total)**

```bash
# Generar logs continuamente (Ctrl+C para parar)
python scripts/log_generator.py

# Con parámetros personalizados
python scripts/log_generator.py --rate 60 --interval 1 --anomaly-rate 0.20

# Ejecutar por 5 minutos y parar
python scripts/log_generator.py --rate 30 --duration 300

# En background
nohup python scripts/log_generator.py --rate 20 > logs/generator.log 2>&1 &
```

---

### **Opción 3: Logs REALES (Producción)**

#### 3.1 Desde rsyslog (servidores Linux)

```bash
# En el servidor que genera logs
# /etc/rsyslog.d/50-siem.conf

*.* action(type="omfwd" target="SIEM_IP" port="514" protocol="tcp")
```

```bash
sudo systemctl restart rsyslog

# Probar
logger "Test desde rsyslog"
```

#### 3.2 Desde Filebeat (archivos de log)

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/auth.log
      - /var/log/nginx/*.log

output.http:
  hosts: ["http://SIEM_IP:8000"]
  path: "/api/v1/logs/analyze"
```

#### 3.3 Desde tu aplicación Python

```python
import requests

SIEM_API = "http://localhost:8000/api/v1/logs/analyze"

def send_to_siem(log_message: str):
    requests.post(SIEM_API, json={
        "log_line": log_message,
        "source": "myapp"
    })

# Uso
send_to_siem("Failed login attempt from 185.234.219.45")
```

#### 3.4 Con cURL (cualquier sistema)

```bash
curl -X POST http://localhost:8000/api/v1/logs/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "log_line": "Jan 17 03:45:12 server sshd: Failed password for root from 185.234.219.45",
    "source": "auth"
  }'
```

---

## 📊 Verificar que Funciona

```bash
# 1. Ver estadísticas
curl http://localhost:8000/api/v1/stats | jq

# 2. Ver anomalías detectadas
curl "http://localhost:8000/api/v1/anomalies?limit=10" | jq

# 3. Contar logs en base de datos
docker exec siem-postgres psql -U siem_user -d siem_db -c \
  "SELECT COUNT(*) FROM logs WHERE created_at > NOW() - INTERVAL '1 hour';"

# 4. Ver frontend
open http://localhost:5173
```

---

## 🎯 Diferencia Clave

| Modo | Uso | Logs | Duración |
|------|-----|------|----------|
| **Manual** | Testing | 8 logs fijos | 1 vez |
| **Generador** | Demo/Dev | Aleatorios continuos | Hasta que lo pares |
| **Producción** | Real | Logs reales del sistema | 24/7 |

---

## 📚 Más Información

- **Guía completa**: `docs/LOG_INGESTION.md`
- **Endpoints API**: http://localhost:8000/docs
- **Monitorización**: Prometheus (http://localhost:9090) + Grafana (http://localhost:3000)

---

## 🐛 Troubleshooting

### No veo logs nuevos

```bash
# 1. ¿Está corriendo el generador?
docker ps | grep log-generator

# 2. ¿La API está recibiendo peticiones?
docker logs siem-api --tail 50

# 3. ¿Hay errores?
docker logs siem-log-generator --tail 50
```

### Generador muy lento

```bash
# Aumentar tasa en .env
LOG_RATE=60  # 60 logs/minuto

# Reiniciar
docker compose --profile demo up -d --force-recreate log-generator
```

### Quiero parar el generador pero mantener el SIEM

```bash
# Parar solo generador
docker stop siem-log-generator

# O sin profile demo
docker compose up -d  # Sin --profile demo
```
