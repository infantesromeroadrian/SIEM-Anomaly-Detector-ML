# 📥 Log Ingestion Guide

Este documento explica cómo configurar la **ingesta continua de logs** al SIEM desde sistemas reales y simulados.

## 🎯 Opción 1: Generador Continuo (DEMO)

### Para qué sirve
- **Demos y presentaciones**: Muestra datos fluyendo constantemente
- **Desarrollo y testing**: Genera tráfico realista sin necesitar infraestructura real
- **Validación de modelos**: Prueba el SIEM con diferentes tasas de anomalías

### Modo 1: Docker Service (Recomendado para demos)

```bash
# Iniciar SIEM con generador de logs automático
docker compose --profile demo up -d

# Verificar que está corriendo
docker logs siem-log-generator --tail 50 -f

# Ver estadísticas en tiempo real
docker exec siem-log-generator pkill -USR1 python  # (future: signal handler)

# Parar el generador (mantener el resto del sistema)
docker stop siem-log-generator

# Parar todo
docker compose --profile demo down
```

**Configuración** (archivo `.env`):
```bash
LOG_RATE=20              # Logs por minuto (default: 20)
LOG_INTERVAL=3           # Segundos entre lotes (default: 3)
ANOMALY_RATE=0.15        # Tasa de anomalías 0.0-1.0 (default: 0.15 = 15%)
```

### Modo 2: Script Manual (Control total)

```bash
# Generación continua (Ctrl+C para parar)
python scripts/log_generator.py

# Con parámetros personalizados
python scripts/log_generator.py \
  --rate 60 \              # 60 logs/minuto (1 por segundo)
  --interval 1 \           # Lotes cada 1 segundo
  --anomaly-rate 0.25      # 25% de anomalías

# Ejecutar por tiempo limitado
python scripts/log_generator.py --rate 30 --duration 300  # 5 minutos

# En background con nohup
nohup python scripts/log_generator.py --rate 20 > logs/generator.log 2>&1 &

# Monitorizar progreso
tail -f logs/generator.log
```

**Tipos de logs generados:**
- ✅ SSH logins exitosos (normal)
- ✅ Peticiones web normales (normal)
- ✅ Eventos del sistema (normal)
- 🔴 Brute force SSH (anomalía)
- 🔴 SQL injection (anomalía)
- 🔴 Privilege escalation (anomalía)
- 🔴 Cryptomining malware (anomalía)

---

## 🏭 Opción 2: Logs Reales (PRODUCCIÓN)

### 2.1 Syslog Server (rsyslog/syslog-ng)

**Caso de uso:** Recibir logs de firewalls, routers, switches, servidores Linux.

#### Configuración rsyslog

```bash
# En el servidor que genera logs
# /etc/rsyslog.d/50-siem.conf

# Enviar todos los logs al SIEM vía HTTP
$ModLoad imuxsock
$ModLoad imjournal

# Template para enviar como JSON al SIEM
template(name="SiemJsonTemplate" type="list") {
    constant(value="{\"log_line\":\"")
    property(name="msg" format="json")
    constant(value="\",\"source\":\"syslog\"}")
}

# Enviar logs críticos/alertas al SIEM
if $syslogseverity <= 4 then {
    action(
        type="omhttp"
        server="siem.company.com"
        serverport="8000"
        restpath="/api/v1/logs/analyze"
        template="SiemJsonTemplate"
        batch="on"
        batch.maxsize="100"
    )
}
```

```bash
# Reiniciar rsyslog
sudo systemctl restart rsyslog

# Verificar que envía logs
logger -p auth.crit "Test SIEM integration"
```

### 2.2 Filebeat (Elastic Stack)

**Caso de uso:** Leer logs de archivos, enviarlos al SIEM vía HTTP.

#### filebeat.yml

```yaml
filebeat.inputs:
  # SSH/Auth logs
  - type: log
    enabled: true
    paths:
      - /var/log/auth.log
      - /var/log/secure
    tags: ["auth", "ssh"]
    fields:
      source: "auth"

  # Nginx logs
  - type: log
    enabled: true
    paths:
      - /var/log/nginx/access.log
      - /var/log/nginx/error.log
    tags: ["nginx", "web"]
    fields:
      source: "nginx"

  # Syslog
  - type: log
    enabled: true
    paths:
      - /var/log/syslog
      - /var/log/messages
    tags: ["syslog"]
    fields:
      source: "syslog"

# Output to SIEM API
output.http:
  hosts: ["http://siem.company.com:8000"]
  path: "/api/v1/logs/analyze"
  method: "POST"
  headers:
    Content-Type: "application/json"
  parameters:
    source: "%{[fields.source]}"
  bulk_max_size: 50
  worker: 2
  compression_level: 3
  timeout: 30s

# Procesamiento
processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
  - rename:
      fields:
        - from: "message"
          to: "log_line"
```

```bash
# Instalar Filebeat
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.0-linux-x86_64.tar.gz
tar xzvf filebeat-8.11.0-linux-x86_64.tar.gz
cd filebeat-8.11.0

# Iniciar
sudo ./filebeat -e -c filebeat.yml
```

### 2.3 Fluentd (Unified Logging Layer)

**Caso de uso:** Centralizar logs de múltiples fuentes, procesarlos, enviarlos al SIEM.

#### fluent.conf

```ruby
# Input: Syslog UDP
<source>
  @type syslog
  port 5140
  bind 0.0.0.0
  tag syslog
</source>

# Input: Tail nginx access logs
<source>
  @type tail
  path /var/log/nginx/access.log
  pos_file /var/log/td-agent/nginx-access.log.pos
  tag nginx.access
  <parse>
    @type nginx
  </parse>
</source>

# Input: Forward from other servers
<source>
  @type forward
  port 24224
  bind 0.0.0.0
</source>

# Transform: Add source field
<filter **>
  @type record_transformer
  <record>
    source ${tag_parts[0]}
  </record>
</filter>

# Output: Send to SIEM API
<match **>
  @type http
  endpoint http://siem.company.com:8000/api/v1/logs/analyze
  http_method post
  serializer json
  rate_limit_msec 100
  <buffer>
    flush_interval 5s
    chunk_limit_size 10M
  </buffer>
  <format>
    @type json
  </format>
</match>
```

### 2.4 Logstash (ELK Stack)

#### logstash.conf

```ruby
input {
  # Syslog input
  syslog {
    port => 514
    type => "syslog"
  }

  # File input
  file {
    path => "/var/log/auth.log"
    type => "auth"
    start_position => "beginning"
  }

  # Beats input
  beats {
    port => 5044
  }
}

filter {
  # Add source field based on type
  mutate {
    add_field => { "source" => "%{type}" }
  }
}

output {
  # Send to SIEM
  http {
    url => "http://siem.company.com:8000/api/v1/logs/analyze"
    http_method => "post"
    format => "json"
    mapping => {
      "log_line" => "%{message}"
      "source" => "%{source}"
    }
  }
}
```

### 2.5 Nginx/Apache - Direct Logging

**Nginx con syslog:**

```nginx
# /etc/nginx/nginx.conf
http {
    # Log format
    log_format siem_json escape=json
        '{'
            '"log_line":"$remote_addr - $remote_user [$time_local] \\"$request\\" $status $body_bytes_sent",'
            '"source":"nginx"'
        '}';

    # Access log to SIEM via HTTP POST (requires nginx module)
    access_log syslog:server=siem.company.com:514,facility=local7,tag=nginx,severity=info siem_json;
}
```

### 2.6 Python Application - Direct Integration

```python
import requests
import logging

class SIEMHandler(logging.Handler):
    """Send logs directly to SIEM API."""

    def __init__(self, siem_url: str, source: str = "app"):
        super().__init__()
        self.siem_url = siem_url
        self.source = source

    def emit(self, record):
        """Send log record to SIEM."""
        log_entry = self.format(record)

        try:
            requests.post(
                self.siem_url,
                json={
                    "log_line": log_entry,
                    "source": self.source,
                    "metadata": {
                        "level": record.levelname,
                        "logger": record.name,
                        "filename": record.filename,
                        "lineno": record.lineno,
                    }
                },
                timeout=5
            )
        except Exception:
            # Don't fail application if SIEM is down
            pass

# Usage
logger = logging.getLogger(__name__)
siem_handler = SIEMHandler("http://siem.company.com:8000/api/v1/logs/analyze", source="myapp")
logger.addHandler(siem_handler)

logger.critical("Suspicious login attempt from 185.234.219.45")
```

### 2.7 Webhook Integration (GitHub, GitLab, etc.)

```python
# backend/api/routes/webhooks.py (new endpoint)
from fastapi import APIRouter, Request

router = APIRouter()

@router.post("/webhooks/github")
async def github_webhook(request: Request):
    """Receive GitHub audit logs."""
    payload = await request.json()

    # Convert to log format
    log_line = f"GitHub: {payload['action']} by {payload['sender']['login']}"

    # Forward to analysis endpoint
    # ... (implementation)

    return {"status": "received"}
```

---

## 🔌 Opción 3: API Directa (Custom Integration)

### cURL Example

```bash
# Single log
curl -X POST http://localhost:8000/api/v1/logs/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "log_line": "Jan 17 03:45:12 server sshd[5678]: Failed password for root from 185.234.219.45",
    "source": "auth"
  }'

# Batch logs (más eficiente)
curl -X POST http://localhost:8000/api/v1/logs/batch \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      {"log_line": "...", "source": "auth"},
      {"log_line": "...", "source": "nginx"},
      {"log_line": "...", "source": "firewall"}
    ]
  }'
```

### Python Script

```python
#!/usr/bin/env python3
"""Send logs from file to SIEM."""

import requests
import time

SIEM_API = "http://localhost:8000/api/v1/logs/analyze"

def tail_file(filename):
    """Tail file and send new lines to SIEM."""
    with open(filename, 'r') as f:
        # Go to end of file
        f.seek(0, 2)

        while True:
            line = f.readline()
            if line:
                # Send to SIEM
                requests.post(SIEM_API, json={
                    "log_line": line.strip(),
                    "source": "auth"  # Detect from file path
                })
            else:
                time.sleep(0.5)

if __name__ == "__main__":
    tail_file("/var/log/auth.log")
```

---

## 📊 Verificación de Ingesta

### 1. Verificar logs recibidos

```bash
# API endpoint
curl http://localhost:8000/api/v1/stats

# Base de datos
docker exec siem-postgres psql -U siem_user -d siem_db -c \
  "SELECT COUNT(*) FROM logs WHERE created_at > NOW() - INTERVAL '1 hour';"
```

### 2. Monitorizar tasa de ingesta

```bash
# Ver logs en tiempo real
watch -n 1 'curl -s http://localhost:8000/api/v1/stats | jq ".logs_analyzed_24h"'

# Prometheus metrics
curl http://localhost:8000/metrics | grep siem_logs_analyzed_total
```

### 3. Ver anomalías detectadas

```bash
# Últimas anomalías
curl -s "http://localhost:8000/api/v1/anomalies?limit=10" | jq '.anomalies[] | {risk: .risk_score, level: .risk_level, ip: .features.geographic}'

# Frontend
open http://localhost:5173
```

---

## ⚙️ Configuración de Rendimiento

### Límites de tasa (Rate Limiting)

Si recibes **muchos logs** (>1000/sec), considera:

1. **Batch processing**: Usar `/api/v1/logs/batch` en lugar de llamadas individuales
2. **Redis queue**: Encolar logs y procesarlos async
3. **Horizontal scaling**: Múltiples workers de FastAPI
4. **Sampling**: Solo analizar % de logs normales, 100% de críticos

```python
# Example: Sample 10% of INFO, 100% of CRITICAL
import random

def should_analyze(log_level: str) -> bool:
    if log_level in ["CRITICAL", "ERROR"]:
        return True
    elif log_level == "WARNING":
        return random.random() < 0.5
    else:
        return random.random() < 0.1
```

---

## 🚀 Quick Start

### Demo Mode (Para presentaciones)

```bash
# 1. Iniciar todo con generador automático
docker compose --profile demo up -d

# 2. Esperar 30 segundos

# 3. Abrir frontend
open http://localhost:5173

# 4. Verás logs fluyendo constantemente
```

### Producción (Logs reales)

```bash
# 1. Iniciar SIEM (sin generador)
docker compose up -d

# 2. Configurar rsyslog/Filebeat/Fluentd según tu infraestructura

# 3. Enviar log de prueba
logger -p auth.crit "Test from rsyslog"

# 4. Verificar recepción
curl http://localhost:8000/api/v1/stats
```

---

## 📚 Recursos

- [rsyslog documentation](https://www.rsyslog.com/doc/)
- [Filebeat reference](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)
- [Fluentd guides](https://docs.fluentd.org/)
- [RFC 5424 (Syslog Protocol)](https://tools.ietf.org/html/rfc5424)

---

## 🐛 Troubleshooting

### Logs no llegan al SIEM

```bash
# 1. Verificar API está arriba
curl http://localhost:8000/api/v1/health

# 2. Verificar firewall
sudo netstat -tulpn | grep 8000

# 3. Probar envío manual
curl -X POST http://localhost:8000/api/v1/logs/analyze \
  -H "Content-Type: application/json" \
  -d '{"log_line": "test", "source": "syslog"}'

# 4. Ver logs de API
docker logs siem-api --tail 100 -f
```

### Rendimiento lento

```bash
# 1. Verificar carga de CPU/RAM
docker stats siem-api

# 2. Verificar latencia de BD
docker exec siem-postgres psql -U siem_user -d siem_db -c \
  "SELECT pg_stat_statements_reset();"  # Reiniciar stats

# 3. Escalar workers
# En docker-compose.yml cambiar:
# command: uvicorn backend.main:app --workers 4
```
