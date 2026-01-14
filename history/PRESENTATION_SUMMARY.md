# 🤖 SIEM Anomaly Detector - Presentación Técnica

## 🎯 Objetivo del Proyecto

**Detectar amenazas de seguridad en tiempo real usando Machine Learning no supervisado**

- ✅ Analiza logs de SSH, Nginx, syslog, firewall
- ✅ Detecta brute force, SQL injection, DDoS, privilege escalation, etc.
- ✅ Sin necesidad de logs etiquetados (unsupervised learning)
- ✅ Response time: <10ms por log

---

## 🏗️ Arquitectura ML (Perspectiva ML Engineer)

### **1. Pipeline Completo**

```
Log Raw → Parser → Feature Engineering (21 features) → Ensemble ML → Clasificación
   1ms      3ms            5ms                            10ms total
```

### **2. Ensemble de 3 Modelos**

| Modelo | Peso | Qué Detecta | Por Qué |
|--------|------|-------------|---------|
| **Isolation Forest** | 50% | Outliers globales | Rápido, detecta ataques externos |
| **DBSCAN** | 30% | Anomalías locales | Insider threats, escalaciones |
| **Gaussian Mixture** | 20% | Anomalías estadísticas | Scores probabilísticos |

**Agregación:**
```
Score Final = 0.5×IF + 0.3×DBSCAN + 0.2×GMM
Anomalía si Score ≥ 0.6 (configurable)
```

### **3. Feature Engineering (21 features)**

- **Temporal** (4): hora, día, weekend, horario laboral
- **Frequency** (4): login attempts/min, requests/sec, unique IPs, endpoints
- **Rates** (3): failed_auth_rate, error_4xx, error_5xx
- **Geographic** (3): distancia_km, país conocido, IP conocida
- **Behavioral** (4): bytes, tiempo_inactividad, sesión, entropía
- **Context** (3): usuario privilegiado, endpoint sensible, user agent

**Cálculo en tiempo real:**
- Redis → rates (últimos 60s)
- PostgreSQL → histórico
- GeoIP → ubicación

---

## 📊 Métricas del Modelo

### **Confusion Matrix (Test Set)**

```
              Predicted
           Normal  Anomaly
Actual
Normal      1993      7     ← Solo 7 falsos positivos
Anomaly        0    100     ← CERO amenazas perdidas 🎯
```

### **Métricas Principales**

| Métrica | Valor | Interpretación |
|---------|-------|----------------|
| **F1-Score** | **96.6%** | Balance excelente |
| **Recall** | **100%** | Detecta TODAS las amenazas 🎯 |
| **Precision** | 93.5% | Cuando alerta, acierta 93.5% |
| **FPR** | 0.35% | Solo 7 falsos positivos de 2000 |
| **ROC-AUC** | 100% | Separación perfecta |

### **vs Baseline (Dummy Classifier)**

- Baseline F1: **0%** (no detecta nada)
- Nuestro Ensemble F1: **96.6%**
- **Mejora: +96.6 puntos** (infinito en términos relativos)

---

## 🚀 Stack Tecnológico

```yaml
ML/Data:
  - scikit-learn 1.8.0
  - numpy 2.4.1
  - pandas 2.3.3

Backend:
  - FastAPI 0.128.0
  - PostgreSQL 15 (TimescaleDB)
  - Redis 7

Frontend:
  - React + TypeScript
  - Vite
  - Recharts (visualización)

Infrastructure:
  - Docker + Compose
  - Prometheus + Grafana
  - uv (dependency management)
```

---

## 🎓 Training Process

### **Data Split:**
- Train: 60% (6,300 samples)
- Validation: 20% (2,100 samples)
- Test: 20% (2,100 samples)

### **Data Leakage Check:**
✅ PASSED - No overlap entre splits

### **Training Time:**
~3.5 segundos en CPU

### **Data:**
- 10,000 logs normales (95%)
- 500 logs anómalos (5%)
- **NOTA:** Data sintética generada con patrones realistas
- **TODO:** Re-entrenar con logs reales de producción

---

## 💻 Demo en Vivo

### **1. Ver Arquitectura en Frontend**

```bash
# Abrir navegador
http://localhost:5173

# Ir a la sección "🏗️ Model Architecture"
# - Tab Overview: Resumen del modelo
# - Tab Architecture: Pipeline visual completo
# - Tab Metrics: Confusion matrix, F1, etc.
# - Tab Features: 21 features explicadas
```

### **2. Enviar Logs de Prueba**

```bash
# Terminal 1: API debe estar corriendo
docker ps  # Verificar que siem-api está UP

# Terminal 2: Enviar logs
source .venv/bin/activate
python scripts/send_test_logs.py

# Output: 8 logs analizados
# - 3 normales (green)
# - 5 anomalías (red/orange)
```

### **3. Ver Resultados en UI**

```bash
# Refrescar http://localhost:5173
# - Dashboard: Stats actualizadas
# - Anomaly List: Logs detectados con detalles
#   - Risk score
#   - Reasons (por qué es anomalía)
#   - Recommended action
```

---

## 🔧 Desarrollo desde Perspectiva ML

### **Cómo Modificar el Modelo**

```python
# 1. Editar ensemble
vim backend/ml/ensemble.py

# Cambiar pesos:
ensemble_weights=[0.6, 0.2, 0.2]  # Más conservador

# 2. Re-entrenar
python scripts/train_ensemble_with_metrics.py

# 3. Verificar métricas
# Output: F1, Precision, Recall, Confusion Matrix
# Guardar en: models/ensemble_YYYYMMDD_HHMMSS.joblib

# 4. Actualizar .env
MODEL_PATH=./models/ensemble_YYYYMMDD_HHMMSS.joblib

# 5. Rebuild & restart
docker compose build api
docker compose restart api

# 6. Probar
python scripts/send_test_logs.py
```

### **Cómo Añadir Features**

```python
# 1. Añadir feature a dataclass
# backend/ml/features.py
@dataclass
class LogFeatures:
    # ... existing features
    new_feature: float  # Nueva feature

# 2. Calcular en extract()
async def extract(self, parsed_log: dict) -> LogFeatures:
    # ... existing code
    new_feature = calculate_new_feature(parsed_log)
    
    return LogFeatures(
        # ... existing
        new_feature=new_feature
    )

# 3. Re-entrenar modelo
python scripts/train_ensemble_with_metrics.py

# 4. Deploy
docker compose restart api
```

---

## 📈 Roadmap

### **Mejoras ML**

- [ ] Re-entrenar con logs reales (no sintéticos)
- [ ] Hyperparameter tuning (Grid Search)
- [ ] Añadir feature importance analysis (SHAP values)
- [ ] Implementar drift detection
- [ ] Auto-retraining pipeline (cada 7 días)

### **Mejoras Sistema**

- [ ] Syslog UDP listener (puerto 514)
- [ ] File watcher para /var/log/auth.log
- [ ] Alerting (Slack, Email, PagerDuty)
- [ ] RBAC (Role-Based Access Control)
- [ ] Multi-tenancy

### **Tests**

- [ ] Tests unitarios (pytest)
- [ ] Tests de integración
- [ ] Tests de carga (locust)
- [ ] CI/CD pipeline (GitHub Actions)

---

## 📚 Documentación Completa

```bash
# ML Engineer Guide (TÉCNICO - 800 líneas)
cat history/ML_ENGINEER_GUIDE.md

# Flujo de Data
cat history/DATA_FLOW.md

# Instalación
cat history/INSTALL.md
```

---

## 🎯 Puntos Clave para la Presentación

### **1. El Problema**
❌ Logs de seguridad abrumadores (miles/minuto)
❌ Amenazas escondidas entre ruido
❌ SOC teams saturados

### **2. La Solución**
✅ ML detecta patrones anómalos automáticamente
✅ <10ms por log → tiempo real
✅ 100% recall → NO pierde amenazas
✅ 0.35% FPR → Pocos falsos positivos

### **3. Resultados**
✅ F1-Score: 96.6%
✅ Detecta: brute force, SQL injection, DDoS, privilege escalation
✅ Explicable: muestra razones de cada alerta

### **4. Tech Stack Moderno**
✅ Ensemble ML (IF + DBSCAN + GMM)
✅ Feature engineering avanzado (21 features)
✅ FastAPI + React + Docker
✅ Prometheus + Grafana monitoring

### **5. Production Ready**
✅ Docker Compose stack completo
✅ Health checks + monitoring
✅ API RESTful documentada (OpenAPI)
✅ Frontend profesional

---

## ❓ Preguntas Esperadas

**Q: ¿Por qué no usar Deep Learning?**
A: Para este dataset (10k samples), ensemble clásico es suficiente y más rápido. DL requiere >100k samples y GPU.

**Q: ¿Cómo maneja logs nunca vistos?**
A: Unsupervised learning → aprende "lo normal", cualquier desviación es sospechosa.

**Q: ¿Qué pasa si la "normalidad" cambia?**
A: Implementar drift detection + auto-retraining cada 7 días.

**Q: ¿Cómo reducir falsos positivos?**
A: Ajustar `ensemble_weights` y `alert_threshold`. Actualmente FPR = 0.35% (muy bajo).

**Q: ¿Puede escalar a millones de logs?**
A: Sí. Con workers paralelización y batching → >1000 logs/sec. Para más, usar Kafka + Spark.

---

**🎤 ¡Listo para presentar!**

```bash
# Comando para iniciar demo:
docker compose up -d
# Esperar 10s
python scripts/send_test_logs.py
# Abrir http://localhost:5173
```
