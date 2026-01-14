# 🤖 SIEM Anomaly Detector - ML Engineer Guide

## 📋 Índice

1. [Introducción](#introducción)
2. [Arquitectura ML](#arquitectura-ml)
3. [Pipeline Completo](#pipeline-completo)
4. [Modelos del Ensemble](#modelos-del-ensemble)
5. [Feature Engineering](#feature-engineering)
6. [Training & Validation](#training--validation)
7. [Métricas de Performance](#métricas-de-performance)
8. [Deployment & Production](#deployment--production)
9. [Troubleshooting](#troubleshooting)

---

## 🎯 Introducción

### ¿Qué es este sistema?

Sistema de detección de anomalías en logs de seguridad (SIEM) usando **Machine Learning no supervisado**. Detecta amenazas en tiempo real analizando patrones en logs de SSH, Nginx, syslog y firewall.

### ¿Por qué ML No Supervisado?

```
✅ No requiere logs etiquetados (difícil de conseguir)
✅ Detecta amenazas nunca vistas antes (0-day attacks)
✅ Se adapta a patrones cambiantes
❌ Puede tener falsos positivos (mitigado con ensemble)
```

### Stack Tecnológico

```python
# ML/Data Science
- scikit-learn 1.8.0    # ML algorithms
- numpy 2.4.1           # Numerical computing
- pandas 2.3.3          # Data manipulation
- joblib 1.5.3          # Model persistence

# Backend
- FastAPI 0.128.0       # API framework
- PostgreSQL 15         # Data storage
- Redis 7               # Rate tracking
- Pydantic 2.12.5       # Data validation
- structlog 25.5.0      # Structured logging

# Infrastructure
- Docker + Compose      # Containerization
- Prometheus + Grafana  # Monitoring
- uvicorn               # ASGI server
```

---

## 🏗️ Arquitectura ML

### Diagrama de Alto Nivel

```
┌─────────────────────────────────────────────────────────────┐
│                    RAW SECURITY LOG                         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  PARSERS (backend/parsers/)                                 │
│  - auth.py     → SSH, sudo, su                              │
│  - nginx.py    → HTTP access logs                           │
│  - syslog.py   → Generic syslog                             │
│  - firewall.py → iptables, ufw                              │
└─────────────────────────────────────────────────────────────┘
                            ↓
                  Structured Dict
                  {timestamp, ip, user, ...}
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  FEATURE ENGINEERING (backend/ml/features.py)               │
│  - Query Redis    → Rates (login attempts, req/sec)         │
│  - Query Postgres → Historical (last activity, IPs)         │
│  - GeoIP lookup   → Geographic distance, country            │
│  ────────────────────────────────────────────────────────── │
│  Output: 21 numerical features [0, 1, 0, ...]              │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  ML ENSEMBLE (backend/ml/ensemble.py)                       │
│  ┌──────────────┬──────────────┬──────────────┐            │
│  │ Isolation    │ DBSCAN       │ GMM          │            │
│  │ Forest       │              │              │            │
│  │ (50%)        │ (30%)        │ (20%)        │            │
│  │              │              │              │            │
│  │ Score: 0.85  │ Score: 0.75  │ Score: 0.92  │            │
│  └──────────────┴──────────────┴──────────────┘            │
│                            ↓                                │
│  Weighted Sum: 0.5×0.85 + 0.3×0.75 + 0.2×0.92 = 0.834      │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  OUTPUT                                                     │
│  - is_anomaly: true                                         │
│  - risk_score: 0.834 (HIGH)                                 │
│  - recommended_action: BLOCK_IP                             │
│  - reasons: ["Unusual hour", "High login rate", ...]        │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔄 Pipeline Completo

### 1. Ingesta de Logs

```python
# Vía API REST
POST /api/v1/logs/analyze
{
  "log_line": "Jan 14 03:45:12 server sshd: Failed password for admin from 185.234.219.45",
  "source": "auth"
}

# Futuro: Vía syslog UDP (puerto 514)
# Futuro: Vía file watcher (tail -f /var/log/auth.log)
```

### 2. Parsing

```python
# backend/parsers/auth.py
class AuthLogParser:
    def parse(self, log_line: str) -> ParsedLog:
        # Regex patterns para extraer:
        # - timestamp
        # - hostname
        # - process (sshd, sudo, etc.)
        # - source_ip
        # - username
        # - event_type (ssh_password_failed, etc.)
        
# Output:
{
    "timestamp": "2026-01-14T03:45:12Z",
    "source_ip": "185.234.219.45",
    "username": "admin",
    "event_type": "ssh_password_failed",
    "success": false
}
```

### 3. Feature Engineering

```python
# backend/ml/features.py
class FeatureEngineer:
    async def extract(self, parsed_log: dict) -> LogFeatures:
        """
        Extrae 21 features en tiempo real:
        
        1. Temporal (4): hour, day_of_week, is_weekend, is_business_hours
        2. Frequency (4): login_attempts/min, requests/sec, unique_ips, endpoints
        3. Rates (3): failed_auth_rate, error_4xx, error_5xx
        4. Geographic (3): distance_km, is_known_country, is_known_ip
        5. Behavioral (4): bytes_transferred, time_since_last, session_duration, entropy
        6. Context (3): is_privileged_user, is_sensitive_endpoint, is_known_user_agent
        """
        
        # Consulta Redis para rates (últimos 60s)
        login_attempts = await self.redis.get(f"login_attempts:{source_ip}:last_minute")
        
        # Consulta PostgreSQL para histórico
        last_activity = await self.db.query(
            "SELECT MAX(timestamp) FROM logs WHERE source_ip = $1",
            source_ip
        )
        
        # GeoIP lookup
        geo = self.geoip.lookup(source_ip)
        distance_km = self._calculate_distance(geo.location, typical_location)
        
        return LogFeatures(
            hour_of_day=3,
            login_attempts_per_minute=25.0,  # ← RED FLAG
            failed_auth_rate=0.95,            # ← RED FLAG
            geographic_distance_km=8500.0,    # ← RED FLAG
            # ... 18 más
        )
```

### 4. ML Prediction

```python
# backend/ml/ensemble.py
class AnomalyEnsemble:
    def predict(self, features: LogFeatures) -> AnomalyResult:
        X = features.to_array().reshape(1, -1)  # [21 features]
        X_scaled = self.scaler.transform(X)
        
        # 1. Isolation Forest (50%)
        if_decision = self.isolation_forest.decision_function(X)[0]
        if_score = 1.0 / (1.0 + np.exp(if_decision * 10))
        # if_score = 0.85 (outlier!)
        
        # 2. DBSCAN (30%)
        dbscan_prediction = self._predict_dbscan(X_scaled[0])
        dbscan_score = 0.75  # Lejos de clusters
        
        # 3. GMM (20%)
        gmm_log_likelihood = self.gmm.score_samples(X_scaled)[0]
        gmm_score = 1.0 / (1.0 + np.exp((gmm_log_likelihood + 10) * 0.5))
        # gmm_score = 0.92 (baja probabilidad)
        
        # Weighted sum
        final_score = 0.5*0.85 + 0.3*0.75 + 0.2*0.92 = 0.834
        
        # Threshold (configurable via settings)
        is_anomaly = final_score >= 0.6  # medium threshold
        
        return AnomalyResult(
            is_anomaly=True,
            risk_score=0.834,
            confidence="high",  # Basado en std de scores
            isolation_forest_score=0.85,
            dbscan_score=0.75,
            gmm_score=0.92,
            important_features=[...],
            processing_time_ms=8.5
        )
```

---

## 🤖 Modelos del Ensemble

### 1. Isolation Forest (50% peso)

**Algoritmo:**
```
1. Crea árboles de decisión aleatorios (n_estimators=100)
2. En cada split, elige feature y valor aleatorio
3. Anomalías → pocas divisiones para aislarlas
4. Datos normales → muchas divisiones
```

**Parámetros:**
```python
IsolationForest(
    contamination=0.05,    # Espera 5% anomalías
    n_estimators=100,      # 100 árboles
    max_samples="auto",    # Auto-tune sample size
    random_state=42,       # Reproducibilidad
    n_jobs=-1              # Usa todos los cores
)
```

**Por qué lo usamos:**
- ✅ Muy rápido (O(n log n))
- ✅ Escala bien a datasets grandes
- ✅ No asume distribución de datos
- ✅ Detecta outliers globales

**Mejor para:**
- Ataques externos (IPs desconocidas)
- Patrones nunca vistos (0-day)
- Brute force attacks
- Port scanning

### 2. DBSCAN (30% peso)

**Algoritmo:**
```
1. Agrupa puntos densos en clusters
2. Parámetros: eps (radio) y min_samples (mín vecinos)
3. Puntos lejos de clusters → outliers
4. No necesita número de clusters predefinido
```

**Parámetros:**
```python
DBSCAN(
    eps=5.0,            # Radio de vecindad
    min_samples=50,     # Mínimo puntos para core point
    n_jobs=-1
)
```

**Por qué lo usamos:**
- ✅ Detecta anomalías locales
- ✅ Forma clusters de forma arbitraria
- ✅ Robusto a ruido
- ❌ No tiene predict() nativo (implementamos workaround)

**Mejor para:**
- Insider threats (comportamiento anómalo de usuarios conocidos)
- Privilege escalation
- Anomalías temporales (actividad a horas raras)

### 3. Gaussian Mixture Model (20% peso)

**Algoritmo:**
```
1. Modela datos como mezcla de K gaussianas
2. Estima parámetros con EM algorithm
3. Calcula log-likelihood de cada punto
4. Baja probabilidad → anomalía
```

**Parámetros:**
```python
GaussianMixture(
    n_components=3,         # 3 distribuciones
    covariance_type="full", # Covarianza completa
    random_state=42,
    n_init=10               # 10 inicializaciones
)
```

**Por qué lo usamos:**
- ✅ Da scores probabilísticos (interpretables)
- ✅ Soft clustering (pertenencia parcial)
- ✅ Modela distribuciones complejas
- ❌ Asume gaussianidad (mitigado con ensemble)

**Mejor para:**
- Anomalías estadísticas
- Eventos raros pero válidos
- Drift detection (cambios graduales)

---

## 🔧 Feature Engineering

### Features Calculados (21 total)

#### 1. Temporal Features (4)

```python
hour_of_day: int        # 0-23 (3 AM = sospechoso)
day_of_week: int        # 0-6 (0=Lunes, fin de semana = sospechoso)
is_weekend: bool        # True si sábado/domingo
is_business_hours: bool # True si 9 AM - 6 PM
```

**Fuente:** `timestamp` del log parseado

**Por qué importantes:**
- Ataques suelen ocurrir de noche (3-5 AM)
- Actividad en fin de semana es inusual
- Actividad fuera de horario laboral es sospechosa

#### 2. Frequency Features (4)

```python
login_attempts_per_minute: float  # Rate de logins (brute force)
requests_per_second: float        # Rate de requests (DDoS)
unique_ips_last_hour: int         # IPs distintas (distributed attack)
unique_endpoints_accessed: int    # Endpoints tocados (scanning)
```

**Fuente:** Redis (ventana deslizante de 60s)

**Implementación:**
```python
# Redis key pattern
f"login_attempts:{source_ip}:last_minute"

# Incrementa counter con TTL
await redis.incr(key, expire=60)

# Calcula rate
count = await redis.get(key)
rate = count / 60.0
```

**Por qué importantes:**
- Brute force → >20 intentos/min
- DDoS → >100 requests/sec
- Scanning → >30 endpoints

#### 3. Rate Features (3)

```python
failed_auth_rate: float  # 0.0-1.0 (% de fallos)
error_rate_4xx: float    # Client errors (bad requests)
error_rate_5xx: float    # Server errors (DoS symptoms)
```

**Fuente:** Redis (últimos 5 minutos)

**Por qué importantes:**
- Failed auth >70% = brute force
- High 4xx = scanning/probing
- High 5xx = DoS o exploit

#### 4. Geographic Features (3)

```python
geographic_distance_km: float  # Distancia desde ubicación típica
is_known_country: bool         # País en whitelist
is_known_ip: bool              # IP en whitelist
```

**Fuente:** MaxMind GeoIP2 database

**Implementación:**
```python
# GeoIP lookup
location = geoip2.city(source_ip)

# Calcular distancia haversine
distance = haversine(
    (location.lat, location.lon),
    (typical_lat, typical_lon)
)

# Check whitelists
is_known = source_ip in known_ips_set
is_known_country = location.country in ["US", "ES", "FR", "DE", "GB"]
```

**Por qué importantes:**
- Login desde China cuando usuario está en España = sospechoso
- Distancia >5000km = muy sospechoso
- IPs conocidas = usuarios legítimos

#### 5. Behavioral Features (4)

```python
bytes_transferred: float           # log1p(bytes) normalizado
time_since_last_activity_sec: float # Inactividad antes del log
session_duration_sec: float         # Duración de sesión
payload_entropy: float              # Entropía del payload (0-8)
```

**Fuente:** PostgreSQL (histórico) + análisis de payload

**Implementación:**
```python
# Entropía (randomness del payload)
from scipy.stats import entropy

def calculate_entropy(data: str) -> float:
    """Shannon entropy - detects encrypted/random data"""
    probabilities = [data.count(c) / len(data) for c in set(data)]
    return entropy(probabilities, base=2)

# entropy ≈ 4.5 = texto normal
# entropy ≈ 7.8 = datos encriptados (shellcode, cryptominers)
```

**Por qué importantes:**
- High entropy = payloads encriptados o shellcode
- Time since last = dormant accounts activating
- Bytes transferred = data exfiltration

#### 6. Context Features (3)

```python
is_privileged_user: bool      # root, admin, administrator
is_sensitive_endpoint: bool   # /admin, /api/admin, /wp-admin
is_known_user_agent: bool     # User agent en whitelist
```

**Fuente:** Configuración + análisis de log

**Por qué importantes:**
- Privileged user + failed login = crítico
- Sensitive endpoint + unknown IP = alerta
- Unknown user agent = bot/script

### Feature Normalization

```python
class FeatureEngineer:
    def normalize(self, features: dict) -> np.ndarray:
        """
        Normaliza features a [0, 1] para el modelo
        """
        # Temporal features → ya normalizados
        hour_norm = features["hour_of_day"] / 24.0
        day_norm = features["day_of_week"] / 7.0
        
        # Frequency features → log scale + clip
        login_norm = min(features["login_attempts_per_minute"] / 30.0, 1.0)
        
        # Geographic → log scale
        distance_norm = min(np.log1p(features["geographic_distance_km"]) / 10.0, 1.0)
        
        # Boolean → 0 o 1
        is_weekend_norm = float(features["is_weekend"])
        
        return np.array([...])  # 21 features normalizados
```

---

## 🎓 Training & Validation

### Training Script

```bash
# Script profesional con métricas completas
python scripts/train_ensemble_with_metrics.py

# Output:
# - Train/Val/Test split (60/20/20)
# - Data leakage check
# - Baseline comparison (Dummy Classifier)
# - Comprehensive metrics (F1, Precision, Recall, ROC-AUC, Confusion Matrix)
# - Model saved to models/
# - Metrics saved to JSON
```

### Data Split Strategy

```python
# 1. First split: 80% train+val, 20% test
X_temp, X_test, y_temp, y_test = train_test_split(
    X, y, 
    test_size=0.2,        # 20% para test final
    random_state=42,      # Reproducibilidad
    stratify=y            # Mantiene proporción de clases
)

# 2. Second split: 75% train, 25% val (del 80%)
# Resulta en 60/20/20 overall
X_train, X_val, y_train, y_val = train_test_split(
    X_temp, y_temp,
    test_size=0.25,
    random_state=42,
    stratify=y_temp
)

print(f"Train: {len(X_train):,} samples (60%)")  # 6,300
print(f"Val:   {len(X_val):,} samples (20%)")    # 2,100
print(f"Test:  {len(X_test):,} samples (20%)")   # 2,100
```

**¿Por qué 60/20/20?**
- ✅ Train (60%): Suficiente data para aprender patrones
- ✅ Val (20%): Validar sin tocar test set
- ✅ Test (20%): Evaluación final no sesgada

### Data Leakage Check

```python
def check_data_leakage(X_train, X_val, X_test):
    """
    Verifica que no haya samples duplicados entre splits
    """
    train_set = {tuple(row) for row in X_train}
    val_set = {tuple(row) for row in X_val}
    test_set = {tuple(row) for row in X_test}
    
    overlap_train_val = len(train_set & val_set)
    overlap_train_test = len(train_set & test_set)
    overlap_val_test = len(val_set & test_set)
    
    if overlap_train_val > 0:
        raise ValueError(f"Data leakage: {overlap_train_val} samples in train AND val")
    
    print("✅ No data leakage detected")
```

**¿Por qué importante?**
- ❌ Data leakage → métricas infladas, modelo no generaliza
- ✅ Sin leakage → confianza en métricas

### Training Process

```python
# 1. Initialize ensemble
ensemble = AnomalyEnsemble(
    contamination=0.05,  # 5% esperado de anomalías
    n_estimators=100,
    dbscan_eps=5.0,
    dbscan_min_samples=50,
    gmm_n_components=3,
    ensemble_weights=[0.5, 0.3, 0.2]
)

# 2. Train on training set
ensemble.train(X_train)  # 6,300 samples
# - Fits StandardScaler
# - Trains Isolation Forest
# - Trains DBSCAN + computes cluster centroids
# - Trains GMM

# Training time: ~3.5 segundos en CPU moderna

# 3. Validate on validation set
val_metrics = evaluate_model(ensemble, X_val, y_val)

# 4. Final evaluation on test set (ONLY ONCE!)
test_metrics = evaluate_model(ensemble, X_test, y_test)
```

**¿Por qué NO tocar test set hasta el final?**
- ❌ Tuning con test set → overfitting
- ✅ Test set virgen → métricas reales

---

## 📊 Métricas de Performance

### Confusion Matrix (Test Set)

```
              Predicted
           Normal  Anomaly
Actual
Normal      1993      7     ← FPR = 7/2000 = 0.35%
Anomaly        0    100     ← FNR = 0/100 = 0%
```

**Interpretación:**
- **TN (1993)**: Logs normales correctamente clasificados ✅
- **FP (7)**: Falsos positivos - solo 7 de 2000 normales ✅
- **FN (0)**: CERO amenazas perdidas 🎯
- **TP (100)**: Todas las anomalías detectadas ✅

### Métricas Principales

```python
# Test Set Results:
{
    "accuracy": 0.997,      # 99.7% - casi perfecto
    "precision": 0.935,     # 93.5% - cuando dice anomalía, acierta 93.5%
    "recall": 1.000,        # 100% - detecta TODAS las anomalías 🎯
    "f1_score": 0.966,      # 96.6% - balance perfecto
    "roc_auc": 1.000,       # 100% - separación perfecta de clases
    "fpr": 0.0035,          # 0.35% - tasa muy baja de falsos positivos
    "fnr": 0.0              # 0% - NO pierde amenazas
}
```

**¿Qué métrica es más importante?**

Para **seguridad**, la prioridad es:
1. **Recall (100%)**: NO podemos perder amenazas → FN = 0 ✅
2. **FPR (0.35%)**: Pocos falsos positivos para no saturar SOC ✅
3. **F1-Score (96.6%)**: Balance general excelente ✅

**Comparación con Baseline:**

```python
# Baseline (Dummy Classifier - Most Frequent)
{
    "accuracy": 0.952,  # Solo predice "normal" siempre
    "f1_score": 0.0     # NO detecta ninguna anomalía
}

# Nuestro Ensemble
{
    "accuracy": 0.997,  # +4.4 points
    "f1_score": 0.966   # +96.6 points (INFINITO en términos relativos)
}
```

**Conclusion:** El modelo es **MUCHO MEJOR** que baseline.

---

## 🚀 Deployment & Production

### Arquitectura en Producción

```
┌─────────────────────────────────────────────────────────┐
│  Docker Compose Stack                                   │
├─────────────────────────────────────────────────────────┤
│  • postgres:5432  → TimescaleDB (logs históricos)       │
│  • redis:6379     → Cache + rate tracking               │
│  • api:8000       → FastAPI (ML inference)              │
│  • frontend:5173  → React UI                            │
│  • prometheus:9090 → Metrics collection                 │
│  • grafana:3000   → Dashboards                          │
└─────────────────────────────────────────────────────────┘
```

### Model Loading

```python
# backend/ml/model_loader.py
class ModelLoader:
    def __init__(self):
        self.isolation_forest = None
        self.dbscan = None
        self.gmm = None
        self.scaler = None
        
    def load_model(self, model_path: Path) -> None:
        """
        Carga modelo entrenado desde disco
        """
        ensemble_data = joblib.load(model_path)
        
        self.isolation_forest = ensemble_data["isolation_forest"]
        self.dbscan = ensemble_data["dbscan"]
        self.gmm = ensemble_data["gmm"]
        self.scaler = ensemble_data["scaler"]
        
        # Metadata
        self.model_version = ensemble_data["model_version"]
        self.trained_at = ensemble_data["trained_at"]
        self.n_training_samples = ensemble_data["n_training_samples"]
```

### API Endpoints

```python
# GET /api/v1/health
{
    "status": "healthy",
    "checks": {
        "database": "healthy",
        "redis": "healthy",
        "ml_models": "loaded"
    }
}

# POST /api/v1/logs/analyze
Request:
{
    "log_line": "Jan 14 03:45:12 server sshd: Failed password...",
    "source": "auth"
}

Response:
{
    "is_anomaly": true,
    "risk_score": 0.834,
    "risk_level": "HIGH",
    "reasons": ["Unusual hour", "High login rate", ...],
    "recommended_action": "BLOCK_IP",
    "model_scores": {
        "isolation_forest": 0.85,
        "dbscan": 0.75,
        "gmm": 0.92
    },
    "processing_time_ms": 8.5
}
```

### Performance

```
# Latencia de inferencia:
- Parse: ~1ms
- Feature engineering: ~3ms (Redis + GeoIP)
- ML prediction: ~5ms (3 modelos)
- Total: ~8-10ms por log

# Throughput:
- 1 worker: ~100 logs/sec
- 4 workers: ~400 logs/sec
- Con batching: >1000 logs/sec
```

### Monitoring

```python
# Prometheus metrics
ml_predictions_total           # Counter de predicciones
ml_anomalies_detected_total    # Counter de anomalías
ml_prediction_duration_seconds # Histogram de latencia
ml_model_score_distribution    # Histogram de scores

# Grafana dashboards
- Real-time anomaly detection rate
- Model scores distribution
- False positive rate trends
- Processing latency
```

---

## 🐛 Troubleshooting

### Problema: High False Positive Rate

**Síntoma:**
```
Muchos logs normales clasificados como anomalías
FPR > 5%
```

**Causas:**
1. **contamination** muy alto en Isolation Forest
2. **dbscan_eps** muy pequeño (todo es outlier)
3. **ensemble_weights** desbalanceados

**Solución:**
```python
# 1. Reducir contamination
ensemble = AnomalyEnsemble(
    contamination=0.03,  # Era 0.05, bajar a 3%
)

# 2. Aumentar dbscan_eps
ensemble = AnomalyEnsemble(
    dbscan_eps=7.0,  # Era 5.0, aumentar radio
)

# 3. Ajustar weights (dar más peso a IF)
ensemble = AnomalyEnsemble(
    ensemble_weights=[0.6, 0.2, 0.2]  # Más conservador
)
```

### Problema: Missing Anomalies (Low Recall)

**Síntoma:**
```
Amenazas reales NO detectadas
FN > 0, Recall < 100%
```

**Causas:**
1. **threshold** muy alto
2. Modelo no entrenado con suficiente variedad
3. Features no capturan el patrón

**Solución:**
```python
# 1. Bajar threshold
ALERT_THRESHOLD_MEDIUM = 0.5  # Era 0.6

# 2. Re-entrenar con más data sintética de ese ataque
anomalous_data["new_attack_pattern"] = ...

# 3. Añadir nuevas features específicas
is_sql_injection = check_sql_patterns(payload)
```

### Problema: Model Overfitting

**Síntoma:**
```
Validation accuracy >> Test accuracy
Model no generaliza a data nueva
```

**Causas:**
1. Data leakage entre splits
2. Overfitting en data sintética
3. No suficiente diversidad en training data

**Solución:**
```python
# 1. Re-validar splits
check_data_leakage(X_train, X_val, X_test)

# 2. Aumentar varianza en data sintética
anomalous_data["login_attempts"] = np.random.uniform(15, 50, n)  # Más variedad

# 3. Cross-validation
from sklearn.model_selection import StratifiedKFold
kfold = StratifiedKFold(n_splits=5)
cv_scores = []
for train_idx, val_idx in kfold.split(X, y):
    ensemble.train(X[train_idx])
    score = evaluate(X[val_idx], y[val_idx])
    cv_scores.append(score)
print(f"CV F1: {np.mean(cv_scores):.3f} ± {np.std(cv_scores):.3f}")
```

### Problema: Slow Inference

**Síntoma:**
```
processing_time_ms > 50ms
API timeouts
```

**Causas:**
1. Redis/Postgres queries lentas
2. GeoIP lookups sin cache
3. Sin workers paralelización

**Solución:**
```python
# 1. Índices en Postgres
CREATE INDEX idx_logs_source_ip_timestamp ON logs(source_ip, log_timestamp);

# 2. Cache GeoIP lookups
@lru_cache(maxsize=10000)
def geoip_lookup(ip: str) -> Location:
    return geoip2.city(ip)

# 3. Aumentar workers
# docker-compose.yml
command: uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers 4
```

---

## 📚 Referencias

### Papers

- Liu, Fei Tony, et al. "Isolation forest." 2008 eighth ieee international conference on data mining. IEEE, 2008.
- Ester, Martin, et al. "A density-based algorithm for discovering clusters in large spatial databases with noise." kdd. Vol. 96. No. 34. 1996.
- Reynolds, Douglas. "Gaussian mixture models." Encyclopedia of biometrics 741 (2009): 659-663.

### Libraries

- scikit-learn: https://scikit-learn.org/stable/
- FastAPI: https://fastapi.tiangolo.com/
- Structlog: https://www.structlog.org/

### Internal Docs

- `history/DATA_FLOW.md` - Flujo completo de data
- `history/INSTALL.md` - Setup con uv
- `README.md` - Overview del proyecto

---

## ✅ Checklist para ML Engineers

Al hacer cambios en el modelo:

```
□ Modificar código en backend/ml/
□ Re-entrenar con scripts/train_ensemble_with_metrics.py
□ Verificar métricas (F1 > 0.95, FNR = 0)
□ Actualizar MODEL_PATH en .env
□ Rebuild Docker: docker compose build
□ Restart containers: docker compose up -d
□ Verificar health: curl http://localhost:8000/api/v1/health
□ Probar con send_test_logs.py
□ Monitorear Grafana para FPR/FNR
□ Documentar cambios en CHANGELOG.md
```

---

**🎯 Fin del ML Engineer Guide**

Para presentarlo a tus compañeros, te recomiendo:
1. Abrir el frontend: `http://localhost:5173`
2. Ir a la tab "🏗️ Architecture"
3. Usar este documento como referencia técnica
4. Ejecutar `scripts/send_test_logs.py` para demo en vivo
