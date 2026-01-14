# 🧠 ML Architecture - SIEM Anomaly Detector

**Machine Learning Ensemble for Real-time Security Log Anomaly Detection**

---

## 📋 Overview

El sistema ML del SIEM utiliza un **ensemble de 3 algoritmos complementarios** basados en los notebooks del módulo de clustering:

```
Log Entry → Feature Engineering → ML Ensemble → Anomaly Score
                                    ├─ Isolation Forest (50%)
                                    ├─ DBSCAN (30%)
                                    └─ GMM (20%)
```

---

## 🏗️ Architecture

### 1. Feature Engineering (`backend/ml/features.py`)

**Entrada**: Log parseado (dict)  
**Salida**: Vector de 21 features normalizadas

#### Feature Categories

**Temporal** (4 features):
- `hour_of_day` (0-23): Detecta actividad en horas inusuales
- `day_of_week` (0-6): Patrones día laboral vs weekend
- `is_weekend` (bool): Flag de fin de semana
- `is_business_hours` (bool): Actividad dentro de 9 AM - 6 PM

**Frequency** (4 features):
- `login_attempts_per_minute`: Detecta brute force
- `requests_per_second`: Detecta DDoS/flooding
- `unique_ips_last_hour`: Actividad distribuida
- `unique_endpoints_accessed`: Port scanning

**Rates** (3 features):
- `failed_auth_rate` (0.0-1.0): Tasa de fallos de autenticación
- `error_rate_4xx` (0.0-1.0): Errores cliente
- `error_rate_5xx` (0.0-1.0): Errores servidor

**Geographic** (3 features):
- `geographic_distance_km`: Distancia desde ubicación habitual
- `is_known_country` (bool): País en whitelist
- `is_known_ip` (bool): IP en whitelist

**Behavioral** (4 features):
- `bytes_transferred` (log scale): Volumen de datos
- `time_since_last_activity_sec`: Patrón de actividad
- `session_duration_sec`: Duración de sesión
- `payload_entropy` (0-8): Shannon entropy (detecta cifrado)

**Context** (3 features):
- `is_privileged_user` (bool): Usuario con privilegios
- `is_sensitive_endpoint` (bool): Endpoint crítico
- `is_known_user_agent` (bool): User-agent legítimo

---

### 2. ML Ensemble (`backend/ml/ensemble.py`)

#### 2.1 Isolation Forest (Weight: 0.5)

**Basado en**: `notebooks/03-clustering/05-isolation-forest-fraude.ipynb`

```python
IsolationForest(
    contamination=0.03,  # 3% esperado de anomalías
    n_estimators=100,
    max_samples='auto',
    random_state=42
)
```

**Características**:
- ✅ **NO requiere escalado** (invariante a escala)
- ✅ Complejidad lineal O(n)
- ✅ Mejor para outliers extremos
- ✅ Rápido en predicción (<10ms)

**Score Calculation**:
```python
if_decision = model.decision_function(X)  # Negativo = más anómalo
if_score = 1.0 / (1.0 + np.exp(if_decision * 10))  # Sigmoid [0, 1]
```

**Uso**: Detección rápida de comportamientos extremadamente inusuales (brute force, port scanning).

---

#### 2.2 DBSCAN (Weight: 0.3)

**Basado en**: `notebooks/03-clustering/02-dbscan-anomalias-logs.ipynb`

```python
DBSCAN(
    eps=1.5,
    min_samples=50,
    n_jobs=-1
)
```

**Características**:
- ✅ Detecta outliers (label=-1)
- ✅ Clusters de forma irregular
- ✅ No requiere especificar K
- ❌ Requiere escalado (StandardScaler)

**Score Calculation**:
```python
if prediction == -1:  # Outlier
    dbscan_score = 0.9
else:  # Part of cluster
    distance_to_centroid = norm(X - cluster_center)
    dbscan_score = min(distance_to_centroid / 10.0, 1.0)
```

**Uso**: Detecta ataques coordinados (DDoS distribuido, APT multi-stage).

---

#### 2.3 Gaussian Mixture Model (Weight: 0.2)

**Basado en**: `notebooks/03-clustering/04-gmm-perfiles-usuario.ipynb`

```python
GaussianMixture(
    n_components=3,
    covariance_type='full',
    random_state=42,
    n_init=10
)
```

**Características**:
- ✅ Probabilístico (soft clustering)
- ✅ Proporciona confianza
- ✅ Clusters elípticos (más flexibles que K-Means)
- ❌ Requiere escalado

**Score Calculation**:
```python
log_likelihood = model.score_samples(X)  # Más negativo = más anómalo
gmm_score = 1.0 / (1.0 + np.exp((log_likelihood + 10) * 0.5))  # Normalizado
```

**Uso**: Detecta desviaciones sutiles del comportamiento normal (insider threats, privilege escalation).

---

### 3. Ensemble Aggregation

#### Weighted Average

```python
final_score = (
    0.5 * if_score +      # Isolation Forest (50%)
    0.3 * dbscan_score +  # DBSCAN (30%)
    0.2 * gmm_score       # GMM (20%)
)
```

**Justificación de pesos**:
- **IF (50%)**: Mejor para outliers extremos (mayoría de ataques)
- **DBSCAN (30%)**: Complementa con patrones coordinados
- **GMM (20%)**: Añade sensibilidad a desviaciones sutiles

#### Confidence Calculation

```python
scores = [if_score, dbscan_score, gmm_score]
score_std = np.std(scores)

if score_std < 0.1:
    confidence = "high"    # Modelos concuerdan
elif score_std < 0.2:
    confidence = "medium"  # Modelos difieren moderadamente
else:
    confidence = "low"     # Modelos discrepan (investigar)
```

#### Risk Level Classification

```python
if final_score >= 0.8:
    risk_level = "high"         # Bloquear inmediatamente
    action = "BLOCK_IP"
elif final_score >= 0.6:
    risk_level = "medium"       # Requiere MFA
    action = "REQUIRE_MFA"
elif final_score >= 0.4:
    risk_level = "low"          # Monitorear
    action = "MONITOR"
else:
    risk_level = "normal"       # Sin acción
    action = "NO_ACTION"
```

---

## 🎓 Training Process

### 1. Data Generation (`scripts/train_ensemble.py`)

```bash
python scripts/train_ensemble.py
```

**Synthetic Data**:
- 9,700 normal samples (97%)
- 300 anomalous samples (3%)
- 21 features per sample

**Normal Behavior**:
- Business hours (9 AM - 6 PM)
- Low login attempts (1 ± 0.5 per minute)
- Low failed auth rate (5% ± 3%)
- Known IPs/countries
- Typical session durations

**Anomalous Behavior**:
- Unusual hours (night/weekend)
- High login attempts (10-30 per minute)
- High failed auth rate (70-100%)
- Foreign IPs/unknown countries
- Short session durations
- High payload entropy (encrypted traffic)

### 2. Model Training

```python
ensemble = AnomalyEnsemble(
    contamination=0.03,
    n_estimators=100,
    ensemble_weights=[0.5, 0.3, 0.2]
)

ensemble.train(X_train)
ensemble.save(Path("./models"))
```

### 3. Model Persistence

```python
# Save
ensemble.save(Path("./models"))
# → models/ensemble_20260113_233000.joblib

# Load
ensemble = AnomalyEnsemble.load(Path("./models/ensemble_20260113_233000.joblib"))
```

**Saved State**:
- Isolation Forest model
- DBSCAN model (fitted on training data)
- GMM model
- StandardScaler (for DBSCAN/GMM)
- Ensemble weights
- Training metadata (timestamp, n_samples, version)

---

## 🚀 Inference Pipeline

### Real-time Prediction Flow

```
1. Log Entry (raw string)
   ↓
2. Parser (extract fields)
   ↓
3. FeatureEngineer.extract(parsed_log)
   ├─ Temporal features
   ├─ Frequency aggregations (from cache/Redis)
   ├─ Rates calculations
   ├─ Geographic lookups (GeoIP)
   ├─ Behavioral metrics
   └─ Context checks
   ↓
4. LogFeatures (21-dim vector)
   ↓
5. AnomalyEnsemble.predict(features)
   ├─ Isolation Forest (no scaling)
   ├─ DBSCAN (scaled)
   └─ GMM (scaled)
   ↓
6. Weighted aggregation
   ↓
7. AnomalyResult
   ├─ is_anomaly: bool
   ├─ risk_score: float (0-1)
   ├─ confidence: str
   ├─ important_features: list
   └─ recommended_action: str
```

### Performance Characteristics

- **Latency**: <100ms per log (target)
  - Feature extraction: ~20ms
  - ML prediction: ~50ms
  - Aggregation: ~10ms
  - API overhead: ~20ms

- **Throughput**: ~10 logs/sec per worker
  - Scale horizontally with more workers

- **Memory**: ~200 MB per worker
  - Models: ~50 MB (loaded once)
  - Feature cache: ~100 MB
  - API overhead: ~50 MB

---

## 📊 Evaluation Metrics

### Training Metrics

```python
from sklearn.metrics import precision_score, recall_score, f1_score

# Evaluate on test set
y_pred = [ensemble.predict(X[i]).is_anomaly for i in range(len(X_test))]

precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
```

**Target Metrics** (from clustering notebooks):
- Precision: >0.90 (minimize false positives)
- Recall: >0.85 (catch most anomalies)
- F1-Score: >0.87 (balance)

### Production Monitoring

**Prometheus Metrics** (`/metrics`):
```
siem_logs_analyzed_total{source="auth"}
siem_anomalies_detected_total{risk_level="high"}
siem_analysis_duration_seconds{quantile="0.95"}
siem_model_prediction_errors_total
```

**Grafana Dashboards**:
- Anomaly rate over time
- Distribution of risk scores
- Top IPs flagged
- Model score correlations

---

## 🔄 Model Retraining

### Scheduled Retraining

```python
# Celery task (daily at 2 AM)
@celery.task
def retrain_ensemble():
    # 1. Fetch last 24h logs from database
    logs = get_recent_logs(hours=24)
    
    # 2. Get feedback (confirmed true/false positives)
    feedback = get_feedback(hours=24)
    
    # 3. Re-extract features
    X_new = [feature_engineer.extract(log) for log in logs]
    
    # 4. Retrain ensemble
    ensemble.train(np.array(X_new))
    
    # 5. Save new model
    ensemble.save(models_dir)
```

### Online Learning (Future)

```python
# Incremental update with new feedback
ensemble.partial_fit(X_new, feedback)
```

---

## 🎯 Feature Importance

### Global Importance (Averaged)

```python
# Based on SHAP values or permutation importance
important_features = [
    ("failed_auth_rate", 0.25),
    ("login_attempts_per_minute", 0.18),
    ("geographic_distance_km", 0.15),
    ("payload_entropy", 0.12),
    ("hour_of_day", 0.10),
    ...
]
```

### Per-Prediction Importance

```python
result = ensemble.predict(features)
print(result.important_features)
# [
#   ("login_attempts_per_minute", 2.8),  # 2.8 std deviations from mean
#   ("failed_auth_rate", 2.1),
#   ("hour_of_day", 1.9),
#   ...
# ]
```

---

## 🛠️ Configuration

### Environment Variables

```bash
# Model Hyperparameters
MODEL_CONTAMINATION=0.03
MODEL_N_ESTIMATORS=100
DBSCAN_EPS=1.5
DBSCAN_MIN_SAMPLES=50
GMM_N_COMPONENTS=3

# Ensemble Weights (must sum to 1.0)
ENSEMBLE_WEIGHTS=0.5,0.3,0.2

# Thresholds
ALERT_THRESHOLD_HIGH=0.8
ALERT_THRESHOLD_MEDIUM=0.6
ALERT_THRESHOLD_LOW=0.4

# Retraining
MODEL_RETRAIN_INTERVAL_HOURS=24
MODEL_MIN_FEEDBACK_COUNT=100
```

---

## 🔬 Experimental Features (Future)

### 1. Deep Learning (LSTM)

```python
# For sequence anomaly detection
from backend.ml.lstm import LSTMDetector

lstm = LSTMDetector(sequence_length=10)
lstm.train(log_sequences)
```

### 2. SHAP Explainability

```python
import shap

explainer = shap.TreeExplainer(ensemble.isolation_forest)
shap_values = explainer.shap_values(X)
```

### 3. Adversarial Robustness

```python
# Test against adversarial evasion
from backend.ml.adversarial import test_robustness

robustness_score = test_robustness(ensemble, X_test)
```

---

## 📚 References

### Notebooks (Training Foundation)

1. **Isolation Forest**: `notebooks/03-clustering/05-isolation-forest-fraude.ipynb`
   - Contamination tuning
   - Feature importance
   - ROC/PR curves

2. **DBSCAN**: `notebooks/03-clustering/02-dbscan-anomalias-logs.ipynb`
   - Eps determination (K-distance plot)
   - Outlier analysis
   - Comparison with K-Means

3. **GMM**: `notebooks/03-clustering/04-gmm-perfiles-usuario.ipynb`
   - BIC/AIC for component selection
   - Log-likelihood anomaly detection
   - Soft clustering interpretation

### Papers

- [Isolation Forest Paper (Liu et al., 2008)](https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf)
- [DBSCAN (Ester et al., 1996)](https://www.aaai.org/Papers/KDD/1996/KDD96-037.pdf)
- [Gaussian Mixture Models (Bishop, 2006)](https://www.microsoft.com/en-us/research/publication/pattern-recognition-machine-learning/)

---

**Author**: Adrian Infantes Romero  
**Version**: 1.0.0  
**Last Updated**: 2026-01-13
