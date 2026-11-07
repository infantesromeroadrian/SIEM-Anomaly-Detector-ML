# SIEM Anomaly Detector - Architecture

> Note: diagrams below show the original three-model ensemble. Since the evaluation, the default configuration scores with Isolation Forest only (weights `1.0,0.0,0.0`); DBSCAN and GMM are opt-in. See ML_ARCHITECTURE.md.

## System Overview

```
                                    SIEM ANOMALY DETECTOR
    ============================================================================
    
                                   +------------------+
                                   |   Log Sources    |
                                   +------------------+
                                   | - Syslog         |
                                   | - Auth (SSH)     |
                                   | - Apache/Nginx   |
                                   | - Firewall       |
                                   | - Custom         |
                                   +--------+---------+
                                            |
                                            v
    +------------------+           +------------------+           +------------------+
    |     Frontend     |           |      API         |           |    Monitoring    |
    +------------------+   REST    +------------------+           +------------------+
    | React + TS       |<--------->| FastAPI          |           | Prometheus :9090 |
    | Vite             |   :8000   | Async/Await      |---------->| Grafana    :3000 |
    | Dashboard        |           | Structlog        |  metrics  |                  |
    | Recharts         |           +--------+---------+           +------------------+
    | :5173            |                    |
    +------------------+                    |
                                            v
                              +---------------------------+
                              |      ML Ensemble          |
                              +---------------------------+
                              |                           |
                              |  +---------------------+  |
                              |  | Isolation Forest    |  |
                              |  | (50% weight)        |  |
                              |  +---------------------+  |
                              |            +              |
                              |  +---------------------+  |
                              |  | DBSCAN              |  |
                              |  | (30% weight)        |  |
                              |  +---------------------+  |
                              |            +              |
                              |  +---------------------+  |
                              |  | GMM                 |  |
                              |  | (20% weight)        |  |
                              |  +---------------------+  |
                              |            |              |
                              |            v              |
                              |    Final Risk Score       |
                              |    (0.0 - 1.0)            |
                              +-------------+-------------+
                                            |
                              +-------------+-------------+
                              |                           |
                              v                           v
                    +------------------+       +------------------+
                    |   PostgreSQL     |       |      Redis       |
                    +------------------+       +------------------+
                    | TimescaleDB      |       | Cache            |
                    | Anomalies Table  |       | Rate Limiting    |
                    | Logs Table       |       | Session Data     |
                    | Alerts Table     |       | :6379            |
                    | :5432            |       +------------------+
                    +------------------+
```

---

## Component Diagram (Mermaid)

```mermaid
graph TB
    subgraph "External"
        LS[("Log Sources<br/>Syslog, SSH, Apache,<br/>Nginx, Firewall")]
    end
    
    subgraph "Frontend Layer"
        FE["React Dashboard<br/>:5173"]
    end
    
    subgraph "API Layer"
        API["FastAPI<br/>:8000"]
        PARSE["Log Parsers<br/>Syslog, Auth, Nginx"]
        FEAT["Feature<br/>Engineering"]
    end
    
    subgraph "ML Layer"
        ENS["Ensemble Model"]
        IF["Isolation Forest<br/>50%"]
        DB["DBSCAN<br/>30%"]
        GMM["GMM<br/>20%"]
    end
    
    subgraph "Data Layer"
        PG[("PostgreSQL<br/>TimescaleDB<br/>:5432")]
        RD[("Redis<br/>Cache<br/>:6379")]
    end
    
    subgraph "Monitoring"
        PROM["Prometheus<br/>:9090"]
        GRAF["Grafana<br/>:3000"]
    end
    
    LS --> API
    FE <--> API
    API --> PARSE
    PARSE --> FEAT
    FEAT --> ENS
    ENS --> IF
    ENS --> DB
    ENS --> GMM
    IF --> ENS
    DB --> ENS
    GMM --> ENS
    ENS --> API
    API <--> PG
    API <--> RD
    API --> PROM
    PROM --> GRAF
    
    style LS fill:#ff6b6b,color:#fff
    style FE fill:#4ecdc4,color:#fff
    style API fill:#45b7d1,color:#fff
    style ENS fill:#96ceb4,color:#fff
    style IF fill:#ffeaa7,color:#333
    style DB fill:#dfe6e9,color:#333
    style GMM fill:#fd79a8,color:#fff
    style PG fill:#6c5ce7,color:#fff
    style RD fill:#e17055,color:#fff
    style PROM fill:#fdcb6e,color:#333
    style GRAF fill:#00b894,color:#fff
```

---

## Data Flow Diagram

```mermaid
sequenceDiagram
    participant LS as Log Source
    participant API as FastAPI
    participant PARSE as Parser
    participant FEAT as Features
    participant ML as Ensemble
    participant DB as PostgreSQL
    participant CACHE as Redis
    participant FE as Frontend
    
    LS->>API: POST /api/v1/logs/analyze
    API->>PARSE: Parse log line
    PARSE->>FEAT: Extract 21 features
    FEAT->>ML: Predict anomaly
    
    ML->>ML: Isolation Forest (50%)
    ML->>ML: DBSCAN (30%)
    ML->>ML: GMM (20%)
    ML->>ML: Combine scores
    
    ML-->>API: risk_score, is_anomaly
    
    alt is_anomaly == true
        API->>DB: INSERT anomaly
        API->>CACHE: Cache alert
    end
    
    API-->>LS: JSON Response
    
    FE->>API: GET /api/v1/stats
    API->>DB: Query aggregates
    DB-->>API: Stats data
    API-->>FE: Dashboard data
```

---

## ML Ensemble Architecture

```mermaid
graph LR
    subgraph "Input"
        LOG["Raw Log<br/>'Failed password for root...'"]
    end
    
    subgraph "Parsing"
        P1["Syslog Parser"]
        P2["Auth Parser"]
        P3["Nginx Parser"]
        P4["Firewall Parser"]
    end
    
    subgraph "Feature Engineering"
        F["21 deterministic features<br/>- hour_of_day<br/>- requests_per_second (60 s window)<br/>- error_rate_4xx (5 min window)<br/>- payload_entropy<br/>- ..."]
    end
    
    subgraph "Ensemble"
        SC["StandardScaler"]
        IF["Isolation Forest<br/>n_estimators=100<br/>contamination=0.03"]
        DBSCAN["DBSCAN<br/>eps=5.0<br/>min_samples=50"]
        GMM["GMM<br/>n_components=3"]
    end
    
    subgraph "Aggregation"
        W["Weighted Average<br/>0.5×IF + 0.3×DBSCAN + 0.2×GMM"]
        TH["Threshold<br/>≥0.6 = Anomaly"]
    end
    
    subgraph "Output"
        OUT["Risk Score: 0.82<br/>Is Anomaly: true<br/>Confidence: high"]
    end
    
    LOG --> P1 & P2 & P3 & P4
    P1 & P2 & P3 & P4 --> F
    F --> SC
    SC --> IF & DBSCAN & GMM
    IF --> W
    DBSCAN --> W
    GMM --> W
    W --> TH
    TH --> OUT
    
    style LOG fill:#ff6b6b,color:#fff
    style F fill:#4ecdc4,color:#fff
    style IF fill:#ffeaa7,color:#333
    style DBSCAN fill:#74b9ff,color:#fff
    style GMM fill:#fd79a8,color:#fff
    style OUT fill:#00b894,color:#fff
```

---

## Docker Services Architecture

```mermaid
graph TB
    subgraph "Docker Network: siem-network"
        subgraph "Core Services"
            API["siem-api<br/>:8000"]
            FE["siem-frontend<br/>:5173"]
        end
        
        subgraph "Data Services"
            PG["siem-postgres<br/>:5432<br/>TimescaleDB"]
            RD["siem-redis<br/>:6379"]
        end
        
        subgraph "Monitoring Services"
            PROM["siem-prometheus<br/>:9090"]
            GRAF["siem-grafana<br/>:3000"]
        end
    end
    
    subgraph "Volumes"
        V1[("postgres_data")]
        V2[("redis_data")]
        V3[("grafana_data")]
        V4[("prometheus_data")]
    end
    
    PG --- V1
    RD --- V2
    GRAF --- V3
    PROM --- V4
    
    API --> PG
    API --> RD
    API --> PROM
    FE --> API
    PROM --> GRAF
    
    style API fill:#45b7d1,color:#fff
    style FE fill:#4ecdc4,color:#fff
    style PG fill:#6c5ce7,color:#fff
    style RD fill:#e17055,color:#fff
    style PROM fill:#fdcb6e,color:#333
    style GRAF fill:#00b894,color:#fff
```

---

## Feature Categories

The authoritative list is `FEATURE_NAMES` in `backend/ml/features.py`. All features are deterministic and
causal (an event only sees itself and earlier events); per-IP windows are held in memory.

| Group | Features |
|---|---|
| Temporal (4) | hour_of_day, day_of_week, is_weekend, is_business_hours |
| Per-IP activity (4) | login_attempts_per_minute, requests_per_second (60 s), unique_ips_last_hour, unique_endpoints_accessed (5 min) |
| Per-IP ratios, 5 min (3) | failed_auth_rate, error_rate_4xx, error_rate_5xx |
| Event content (7) | status_class, is_known_ip, bytes_transferred, time_since_last_activity_sec, path_length, special_char_ratio, payload_entropy |
| Context (3) | is_privileged_user, is_sensitive_endpoint, is_known_user_agent |

Earlier versions also had geographic distance, country and session-duration features; they were filled with
random numbers (no GeoIP or session tracking existed) and have been removed.

---

## Ports Reference

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| Frontend | 5173 | HTTP | React Dashboard |
| API | 8000 | HTTP | FastAPI REST API |
| PostgreSQL | (internal) | TCP | TimescaleDB; not published to the host |
| Redis | (internal) | TCP | Connectivity probe only; not published to the host |
| Prometheus | 9090 | HTTP | Metrics Collection |
| Grafana | 3000 | HTTP | Monitoring Dashboards |

---

## Technology Stack

```
+------------------+------------------+------------------+
|     FRONTEND     |     BACKEND      |   INFRASTRUCTURE |
+------------------+------------------+------------------+
| React 18         | Python 3.10+     | Docker           |
| TypeScript       | FastAPI          | Docker Compose   |
| Vite             | SQLAlchemy       | PostgreSQL 15    |
| Recharts         | AsyncPG          | TimescaleDB      |
| CSS3             | Pydantic v2      | Redis            |
|                  | Structlog        | Prometheus       |
|                  | scikit-learn     | Grafana          |
|                  | NumPy/Pandas     |                  |
+------------------+------------------+------------------+
```

---

## Security Boundaries

```
    EXTERNAL                    DMZ                         INTERNAL
    ========                    ===                         ========
    
    +--------+            +------------+              +---------------+
    | Logs   |  --------> | API :8000  | -----------> | PostgreSQL    |
    | (Any   |    REST    | (Validates |    SQL       | (Encrypted)   |
    | Source)|            |  & Parses) |              +---------------+
    +--------+            +------------+                     ^
                                |                            |
    +--------+            +------------+              +---------------+
    | Users  |  --------> | Frontend   | -----------> | Redis         |
    | (SOC   |   HTTPS    | :5173      |   Cache      | (Auth)        |
    | Analyst|            | (Auth*)    |              +---------------+
    +--------+            +------------+
    
    * Authentication: TODO (JWT planned)
```

---

## Deployment Options

```mermaid
graph TB
    subgraph "Development"
        DEV["docker compose up"]
    end
    
    subgraph "Production - Single Node"
        PROD1["Docker Compose<br/>+ Reverse Proxy<br/>(Nginx/Traefik)"]
    end
    
    subgraph "Production - Kubernetes"
        K8S["Helm Chart<br/>+ Ingress<br/>+ HPA"]
    end
    
    subgraph "Cloud Managed"
        AWS["AWS ECS/EKS<br/>+ RDS + ElastiCache"]
        GCP["GCP Cloud Run<br/>+ Cloud SQL"]
        AZ["Azure AKS<br/>+ Azure DB"]
    end
    
    DEV --> PROD1
    PROD1 --> K8S
    K8S --> AWS & GCP & AZ
```

---

## File Structure

```
SIEM-Anomaly-Detector-ML/
├── backend/
│   ├── api/routes/          # REST endpoints
│   ├── db/                  # Database models & CRUD
│   ├── ml/                  # ensemble, features, scoring
│   ├── eval/                # dataset fetch, protocol, metrics
│   ├── parsers/             # Log parsers
│   ├── main.py              # FastAPI app
│   └── config.py            # Settings
├── frontend/
│   ├── src/
│   │   ├── components/      # React components
│   │   ├── services/        # API client
│   │   └── App.tsx          # Main app
│   └── vite.config.ts
├── docs/
│   ├── ARCHITECTURE.md      # This file
│   └── ML_ARCHITECTURE.md   # ML details
├── scripts/
│   ├── train_demo_model.py  # synthetic DEMO model for the container
│   ├── benchmark.py         # throughput measurement
│   └── log_generator.py     # DEMO ONLY synthetic traffic
├── tests/                   # pytest suite
├── results/                 # generated evaluation artefacts
├── monitoring/
│   ├── prometheus.yml
│   └── grafana/
├── docker-compose.yml       # Full stack
└── README.md
```

---

*Updated 2026-11-07 to match the code; diagrams above that mention eps=5.0 are illustrative, defaults are in `.env.example`.*
