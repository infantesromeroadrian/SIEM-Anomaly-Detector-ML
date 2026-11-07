"""API tests. The app is used without its lifespan, so no PostgreSQL/Redis is needed."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from types import SimpleNamespace

import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.ml.ensemble import AnomalyEnsemble
from backend.ml.features import FEATURE_NAMES
from backend.ml.model_loader import get_model_loader


@pytest.fixture
def client(reset_singletons):
    return TestClient(app)


@pytest.fixture
def loaded_model(reset_singletons):
    """Install a small trained model into the loader singleton."""
    ens = AnomalyEnsemble(
        ensemble_weights=[0.5, 0.3, 0.2], random_state=0, dbscan_min_samples=5, dbscan_eps=3.0
    )
    ens.train(np.random.default_rng(0).normal(1, 0.3, (200, len(FEATURE_NAMES))).astype(np.float32))
    loader = get_model_loader()
    loader.isolation_forest = ens.isolation_forest
    loader.dbscan = ens.dbscan
    loader.gmm = ens.gmm
    loader.scaler = ens.scaler
    loader._cluster_centroids = ens._cluster_centroids
    loader.metadata = {"training_date": "test"}
    return loader


def test_liveness(client):
    r = client.get("/api/v1/live")
    assert r.status_code == 200 and r.json() == {"status": "alive"}


def test_health_reports_unloaded_model_and_real_dependency_failures(client):
    r = client.get("/api/v1/health")
    body = r.json()
    assert r.status_code == 200
    assert body["status"] == "degraded"
    assert body["checks"]["ml_models"]["status"] == "unloaded"
    # No database / Redis in this environment: the probes must say so instead of faking "healthy".
    assert body["checks"]["database"]["status"] == "unhealthy"
    assert body["checks"]["redis"]["status"] == "unhealthy"


def test_health_with_model_loaded(client, loaded_model):
    assert client.get("/api/v1/health").json()["checks"]["ml_models"]["status"] == "healthy"


def test_readiness_false_without_dependencies(client):
    body = client.get("/api/v1/ready").json()
    assert body["ready"] is False
    assert body["services"]["ml_models"] is False


def test_analyze_without_model_is_503(client):
    r = client.post("/api/v1/logs/analyze", json={"log_line": "x" * 20, "source": "nginx"})
    assert r.status_code == 503


def test_analyze_ingestion(client, loaded_model, access_lines):
    r = client.post("/api/v1/logs/analyze", json={"log_line": access_lines[0], "source": "nginx"})
    assert r.status_code == 200
    body = r.json()
    assert 0 <= body["risk_score"] <= 1
    assert set(body["model_scores"]) == {"isolation_forest", "dbscan", "gmm"}
    assert "geographic" not in body["features"]
    assert body["risk_level"] in {"normal", "low", "medium", "high", "critical"}


def test_analyze_rejects_empty_and_bad_source(client):
    assert (
        client.post("/api/v1/logs/analyze", json={"log_line": "", "source": "nginx"}).status_code
        == 422
    )
    r = client.post("/api/v1/logs/analyze", json={"log_line": "x" * 20, "source": "bogus"})
    assert r.status_code == 422


def test_batch_ingestion(client, loaded_model, access_lines):
    logs = [{"log_line": line, "source": "nginx"} for line in access_lines[:3]]
    r = client.post("/api/v1/logs/batch", json={"logs": logs})
    assert r.status_code == 200
    body = r.json()
    assert body["total_logs"] == 3
    assert len(body["results"]) == 3


def test_batch_without_model_is_503(client, access_lines):
    r = client.post(
        "/api/v1/logs/batch", json={"logs": [{"log_line": access_lines[0], "source": "nginx"}]}
    )
    assert r.status_code == 503


class _Result:
    def __init__(self, scalar=None, rows=None):
        self._scalar, self._rows = scalar, rows or []

    def scalar(self):
        return self._scalar

    def scalar_one(self):
        return self._scalar

    def scalars(self):
        return SimpleNamespace(all=lambda: self._rows)


def _fake_db(results):
    queue = list(results)

    class Session:
        async def execute(self, *_a, **_k):
            return queue.pop(0)

    @asynccontextmanager
    async def get_db():
        yield Session()

    return get_db


def test_anomalies_endpoint_with_stubbed_database(client, monkeypatch):
    row = SimpleNamespace(
        id=1,
        risk_score=0.9,
        risk_level="high",
        confidence="high",
        features={"a": 1},
        reasons=["r"],
        recommended_action="MONITOR",
        isolation_forest_score=0.9,
        dbscan_score=0.9,
        gmm_score=0.9,
        processing_time_ms=1.0,
        created_at=datetime.now(timezone.utc),
    )
    monkeypatch.setattr(
        "backend.db.database.get_db", _fake_db([_Result(scalar=1), _Result(rows=[row])])
    )
    r = client.get("/api/v1/anomalies?limit=5")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1 and body["anomalies"][0]["risk_level"] == "high"


def test_stats_without_database_is_503_not_invented_numbers(client):
    r = client.get("/api/v1/stats")
    assert r.status_code == 503


def test_stats_with_stubbed_database(client, monkeypatch):
    monkeypatch.setattr(
        "backend.api.routes.stats.get_db", _fake_db([_Result(scalar=200), _Result(scalar=10)])
    )
    body = client.get("/api/v1/stats").json()
    assert body["logs_analyzed_24h"] == 200
    assert body["anomalies_detected_24h"] == 10
    assert body["anomaly_rate"] == 0.05


def test_timeseries_without_database_is_503_not_random_data(client):
    assert client.get("/api/v1/stats/timeseries?hours=2").status_code == 503
