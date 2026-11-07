from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np

import backend.ml.features as features
from backend.ml.features import (
    FEATURE_NAMES,
    FeatureEngineer,
    WindowedAggregator,
    shannon_entropy,
    special_char_ratio,
)

T0 = datetime(2022, 1, 24, 10, 0, tzinfo=timezone.utc)


def event(ip="10.0.0.1", dt=0, endpoint="/", status=200, **extra):
    return {
        "timestamp": T0 + timedelta(seconds=dt),
        "source_ip": ip,
        "endpoint": endpoint,
        "status_code": status,
        "bytes_sent": 100,
        "user_agent": "Mozilla/5.0",
        "event_type": "http_request",
        **extra,
    }


def test_vector_matches_feature_names():
    f = FeatureEngineer().extract_sync(event())
    arr = f.to_array()
    assert arr.shape == (len(FEATURE_NAMES),)
    assert arr.dtype == np.float32
    assert set(f.to_dict()) == {"temporal", "frequency", "rates", "behavioral", "context"}


def test_deterministic_across_instances():
    evs = [event(dt=i, endpoint=f"/p{i % 4}", status=404 if i % 3 == 0 else 200) for i in range(50)]
    a = np.stack([FeatureEngineer().extract_sync(e).to_array() for e in evs[:1]])
    fe1, fe2 = FeatureEngineer(), FeatureEngineer()
    x1 = np.stack([fe1.extract_sync(e).to_array() for e in evs])
    x2 = np.stack([fe2.extract_sync(e).to_array() for e in evs])
    assert np.array_equal(x1, x2)
    assert a.shape[1] == x1.shape[1]


def test_no_randomness_in_single_event():
    # Regression: geo/session features used to be np.random values.
    runs = [FeatureEngineer().extract_sync(event()).to_array() for _ in range(5)]
    assert all(np.array_equal(runs[0], r) for r in runs)


def test_burst_raises_request_rate_and_4xx_ratio():
    fe = FeatureEngineer()
    first = fe.extract_sync(event(dt=0))
    for i in range(1, 60):
        last = fe.extract_sync(event(dt=i * 0.5, status=404, endpoint=f"/x{i}"))
    assert last.requests_per_second > first.requests_per_second
    assert last.error_rate_4xx > 0.9
    assert last.unique_endpoints_accessed >= 50


def test_windows_forget_old_events():
    fe = FeatureEngineer()
    for i in range(30):
        fe.extract_sync(event(dt=i))
    late = fe.extract_sync(event(dt=10_000))
    assert late.requests_per_second == 1 / 60
    assert late.time_since_last_activity_sec == 3600.0  # capped


def test_per_ip_isolation():
    fe = FeatureEngineer()
    for i in range(20):
        fe.extract_sync(event(ip="10.0.0.1", dt=i))
    other = fe.extract_sync(event(ip="10.0.0.2", dt=21))
    assert other.requests_per_second == 1 / 60
    assert other.unique_ips_last_hour == 2


def test_auth_failure_ratio():
    fe = FeatureEngineer()
    for i in range(4):
        f = fe.extract_sync(event(dt=i, event_type="ssh_password_failed", endpoint=""))
    assert f.failed_auth_rate == 1.0
    assert f.login_attempts_per_minute == 4


def test_known_ip_and_context_flags():
    fe = FeatureEngineer(config={"known_ips": ["10.0.0.1"]})
    f = fe.extract_sync(event(endpoint="/wp-admin/x", username="ROOT"))
    assert f.is_known_ip and f.is_sensitive_endpoint and f.is_privileged_user
    assert not fe.extract_sync(event(ip="9.9.9.9")).is_known_ip


def test_calendar_features():
    f = FeatureEngineer().extract_sync(event())  # Monday 10:00 UTC
    assert (f.hour_of_day, f.day_of_week, f.is_weekend, f.is_business_hours) == (10, 0, False, True)


def test_memory_is_bounded(monkeypatch):
    monkeypatch.setattr(features, "MAX_TRACKED_IPS", 5)
    agg = WindowedAggregator()
    for i in range(50):
        agg.observe(f"10.0.0.{i}", float(i), "/", 200, False, False)
    assert len(agg._per_ip) == 5


def test_aggregator_reset():
    agg = WindowedAggregator()
    agg.observe("a", 0.0, "/", 200, False, False)
    agg.reset()
    assert not agg._per_ip and not agg._global


def test_entropy_and_special_chars():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert abs(shannon_entropy("ab") - 1.0) < 1e-9
    assert special_char_ratio("") == 0.0
    assert special_char_ratio("/a/b.php") == 0.0
    assert special_char_ratio("a'b%27") > 0.3


def test_singleton_engineer(reset_singletons):
    assert features.get_feature_engineer() is features.get_feature_engineer()


def test_extract_async(event_loop=None):
    import asyncio

    f = asyncio.run(FeatureEngineer().extract(event()))
    assert f.hour_of_day == 10
