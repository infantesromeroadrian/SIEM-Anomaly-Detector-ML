"""Database / Redis wiring tested without live services (stub session, patched factories)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend.db import cache, crud, database


class Result:
    def __init__(self, value=None):
        self.value = value

    def scalar_one(self):
        return self.value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return SimpleNamespace(all=lambda: self.value or [])

    def all(self):
        return self.value or []


class StubSession:
    def __init__(self, *results):
        self.results = list(results)
        self.statements: list[str] = []
        self.added: list[object] = []

    async def execute(self, stmt):
        self.statements.append(str(stmt.compile(compile_kwargs={"literal_binds": False})))
        return self.results.pop(0) if self.results else Result()

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        pass

    async def refresh(self, _obj):
        pass


async def test_get_anomalies_builds_all_filters():
    s = StubSession(Result([1, 2]))
    out = await crud.get_anomalies(
        s, limit=5, offset=10, min_risk_score=0.7, risk_level="high", source_ip="1.2.3.4"
    )
    assert out == [1, 2]
    sql = s.statements[0]
    for fragment in ("risk_score >=", "risk_level =", "source_ip =", "LIMIT", "OFFSET", "ORDER BY"):
        assert fragment in sql


async def test_count_and_stats():
    s = StubSession(Result(3))
    assert await crud.count_anomalies(s, hours=2, min_risk_score=0.5) == 3
    s = StubSession(
        Result(4),
        Result([("high", 3)]),
        Result([("ssh", 2)]),
        Result([("1.1.1.1", 2)]),
        Result(0.8),
    )
    stats = await crud.get_anomaly_stats(s, hours=6)
    assert stats["total_anomalies"] == 4
    assert stats["by_risk_level"] == {"high": 3}
    assert stats["avg_risk_score"] == 0.8 and stats["time_window_hours"] == 6


async def test_update_anomaly():
    obj = SimpleNamespace(risk_score=0.1)
    s = StubSession(Result(obj))
    out = await crud.update_anomaly(s, 1, {"risk_score": 0.9})
    assert out.risk_score == 0.9
    assert await crud.update_anomaly(StubSession(Result(None)), 1, {}) is None


async def test_create_records_are_added():
    s = StubSession()
    await crud.create_log(
        s,
        {
            "log_timestamp": None,
            "source_ip": "1.1.1.1",
            "event_type": "x",
            "raw_log": "r",
            "log_source": "nginx",
        },
    )
    await crud.create_feedback(s, {"anomaly_id": 1, "is_false_positive": False})
    await crud.create_alert(s, {"anomaly_id": 1})
    assert len(s.added) == 3


async def test_reads_and_alert_update():
    s = StubSession(Result([]), Result([]), Result([]), Result(None))
    assert await crud.get_logs(s, limit=1, source_ip="1.1.1.1") == []
    assert await crud.get_feedback_for_anomaly(s, 1) == []
    assert await crud.get_alerts(s, limit=1) == []
    assert await crud.update_alert(s, 1, {"status": "x"}) is None


async def test_init_and_close_db_with_patched_engine(monkeypatch):
    created = {}

    class Engine:
        async def dispose(self):
            created["disposed"] = True

    monkeypatch.setattr(database, "create_async_engine", lambda *a, **k: Engine())
    monkeypatch.setattr(database.settings, "debug", False)
    monkeypatch.setattr(database, "_engine", None)
    monkeypatch.setattr(database, "_async_session_factory", None)
    await database.init_db()
    assert database.get_session_factory() is not None
    await database.init_db()  # idempotent
    await database.close_db()
    assert created["disposed"] and database._engine is None
    await database.close_db()  # no-op
    with pytest.raises(RuntimeError, match="not initialized"):
        async with database.get_db():
            pass


async def test_get_db_commits_and_rolls_back(monkeypatch):
    events = []

    class Sess:
        async def commit(self):
            events.append("commit")

        async def rollback(self):
            events.append("rollback")

        async def close(self):
            events.append("close")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(database, "_async_session_factory", lambda: Sess())
    async with database.get_db():
        pass
    with pytest.raises(ValueError, match="boom"):
        async with database.get_db():
            raise ValueError("boom")
    assert events == ["commit", "close", "rollback", "close"]


async def test_redis_lifecycle(monkeypatch):
    class Client:
        closed = False

        def __init__(self, **kw):
            pass

        async def ping(self):
            return True

        async def aclose(self):
            Client.closed = True

    monkeypatch.setattr(cache.redis, "Redis", Client)
    monkeypatch.setattr(cache, "_redis_client", None)
    with pytest.raises(RuntimeError, match="not initialized"):
        cache.get_redis()
    c = await cache.init_redis()
    assert cache.get_redis() is c
    assert await cache.init_redis() is c
    await cache.close_redis()
    assert Client.closed
    await cache.close_redis()


async def test_redis_connection_error_propagates(monkeypatch):
    class Client:
        def __init__(self, **kw):
            pass

        async def ping(self):
            raise cache.redis.ConnectionError("down")

    monkeypatch.setattr(cache.redis, "Redis", Client)
    monkeypatch.setattr(cache, "_redis_client", None)
    with pytest.raises(cache.redis.ConnectionError):
        await cache.init_redis()
