"""
Feature engineering for log analysis.

All features are deterministic functions of the event stream seen so far
(causal windows: an event only sees itself and earlier events). There is no
randomness and no external service involved, so training, offline evaluation
and online scoring share exactly the same code path.

Earlier revisions filled some features with ``np.random`` values (geographic
distance, session duration and every Redis fallback). Those features carried no
information and have been removed.
"""

from __future__ import annotations

import math
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import numpy as np
import structlog

logger = structlog.get_logger(__name__)

#: Column order of ``LogFeatures.to_array``. Single source of truth.
FEATURE_NAMES: tuple[str, ...] = (
    "hour_of_day",
    "day_of_week",
    "is_weekend",
    "is_business_hours",
    "login_attempts_per_minute",
    "requests_per_second",
    "unique_ips_last_hour",
    "unique_endpoints_accessed",
    "failed_auth_rate",
    "error_rate_4xx",
    "error_rate_5xx",
    "status_class",
    "is_known_ip",
    "bytes_transferred",
    "time_since_last_activity_sec",
    "path_length",
    "special_char_ratio",
    "payload_entropy",
    "is_privileged_user",
    "is_sensitive_endpoint",
    "is_known_user_agent",
)

#: Seconds. Window for per-IP rates.
SHORT_WINDOW_SEC = 60
#: Seconds. Window for per-IP ratios and distinct endpoints.
MEDIUM_WINDOW_SEC = 300
#: Seconds. Window for the global distinct-IP counter.
LONG_WINDOW_SEC = 3600
#: Cap on the per-IP event history (bounds memory under flooding).
MAX_EVENTS_PER_IP = 5000
#: Cap on tracked IPs (bounds memory under source-address spraying).
MAX_TRACKED_IPS = 50_000
#: Cap used for ``time_since_last_activity_sec`` (one hour).
MAX_IDLE_SEC = 3600.0

_BENIGN_PATH_CHARS = frozenset("/.-_")


@dataclass
class LogFeatures:
    """Feature vector extracted from one log entry (see ``FEATURE_NAMES``)."""

    # Temporal
    hour_of_day: int
    day_of_week: int  # 0 = Monday
    is_weekend: bool
    is_business_hours: bool  # 09:00 - 18:00

    # Per-source-IP activity (causal windows)
    login_attempts_per_minute: float
    requests_per_second: float  # requests in the last 60 s / 60
    unique_ips_last_hour: int
    unique_endpoints_accessed: int

    # Per-source-IP ratios over the last 5 minutes
    failed_auth_rate: float
    error_rate_4xx: float
    error_rate_5xx: float

    # Event content
    status_class: int  # 0 unknown, otherwise the hundreds digit (2, 3, 4, 5)
    is_known_ip: bool  # IP present in the configured / training-time allowlist
    bytes_transferred: float  # log1p(bytes)
    time_since_last_activity_sec: float
    path_length: float
    special_char_ratio: float
    payload_entropy: float  # Shannon entropy (bits/char) of the request target

    # Context
    is_privileged_user: bool
    is_sensitive_endpoint: bool
    is_known_user_agent: bool

    def to_array(self) -> np.ndarray:
        """Return the features as a float32 vector ordered as ``FEATURE_NAMES``."""
        return np.array(
            [float(getattr(self, name)) for name in FEATURE_NAMES],
            dtype=np.float32,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert features to a grouped dictionary for API responses."""
        return {
            "temporal": {
                "hour_of_day": self.hour_of_day,
                "day_of_week": self.day_of_week,
                "is_weekend": self.is_weekend,
                "is_business_hours": self.is_business_hours,
            },
            "frequency": {
                "login_attempts_per_minute": round(self.login_attempts_per_minute, 2),
                "requests_per_second": round(self.requests_per_second, 3),
                "unique_ips_last_hour": self.unique_ips_last_hour,
                "unique_endpoints_accessed": self.unique_endpoints_accessed,
            },
            "rates": {
                "failed_auth_rate": round(self.failed_auth_rate, 3),
                "error_rate_4xx": round(self.error_rate_4xx, 3),
                "error_rate_5xx": round(self.error_rate_5xx, 3),
            },
            "behavioral": {
                "status_class": self.status_class,
                "bytes_transferred": round(self.bytes_transferred, 2),
                "time_since_last_activity_sec": round(self.time_since_last_activity_sec, 1),
                "path_length": round(self.path_length, 1),
                "special_char_ratio": round(self.special_char_ratio, 3),
                "payload_entropy": round(self.payload_entropy, 3),
            },
            "context": {
                "is_known_ip": self.is_known_ip,
                "is_privileged_user": self.is_privileged_user,
                "is_sensitive_endpoint": self.is_sensitive_endpoint,
                "is_known_user_agent": self.is_known_user_agent,
            },
        }


@dataclass
class _IpEvent:
    ts: float
    endpoint: str
    status: int
    is_auth: bool
    auth_failed: bool


class WindowedAggregator:
    """
    In-memory, per-source-IP sliding-window state.

    Events must be observed in (roughly) chronological order. Memory is bounded
    by ``MAX_EVENTS_PER_IP`` and ``MAX_TRACKED_IPS`` so a flood or an
    address-spraying source cannot grow it without limit.

    Not thread-safe; the API uses a single instance per worker process.
    """

    def __init__(self) -> None:
        """Create an empty aggregator."""
        self._per_ip: OrderedDict[str, deque[_IpEvent]] = OrderedDict()
        self._global: deque[tuple[float, str]] = deque()
        self._global_counts: Counter[str] = Counter()

    def observe(
        self,
        source_ip: str,
        ts: float,
        endpoint: str,
        status: int,
        is_auth: bool,
        auth_failed: bool,
    ) -> dict[str, float]:
        """Record an event and return the window statistics that include it."""
        events = self._per_ip.get(source_ip)
        if events is None:
            events = deque(maxlen=MAX_EVENTS_PER_IP)
            self._per_ip[source_ip] = events
            if len(self._per_ip) > MAX_TRACKED_IPS:
                self._per_ip.popitem(last=False)
        else:
            self._per_ip.move_to_end(source_ip)

        previous_ts = events[-1].ts if events else None
        events.append(_IpEvent(ts, endpoint, status, is_auth, auth_failed))

        # Drop events older than the largest per-IP window.
        horizon = ts - MEDIUM_WINDOW_SEC
        while events and events[0].ts < horizon:
            events.popleft()

        # Global distinct-IP counter.
        self._global.append((ts, source_ip))
        self._global_counts[source_ip] += 1
        global_horizon = ts - LONG_WINDOW_SEC
        while self._global and self._global[0][0] < global_horizon:
            _, old_ip = self._global.popleft()
            self._global_counts[old_ip] -= 1
            if self._global_counts[old_ip] <= 0:
                del self._global_counts[old_ip]

        short_horizon = ts - SHORT_WINDOW_SEC
        short = [e for e in events if e.ts >= short_horizon]
        medium = list(events)
        n_medium = len(medium)

        auth_events = [e for e in short if e.is_auth]
        auth_medium = [e for e in medium if e.is_auth]

        return {
            "requests_in_short_window": float(len(short)),
            "login_attempts_per_minute": float(len(auth_events)),
            "unique_endpoints": float(len({e.endpoint for e in medium})),
            "unique_ips_last_hour": float(len(self._global_counts)),
            "failed_auth_rate": (
                sum(e.auth_failed for e in auth_medium) / len(auth_medium) if auth_medium else 0.0
            ),
            "error_rate_4xx": sum(400 <= e.status < 500 for e in medium) / n_medium,
            "error_rate_5xx": sum(500 <= e.status < 600 for e in medium) / n_medium,
            "idle_sec": (
                min(max(ts - previous_ts, 0.0), MAX_IDLE_SEC)
                if previous_ts is not None
                else MAX_IDLE_SEC
            ),
        }

    def reset(self) -> None:
        """Forget all state."""
        self._per_ip.clear()
        self._global.clear()
        self._global_counts.clear()


def shannon_entropy(text: str) -> float:
    """Return the Shannon entropy of ``text`` in bits per character."""
    if not text:
        return 0.0
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in Counter(text).values())


def special_char_ratio(text: str) -> float:
    """Return the share of characters that are not alphanumeric nor ``/ . - _``."""
    if not text:
        return 0.0
    odd = sum(1 for ch in text if not (ch.isalnum() or ch in _BENIGN_PATH_CHARS))
    return odd / len(text)


class FeatureEngineer:
    """Turn parsed log dictionaries into ``LogFeatures`` using a ``WindowedAggregator``."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize the feature engineer.

        Args:
            config: Optional overrides: ``known_ips``, ``privileged_users``,
                ``sensitive_endpoints``, ``known_user_agents``.
        """
        self.config = config or {}
        self.known_ips: set[str] = set(self.config.get("known_ips", ["127.0.0.1", "::1"]))
        self.privileged_users: set[str] = set(
            self.config.get("privileged_users", ["root", "admin", "administrator"])
        )
        self.sensitive_endpoints: tuple[str, ...] = tuple(
            self.config.get(
                "sensitive_endpoints",
                ["/admin", "/api/admin", "/wp-admin", "/phpmyadmin"],
            )
        )
        self.known_user_agents: tuple[str, ...] = tuple(
            self.config.get(
                "known_user_agents",
                ["Mozilla", "Chrome", "Safari", "Edge", "Firefox", "curl", "wget"],
            )
        )
        self.aggregator = WindowedAggregator()
        logger.info("feature_engineer_initialized", known_ips=len(self.known_ips))

    def extract_sync(self, parsed_log: dict[str, Any]) -> LogFeatures:
        """
        Extract features from one parsed log entry and update the window state.

        Args:
            parsed_log: Dictionary as produced by ``ParsedLog.to_dict``.

        Returns:
            The feature vector for this event.
        """
        timestamp = parsed_log.get("timestamp") or datetime.now(timezone.utc)
        source_ip = parsed_log.get("source_ip") or "unknown"
        username = parsed_log.get("username") or ""
        endpoint = parsed_log.get("endpoint") or ""
        user_agent = parsed_log.get("user_agent") or ""
        status_code = int(parsed_log.get("status_code") or 0)
        bytes_sent = max(int(parsed_log.get("bytes_sent") or 0), 0)
        event_type = str(parsed_log.get("event_type") or "").lower()

        is_auth = "auth" in event_type or "login" in event_type or "password" in event_type
        auth_failed = is_auth and (
            "fail" in event_type or parsed_log.get("success") is False or status_code >= 400
        )

        stats = self.aggregator.observe(
            source_ip=source_ip,
            ts=timestamp.timestamp(),
            endpoint=endpoint,
            status=status_code,
            is_auth=is_auth,
            auth_failed=auth_failed,
        )

        target = endpoint or str(parsed_log.get("payload") or "")
        hour = timestamp.hour
        weekday = timestamp.weekday()

        return LogFeatures(
            hour_of_day=hour,
            day_of_week=weekday,
            is_weekend=weekday >= 5,
            is_business_hours=9 <= hour < 18,
            login_attempts_per_minute=stats["login_attempts_per_minute"],
            requests_per_second=stats["requests_in_short_window"] / SHORT_WINDOW_SEC,
            unique_ips_last_hour=int(stats["unique_ips_last_hour"]),
            unique_endpoints_accessed=int(stats["unique_endpoints"]),
            failed_auth_rate=stats["failed_auth_rate"],
            error_rate_4xx=stats["error_rate_4xx"],
            error_rate_5xx=stats["error_rate_5xx"],
            status_class=status_code // 100 if 100 <= status_code < 600 else 0,
            is_known_ip=source_ip in self.known_ips,
            bytes_transferred=float(np.log1p(bytes_sent)),
            time_since_last_activity_sec=stats["idle_sec"],
            path_length=float(len(target)),
            special_char_ratio=special_char_ratio(target),
            payload_entropy=shannon_entropy(target),
            is_privileged_user=username.lower() in self.privileged_users,
            is_sensitive_endpoint=any(endpoint.startswith(p) for p in self.sensitive_endpoints),
            is_known_user_agent=any(ua in user_agent for ua in self.known_user_agents),
        )

    async def extract(self, parsed_log: dict[str, Any]) -> LogFeatures:
        """Async wrapper around ``extract_sync`` (kept for the API layer)."""
        return self.extract_sync(parsed_log)


_feature_engineer: FeatureEngineer | None = None


def get_feature_engineer() -> FeatureEngineer:
    """Return the process-wide ``FeatureEngineer`` so window state persists across requests."""
    global _feature_engineer
    if _feature_engineer is None:
        _feature_engineer = FeatureEngineer()
    return _feature_engineer
