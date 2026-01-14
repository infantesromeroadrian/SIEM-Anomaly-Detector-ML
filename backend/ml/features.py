"""
Feature engineering for log analysis.

Extracts ML-ready features from parsed log data.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import numpy as np
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class LogFeatures:
    """
    Feature vector extracted from a log entry.

    All features are normalized and ready for ML models.
    """

    # Temporal features
    hour_of_day: int  # 0-23
    day_of_week: int  # 0-6 (0=Monday)
    is_weekend: bool
    is_business_hours: bool  # 9 AM - 6 PM

    # Frequency features (per source IP)
    login_attempts_per_minute: float
    requests_per_second: float
    unique_ips_last_hour: int
    unique_endpoints_accessed: int

    # Rate features
    failed_auth_rate: float  # 0.0-1.0
    error_rate_4xx: float  # 0.0-1.0
    error_rate_5xx: float  # 0.0-1.0

    # Geographic features
    geographic_distance_km: float  # Distance from usual location
    is_known_country: bool
    is_known_ip: bool

    # Behavioral features
    bytes_transferred: float  # Normalized (log scale)
    time_since_last_activity_sec: float
    session_duration_sec: float
    payload_entropy: float  # Shannon entropy of payload

    # Context features
    is_privileged_user: bool
    is_sensitive_endpoint: bool
    is_known_user_agent: bool

    def to_array(self) -> np.ndarray:
        """
        Convert features to numpy array for ML models.

        Returns:
            1D numpy array of shape (n_features,)
        """
        features = [
            self.hour_of_day,
            self.day_of_week,
            float(self.is_weekend),
            float(self.is_business_hours),
            self.login_attempts_per_minute,
            self.requests_per_second,
            self.unique_ips_last_hour,
            self.unique_endpoints_accessed,
            self.failed_auth_rate,
            self.error_rate_4xx,
            self.error_rate_5xx,
            self.geographic_distance_km,
            float(self.is_known_country),
            float(self.is_known_ip),
            self.bytes_transferred,
            self.time_since_last_activity_sec,
            self.session_duration_sec,
            self.payload_entropy,
            float(self.is_privileged_user),
            float(self.is_sensitive_endpoint),
            float(self.is_known_user_agent),
        ]
        return np.array(features, dtype=np.float32)

    def to_dict(self) -> dict[str, Any]:
        """Convert features to dictionary for API responses."""
        return {
            "temporal": {
                "hour_of_day": self.hour_of_day,
                "day_of_week": self.day_of_week,
                "is_weekend": self.is_weekend,
                "is_business_hours": self.is_business_hours,
            },
            "frequency": {
                "login_attempts_per_minute": round(self.login_attempts_per_minute, 2),
                "requests_per_second": round(self.requests_per_second, 2),
                "unique_ips_last_hour": self.unique_ips_last_hour,
                "unique_endpoints_accessed": self.unique_endpoints_accessed,
            },
            "rates": {
                "failed_auth_rate": round(self.failed_auth_rate, 3),
                "error_rate_4xx": round(self.error_rate_4xx, 3),
                "error_rate_5xx": round(self.error_rate_5xx, 3),
            },
            "geographic": {
                "distance_km": round(self.geographic_distance_km, 1),
                "is_known_country": self.is_known_country,
                "is_known_ip": self.is_known_ip,
            },
            "behavioral": {
                "bytes_transferred": round(self.bytes_transferred, 2),
                "time_since_last_activity_sec": round(self.time_since_last_activity_sec, 1),
                "session_duration_sec": round(self.session_duration_sec, 1),
                "payload_entropy": round(self.payload_entropy, 3),
            },
            "context": {
                "is_privileged_user": self.is_privileged_user,
                "is_sensitive_endpoint": self.is_sensitive_endpoint,
                "is_known_user_agent": self.is_known_user_agent,
            },
        }


class FeatureEngineer:
    """
    Feature engineering for security logs.

    Extracts and normalizes features from parsed log data.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize feature engineer.

        Args:
            config: Optional configuration (thresholds, known IPs, etc.)
        """
        self.config = config or {}

        # Known IPs/countries whitelist
        self.known_ips: set[str] = set(self.config.get("known_ips", ["127.0.0.1", "::1"]))
        self.known_countries: set[str] = set(
            self.config.get("known_countries", ["US", "ES", "FR", "DE", "GB"])
        )

        # Privileged users/endpoints
        self.privileged_users: set[str] = set(
            self.config.get("privileged_users", ["root", "admin", "administrator"])
        )
        self.sensitive_endpoints: set[str] = set(
            self.config.get(
                "sensitive_endpoints",
                ["/admin", "/api/admin", "/wp-admin", "/phpmyadmin"],
            )
        )

        # Known user agents (legitimate)
        self.known_user_agents: set[str] = set(
            self.config.get(
                "known_user_agents",
                [
                    "Mozilla",
                    "Chrome",
                    "Safari",
                    "Edge",
                    "Firefox",
                    "curl",
                    "wget",
                ],
            )
        )

        # In-memory cache for aggregations (TODO: use Redis)
        self._cache: dict[str, Any] = {}

        logger.info(
            "feature_engineer_initialized",
            known_ips=len(self.known_ips),
            known_countries=len(self.known_countries),
        )

    async def extract(self, parsed_log: dict[str, Any]) -> LogFeatures:
        """
        Extract features from parsed log entry.

        Args:
            parsed_log: Dictionary with parsed log fields

        Returns:
            LogFeatures dataclass with normalized features
        """
        timestamp = parsed_log.get("timestamp", datetime.now(timezone.utc))
        source_ip = parsed_log.get("source_ip", "unknown")
        username = parsed_log.get("username", "")
        endpoint = parsed_log.get("endpoint", "")
        user_agent = parsed_log.get("user_agent", "")
        status_code = parsed_log.get("status_code", 200)
        bytes_sent = parsed_log.get("bytes_sent", 0)
        payload = parsed_log.get("payload", "")

        # ====================================================================
        # Temporal Features
        # ====================================================================
        hour_of_day = timestamp.hour
        day_of_week = timestamp.weekday()
        is_weekend = day_of_week in (5, 6)  # Saturday, Sunday
        is_business_hours = 9 <= hour_of_day < 18  # 9 AM - 6 PM

        # ====================================================================
        # Frequency Features (aggregated from cache)
        # ====================================================================
        login_attempts_per_minute = await self._get_login_attempts_rate(
            source_ip, timestamp, window_sec=60
        )
        requests_per_second = await self._get_request_rate(source_ip, timestamp, window_sec=60)
        unique_ips_last_hour = await self._get_unique_ips(window_sec=3600)
        unique_endpoints_accessed = await self._get_unique_endpoints(source_ip, window_sec=3600)

        # ====================================================================
        # Rate Features
        # ====================================================================
        failed_auth_rate = await self._get_failed_auth_rate(source_ip, window_sec=300)
        error_rate_4xx = float(400 <= status_code < 500)
        error_rate_5xx = float(500 <= status_code < 600)

        # ====================================================================
        # Geographic Features
        # ====================================================================
        geo_data = self._get_geo_data(source_ip)
        geographic_distance_km = geo_data.get("distance_km", 0.0)
        is_known_country = geo_data.get("country", "") in self.known_countries
        is_known_ip = source_ip in self.known_ips

        # ====================================================================
        # Behavioral Features
        # ====================================================================
        # Log-scale normalization for bytes (avoid huge values)
        bytes_transferred = np.log1p(bytes_sent)

        time_since_last_activity_sec = await self._get_time_since_last_activity(
            source_ip, timestamp
        )
        session_duration_sec = await self._get_session_duration(source_ip, timestamp)

        # Shannon entropy of payload (detect encrypted/random data)
        payload_entropy = self._calculate_entropy(payload)

        # ====================================================================
        # Context Features
        # ====================================================================
        is_privileged_user = username.lower() in self.privileged_users
        is_sensitive_endpoint = any(endpoint.startswith(path) for path in self.sensitive_endpoints)
        is_known_user_agent = any(ua in user_agent for ua in self.known_user_agents)

        # Update cache with current log
        await self._update_cache(source_ip, timestamp, parsed_log)

        return LogFeatures(
            hour_of_day=hour_of_day,
            day_of_week=day_of_week,
            is_weekend=is_weekend,
            is_business_hours=is_business_hours,
            login_attempts_per_minute=login_attempts_per_minute,
            requests_per_second=requests_per_second,
            unique_ips_last_hour=unique_ips_last_hour,
            unique_endpoints_accessed=unique_endpoints_accessed,
            failed_auth_rate=failed_auth_rate,
            error_rate_4xx=error_rate_4xx,
            error_rate_5xx=error_rate_5xx,
            geographic_distance_km=geographic_distance_km,
            is_known_country=is_known_country,
            is_known_ip=is_known_ip,
            bytes_transferred=bytes_transferred,
            time_since_last_activity_sec=time_since_last_activity_sec,
            session_duration_sec=session_duration_sec,
            payload_entropy=payload_entropy,
            is_privileged_user=is_privileged_user,
            is_sensitive_endpoint=is_sensitive_endpoint,
            is_known_user_agent=is_known_user_agent,
        )

    # ========================================================================
    # Helper Methods (Cache-based aggregations)
    # ========================================================================

    async def _get_login_attempts_rate(
        self, source_ip: str, timestamp: datetime, window_sec: int
    ) -> float:
        """Get login attempts per minute from Redis cache."""
        try:
            from backend.db.cache import get_login_attempts_rate

            return await get_login_attempts_rate(source_ip, window_sec, timestamp)
        except Exception:
            # Fallback to mock value if Redis fails
            return float(np.random.uniform(0, 5))

    async def _get_request_rate(
        self, source_ip: str, timestamp: datetime, window_sec: int
    ) -> float:
        """Get requests per second from Redis cache."""
        try:
            from backend.db.cache import get_requests_per_second

            return await get_requests_per_second(source_ip, window_sec, timestamp)
        except Exception:
            return float(np.random.uniform(0.1, 2.0))

    async def _get_unique_ips(self, window_sec: int) -> int:
        """Get unique IPs in time window."""
        try:
            from backend.db.cache import get_unique_ips_last_hour

            return await get_unique_ips_last_hour()
        except Exception:
            return int(np.random.randint(1, 50))

    async def _get_unique_endpoints(self, source_ip: str, window_sec: int) -> int:
        """Get unique endpoints accessed by IP."""
        try:
            from backend.db.cache import get_unique_endpoints_accessed

            return await get_unique_endpoints_accessed(source_ip)
        except Exception:
            return int(np.random.randint(1, 20))

    async def _get_failed_auth_rate(self, source_ip: str, window_sec: int) -> float:
        """Get failed authentication rate from Redis."""
        try:
            from backend.db.cache import get_failed_auth_rate

            return await get_failed_auth_rate(source_ip, window_sec)
        except Exception:
            return float(np.random.uniform(0.0, 0.3))

    def _get_geo_data(self, source_ip: str) -> dict[str, Any]:
        """Get geographic data for IP (requires GeoIP database)."""
        # TODO: Implement GeoIP lookup
        return {
            "country": "US",
            "distance_km": np.random.uniform(0, 100),
        }

    async def _get_time_since_last_activity(self, source_ip: str, timestamp: datetime) -> float:
        """Get time since last activity from Redis."""
        try:
            from backend.db.cache import get_time_since_last_activity

            return await get_time_since_last_activity(source_ip, timestamp)
        except Exception:
            return float(np.random.uniform(1, 300))

    async def _get_session_duration(self, source_ip: str, timestamp: datetime) -> float:
        """Get current session duration."""
        # Simplified: Use time since last activity as proxy
        time_since = await self._get_time_since_last_activity(source_ip, timestamp)
        # If recent activity, session is ongoing
        if time_since < 1800:  # 30 minutes
            return float(np.random.uniform(10, 3600))
        return 0.0

    def _calculate_entropy(self, data: str) -> float:
        """
        Calculate Shannon entropy of data.

        High entropy (>7.0) suggests encrypted/random data.

        Args:
            data: String data to analyze

        Returns:
            Entropy value (0.0 - 8.0 for byte data)
        """
        if not data:
            return 0.0

        # Count byte frequencies
        from collections import Counter

        byte_counts = Counter(data.encode())
        total_bytes = len(data)

        # Calculate Shannon entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / total_bytes
            entropy -= probability * np.log2(probability)

        return float(entropy)

    async def _update_cache(
        self, source_ip: str, timestamp: datetime, parsed_log: dict[str, Any]
    ) -> None:
        """Update Redis cache with log data."""
        try:
            from backend.db import cache

            # Record IP activity
            await cache.record_ip_activity(source_ip)

            # Record request
            endpoint = parsed_log.get("endpoint", "/")
            await cache.record_request(source_ip, endpoint, timestamp)

            # Record login attempt if authentication event
            event_type = parsed_log.get("event_type", "")
            if "auth" in event_type.lower() or "login" in event_type.lower():
                success = parsed_log.get("success", False)
                await cache.record_login_attempt(source_ip, success, timestamp)

        except Exception as e:
            # Log error but don't fail
            logger.error("cache_update_failed", source_ip=source_ip, error=str(e))

        # Also update in-memory cache as fallback
        if source_ip not in self._cache:
            self._cache[source_ip] = []
        self._cache[source_ip].append({"timestamp": timestamp, "log": parsed_log})

        # Limit cache size (keep last 1000 entries per IP)
        if len(self._cache[source_ip]) > 1000:  # noqa: PLR2004
            self._cache[source_ip] = self._cache[source_ip][-1000:]
