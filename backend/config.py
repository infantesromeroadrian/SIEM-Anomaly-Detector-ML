"""
Configuration module for SIEM Anomaly Detector.

Loads configuration from environment variables using Pydantic Settings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    All settings can be overridden via environment variables.
    See .env.example for full configuration options.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ============================================================================
    # API Configuration
    # ============================================================================
    api_host: str = Field(default="0.0.0.0", description="API bind address")
    api_port: int = Field(default=8000, ge=1, le=65535, description="API port")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging level",
    )

    # ============================================================================
    # Security
    # ============================================================================
    secret_key: str = Field(
        default="your-secret-key-change-in-production",
        description="Secret key for JWT and encryption",
    )
    allowed_hosts: str = Field(default="*", description="Comma-separated allowed hosts")
    cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:8000",
        description="Comma-separated CORS origins",
    )

    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_expiration_minutes: int = Field(
        default=60,
        ge=1,
        description="JWT expiration in minutes",
    )

    # ============================================================================
    # Database (PostgreSQL)
    # ============================================================================
    postgres_host: str = Field(default="localhost", description="PostgreSQL host")
    postgres_port: int = Field(
        default=5432,
        ge=1,
        le=65535,
        description="PostgreSQL port",
    )
    postgres_db: str = Field(default="siem_db", description="Database name")
    postgres_user: str = Field(default="siem_user", description="Database user")
    postgres_password: str = Field(default="changeme", description="Database password")

    postgres_pool_size: int = Field(
        default=20,
        ge=1,
        description="Connection pool size",
    )
    postgres_max_overflow: int = Field(
        default=10,
        ge=0,
        description="Max overflow connections",
    )
    postgres_pool_timeout: int = Field(
        default=30,
        ge=1,
        description="Pool timeout in seconds",
    )

    @property
    def database_url(self) -> str:
        """Build database URL for SQLAlchemy."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def database_url_sync(self) -> str:
        """Build synchronous database URL."""
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # ============================================================================
    # Redis (Cache & Message Broker)
    # ============================================================================
    redis_host: str = Field(default="localhost", description="Redis host")
    redis_port: int = Field(default=6379, ge=1, le=65535, description="Redis port")
    redis_db: int = Field(default=0, ge=0, le=15, description="Redis database number")
    redis_password: str = Field(default="", description="Redis password (optional)")

    redis_max_connections: int = Field(
        default=50,
        ge=1,
        description="Max connections in pool",
    )
    redis_socket_timeout: int = Field(
        default=5,
        ge=1,
        description="Socket timeout in seconds",
    )

    @property
    def redis_url(self) -> str:
        """Build Redis URL."""
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/{self.redis_db}"

    # ============================================================================
    # Machine Learning Configuration
    # ============================================================================
    model_contamination: float = Field(
        default=0.03,
        ge=0.0,
        le=0.5,
        description="Expected proportion of anomalies",
    )
    model_n_estimators: int = Field(
        default=100,
        ge=10,
        le=500,
        description="Isolation Forest n_estimators",
    )

    dbscan_eps: float = Field(default=1.5, gt=0.0, description="DBSCAN eps parameter")
    dbscan_min_samples: int = Field(
        default=50,
        ge=1,
        description="DBSCAN min_samples",
    )

    gmm_n_components: int = Field(
        default=3,
        ge=2,
        le=10,
        description="GMM number of components",
    )
    gmm_covariance_type: Literal["full", "tied", "diag", "spherical"] = Field(
        default="full",
        description="GMM covariance type",
    )

    ensemble_weights: str = Field(
        default="0.5,0.3,0.2",
        description="Comma-separated ensemble weights (IF,DBSCAN,GMM)",
    )

    model_retrain_interval_hours: int = Field(
        default=24,
        ge=1,
        description="Model retraining interval",
    )
    model_min_feedback_count: int = Field(
        default=100,
        ge=10,
        description="Min feedbacks to trigger retraining",
    )

    model_path: Path = Field(
        default=Path("./models"),
        description="Directory for model storage",
    )
    model_backup_enabled: bool = Field(
        default=True,
        description="Enable model backups",
    )

    @field_validator("ensemble_weights")
    @classmethod
    def validate_ensemble_weights(cls, v: str) -> str:
        """Validate ensemble weights sum to 1.0."""
        try:
            weights = [float(w.strip()) for w in v.split(",")]
            if len(weights) != 3:  # noqa: PLR2004
                msg = "Ensemble weights must have exactly 3 values (IF,DBSCAN,GMM)"
                raise ValueError(msg)
            if not abs(sum(weights) - 1.0) < 0.001:  # Allow small floating point error
                msg = f"Ensemble weights must sum to 1.0, got {sum(weights)}"
                raise ValueError(msg)
        except ValueError as e:
            msg = f"Invalid ensemble weights: {e}"
            raise ValueError(msg) from e
        return v

    @property
    def ensemble_weights_list(self) -> list[float]:
        """Parse ensemble weights as list of floats."""
        return [float(w.strip()) for w in self.ensemble_weights.split(",")]

    # ============================================================================
    # Feature Engineering
    # ============================================================================
    feature_window_short: int = Field(
        default=60,
        ge=1,
        description="Short time window in seconds",
    )
    feature_window_medium: int = Field(
        default=3600,
        ge=1,
        description="Medium time window in seconds",
    )
    feature_window_long: int = Field(
        default=86400,
        ge=1,
        description="Long time window in seconds",
    )

    geoip_enabled: bool = Field(default=True, description="Enable GeoIP lookups")
    geoip_database_path: Path = Field(
        default=Path("./data/GeoLite2-City.mmdb"),
        description="GeoIP database path",
    )

    known_ips_whitelist: str = Field(
        default="127.0.0.1,192.168.1.1",
        description="Comma-separated known IPs",
    )
    known_countries_whitelist: str = Field(
        default="US,ES,FR,DE,GB",
        description="Comma-separated known country codes",
    )

    # ============================================================================
    # Alerting
    # ============================================================================
    alert_threshold_high: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="High risk threshold",
    )
    alert_threshold_medium: float = Field(
        default=0.6,
        ge=0.0,
        le=1.0,
        description="Medium risk threshold",
    )
    alert_threshold_low: float = Field(
        default=0.4,
        ge=0.0,
        le=1.0,
        description="Low risk threshold",
    )

    # Slack
    slack_webhook_url: str = Field(default="", description="Slack webhook URL")
    slack_channel: str = Field(default="#security-alerts", description="Slack channel")
    slack_username: str = Field(
        default="SIEM Anomaly Detector",
        description="Slack bot name",
    )

    # Email
    email_enabled: bool = Field(default=False, description="Enable email alerts")
    email_smtp_host: str = Field(default="smtp.gmail.com", description="SMTP host")
    email_smtp_port: int = Field(
        default=587,
        ge=1,
        le=65535,
        description="SMTP port",
    )
    email_smtp_user: str = Field(default="", description="SMTP username")
    email_smtp_password: str = Field(default="", description="SMTP password")
    email_from: str = Field(default="siem@example.com", description="From address")
    email_recipients: str = Field(
        default="admin@example.com",
        description="Comma-separated recipients",
    )

    # Webhook
    webhook_enabled: bool = Field(default=False, description="Enable custom webhook")
    webhook_url: str = Field(default="", description="Webhook URL")
    webhook_secret: str = Field(default="", description="Webhook HMAC secret")
    webhook_timeout: int = Field(
        default=10,
        ge=1,
        description="Webhook timeout in seconds",
    )

    # Rate Limiting
    alert_rate_limit_per_hour: int = Field(
        default=10,
        ge=1,
        description="Max alerts per hour",
    )
    alert_cooldown_minutes: int = Field(
        default=5,
        ge=1,
        description="Cooldown between same alerts",
    )

    # ============================================================================
    # Log Parsing
    # ============================================================================
    supported_log_types: str = Field(
        default="syslog,nginx,auth,firewall",
        description="Comma-separated log types",
    )

    syslog_udp_enabled: bool = Field(
        default=True,
        description="Enable Syslog UDP listener",
    )
    syslog_udp_port: int = Field(
        default=514,
        ge=1,
        le=65535,
        description="Syslog UDP port",
    )

    file_watch_enabled: bool = Field(
        default=False,
        description="Enable file watchers",
    )
    file_watch_paths: str = Field(
        default="/var/log/auth.log,/var/log/syslog",
        description="Comma-separated file paths to watch",
    )
    file_watch_poll_interval: int = Field(
        default=1,
        ge=1,
        description="Poll interval in seconds",
    )

    log_retention_days: int = Field(
        default=90,
        ge=1,
        description="Log retention in days",
    )
    log_compression_enabled: bool = Field(
        default=True,
        description="Enable log compression",
    )

    # ============================================================================
    # Monitoring & Metrics
    # ============================================================================
    prometheus_enabled: bool = Field(
        default=True,
        description="Enable Prometheus metrics",
    )
    prometheus_port: int = Field(
        default=9090,
        ge=1,
        le=65535,
        description="Prometheus port",
    )

    performance_logging_enabled: bool = Field(
        default=True,
        description="Enable performance logging",
    )
    slow_query_threshold_ms: int = Field(
        default=100,
        ge=1,
        description="Slow query threshold in ms",
    )

    # ============================================================================
    # Celery (Async Tasks)
    # ============================================================================
    celery_broker_url: str | None = Field(
        default=None,
        description="Celery broker URL (defaults to redis_url)",
    )
    celery_result_backend: str | None = Field(
        default=None,
        description="Celery result backend (defaults to redis_url)",
    )

    @property
    def celery_broker_url_resolved(self) -> str:
        """Resolve Celery broker URL."""
        return self.celery_broker_url or self.redis_url

    @property
    def celery_result_backend_resolved(self) -> str:
        """Resolve Celery result backend URL."""
        return self.celery_result_backend or self.redis_url

    celery_worker_concurrency: int = Field(
        default=4,
        ge=1,
        description="Celery worker concurrency",
    )
    celery_task_soft_time_limit: int = Field(
        default=300,
        ge=1,
        description="Soft time limit in seconds",
    )
    celery_task_hard_time_limit: int = Field(
        default=600,
        ge=1,
        description="Hard time limit in seconds",
    )

    # ============================================================================
    # Development Settings
    # ============================================================================
    debug: bool = Field(default=False, description="Debug mode (NEVER in production)")
    auto_reload: bool = Field(default=False, description="Auto-reload on code changes")
    testing: bool = Field(default=False, description="Testing mode")

    # ============================================================================
    # Production Optimizations
    # ============================================================================
    uvicorn_workers: int = Field(
        default=4,
        ge=1,
        description="Number of Uvicorn workers",
    )
    max_connections_per_worker: int = Field(
        default=1000,
        ge=1,
        description="Max connections per worker",
    )
    request_timeout: int = Field(
        default=30,
        ge=1,
        description="Request timeout in seconds",
    )

    cache_enabled: bool = Field(default=True, description="Enable caching")
    cache_ttl_seconds: int = Field(
        default=300,
        ge=1,
        description="Cache TTL in seconds",
    )

    rate_limit_enabled: bool = Field(
        default=True,
        description="Enable rate limiting",
    )
    rate_limit_per_minute: int = Field(
        default=60,
        ge=1,
        description="Max requests per minute",
    )
    rate_limit_per_hour: int = Field(
        default=1000,
        ge=1,
        description="Max requests per hour",
    )


# ============================================================================
# Global Settings Instance
# ============================================================================
settings = Settings()
