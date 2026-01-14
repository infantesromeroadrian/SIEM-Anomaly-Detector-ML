"""
Log analysis endpoints for SIEM Anomaly Detector.

Provides real-time anomaly detection for security logs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from backend.config import settings
from backend.parsers import get_parser

logger = structlog.get_logger(__name__)

router = APIRouter()


def _generate_reasons(features: Any, important_features: list[tuple[str, float]]) -> list[str]:
    """
    Generate human-readable reasons for anomaly detection.

    Args:
        features: LogFeatures dataclass
        important_features: List of (feature_name, deviation_score) tuples

    Returns:
        List of human-readable reason strings
    """
    reasons = []

    # Temporal anomalies
    if features.hour_of_day in (0, 1, 2, 3, 4, 5):
        reasons.append(f"Activity at unusual hour ({features.hour_of_day}:00)")

    if features.is_weekend and not features.is_business_hours:
        reasons.append("Weekend activity outside business hours")

    # Frequency anomalies
    if features.login_attempts_per_minute > 5:  # noqa: PLR2004
        reasons.append(
            f"High login attempt rate ({features.login_attempts_per_minute:.1f}/min) - potential brute force"
        )

    if features.requests_per_second > 10:  # noqa: PLR2004
        reasons.append(
            f"High request rate ({features.requests_per_second:.1f}/sec) - potential DDoS"
        )

    # Rate anomalies
    if features.failed_auth_rate > 0.5:  # noqa: PLR2004
        reasons.append(f"High failed authentication rate ({features.failed_auth_rate:.0%})")

    if features.error_rate_5xx > 0:
        reasons.append("Server error detected (5xx status code)")

    # Geographic anomalies
    if not features.is_known_ip:
        reasons.append("Unknown/untrusted IP address")

    if not features.is_known_country:
        reasons.append("Request from unusual country")

    if features.geographic_distance_km > 1000:  # noqa: PLR2004
        reasons.append(
            f"Large geographic distance from typical location ({features.geographic_distance_km:.0f} km)"
        )

    # Context anomalies
    if features.is_privileged_user:
        reasons.append("Privileged user access (root/admin)")

    if features.is_sensitive_endpoint:
        reasons.append("Access to sensitive endpoint")

    # Behavioral anomalies
    if features.payload_entropy > 7.0:  # noqa: PLR2004
        reasons.append("High payload entropy - potential encrypted/malicious content")

    if features.time_since_last_activity_sec > 86400:  # noqa: PLR2004
        reasons.append("First activity in >24 hours - dormant account activation")

    # Add top ML features if not already mentioned
    for feature_name, _deviation in important_features[:3]:
        feature_reason = f"Anomalous {feature_name.replace('_', ' ')}"
        if feature_reason not in " ".join(reasons):
            reasons.append(feature_reason)

    if not reasons:
        reasons = ["Pattern deviates from normal behavior (ensemble detection)"]

    return reasons[:5]  # Limit to top 5 reasons


# ============================================================================
# Enums
# ============================================================================
class LogSource(str, Enum):
    """Supported log sources."""

    SYSLOG = "syslog"
    NGINX = "nginx"
    AUTH = "auth"
    FIREWALL = "firewall"
    CUSTOM = "custom"


class RiskLevel(str, Enum):
    """Risk level classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NORMAL = "normal"


class RecommendedAction(str, Enum):
    """Recommended actions for anomalies."""

    BLOCK_IP = "BLOCK_IP"
    REQUIRE_MFA = "REQUIRE_MFA"
    ALERT_ADMIN = "ALERT_ADMIN"
    MONITOR = "MONITOR"
    NO_ACTION = "NO_ACTION"


# ============================================================================
# Request Models
# ============================================================================
class AnalyzeLogRequest(BaseModel):
    """Request model for single log analysis."""

    log_line: str = Field(
        ...,
        description="Raw log line to analyze",
        min_length=1,
        max_length=10000,
        examples=[
            "Jan 13 03:45:12 server sshd[1234]: Failed password for admin from 192.168.1.100"
        ],
    )
    source: LogSource = Field(
        ...,
        description="Log source type",
        examples=[LogSource.AUTH],
    )
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Optional metadata (timestamp, hostname, etc.)",
    )


class BatchAnalyzeRequest(BaseModel):
    """Request model for batch log analysis."""

    logs: list[AnalyzeLogRequest] = Field(
        ...,
        description="List of logs to analyze",
        min_length=1,
        max_length=1000,
    )

    @field_validator("logs")
    @classmethod
    def validate_batch_size(cls, v: list[AnalyzeLogRequest]) -> list[AnalyzeLogRequest]:
        """Validate batch size limits."""
        if len(v) > 1000:  # noqa: PLR2004
            msg = "Batch size cannot exceed 1000 logs"
            raise ValueError(msg)
        return v


# ============================================================================
# Response Models
# ============================================================================
class AnalysisResult(BaseModel):
    """Analysis result for a single log."""

    log_id: str = Field(..., description="Unique log identifier")
    is_anomaly: bool = Field(..., description="Whether log is anomalous")
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Risk score (0.0 = normal, 1.0 = critical)",
    )
    risk_level: RiskLevel = Field(..., description="Risk level classification")
    confidence: str = Field(..., description="Confidence level (low/medium/high)")

    features: dict[str, Any] = Field(..., description="Extracted features")
    reasons: list[str] = Field(..., description="Human-readable reasons for anomaly")

    recommended_action: RecommendedAction = Field(
        ...,
        description="Recommended action",
    )
    similar_anomalies: int = Field(
        ...,
        ge=0,
        description="Number of similar anomalies in history",
    )

    model_scores: dict[str, float] = Field(
        ...,
        description="Individual model scores",
    )
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")
    timestamp: datetime = Field(..., description="Analysis timestamp")


class BatchAnalysisResponse(BaseModel):
    """Response model for batch analysis."""

    total_logs: int = Field(..., description="Total logs analyzed")
    anomalies_detected: int = Field(..., description="Number of anomalies detected")
    anomaly_rate: float = Field(..., description="Anomaly rate (0.0-1.0)")
    results: list[AnalysisResult] = Field(..., description="Individual results")
    processing_time_ms: float = Field(..., description="Total processing time")


# ============================================================================
# Endpoints
# ============================================================================
@router.post(
    "/logs/analyze",
    response_model=AnalysisResult,
    status_code=status.HTTP_200_OK,
    summary="Analyze Single Log",
    description="Analyze a single log line for anomalies using ML ensemble",
)
async def analyze_log(request: AnalyzeLogRequest) -> AnalysisResult:
    """
    Analyze a single log line for anomalies.

    Process:
    1. Parse log line (extract timestamp, source IP, etc.)
    2. Engineer features (rates, geographic data, etc.)
    3. Run through ML ensemble (IF + DBSCAN + GMM)
    4. Aggregate scores with weights
    5. Determine risk level and recommended action
    6. Return analysis result

    Args:
        request: Log analysis request

    Returns:
        AnalysisResult with anomaly detection details

    Raises:
        HTTPException: 422 if log cannot be parsed
        HTTPException: 500 if analysis fails
    """
    import hashlib
    import time

    start_time = time.time()

    # Generate log ID
    log_id = hashlib.md5(f"{request.log_line}{time.time()}".encode()).hexdigest()[:12]

    logger.info(
        "log_analysis_started",
        log_id=log_id,
        source=request.source,
        log_length=len(request.log_line),
    )

    try:
        # ========================================================================
        # 1. Parse log with professional parsers
        # ========================================================================
        try:
            parser = get_parser(request.source.value)
            parsed_log = parser.parse(request.log_line)
            parsed_data = parsed_log.to_dict()

            # Override with metadata if provided (for custom fields)
            if request.metadata:
                parsed_data.update(request.metadata)

            logger.debug(
                "log_parsed",
                log_id=log_id,
                parser=request.source.value,
                event_type=parsed_data.get("event_type"),
                source_ip=parsed_data.get("source_ip"),
            )
        except Exception as parse_error:
            logger.warning(
                "parser_failed_fallback_to_generic",
                log_id=log_id,
                source=request.source.value,
                error=str(parse_error),
            )
            # Fallback: create minimal parsed data from raw log
            import re

            parsed_data = {
                "timestamp": datetime.now(timezone.utc),
                "source_ip": "unknown",
                "username": "",
                "endpoint": "",
                "user_agent": "",
                "status_code": 0,
                "bytes_sent": 0,
                "payload": request.log_line,
                "event_type": "unknown",
            }
            # Try basic IP extraction
            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", request.log_line)
            if ip_match:
                parsed_data["source_ip"] = ip_match.group(0)
            # Apply metadata overrides if provided
            if request.metadata:
                parsed_data.update(request.metadata)

        # ========================================================================
        # 2. Extract features
        # ========================================================================
        from backend.ml.features import FeatureEngineer

        feature_engineer = FeatureEngineer(
            config={
                "known_ips": ["127.0.0.1", "192.168.1.1", "10.0.0.1"],
                "known_countries": ["US", "ES", "FR", "DE", "GB"],
                "privileged_users": ["root", "admin", "administrator"],
                "sensitive_endpoints": ["/admin", "/api/admin", "/wp-admin"],
            }
        )

        features = await feature_engineer.extract(parsed_data)

        # ========================================================================
        # 3. Run ML ensemble
        # ========================================================================
        from backend.ml.model_loader import get_model_loader

        model_loader = get_model_loader()
        prediction = model_loader.predict(features, ensemble_weights=settings.ensemble_weights_list)

        # Extract scores
        final_score = prediction["risk_score"]
        model_scores = {
            "isolation_forest": prediction["isolation_forest_score"],
            "dbscan": prediction["dbscan_score"],
            "gmm": prediction["gmm_score"],
        }

        # Determine risk level
        if final_score >= settings.alert_threshold_high:
            risk_level = RiskLevel.HIGH
            is_anomaly = True
            confidence = "high"
            recommended_action = RecommendedAction.BLOCK_IP
        elif final_score >= settings.alert_threshold_medium:
            risk_level = RiskLevel.MEDIUM
            is_anomaly = True
            confidence = "medium"
            recommended_action = RecommendedAction.REQUIRE_MFA
        elif final_score >= settings.alert_threshold_low:
            risk_level = RiskLevel.LOW
            is_anomaly = True
            confidence = "low"
            recommended_action = RecommendedAction.MONITOR
        else:
            risk_level = RiskLevel.NORMAL
            is_anomaly = False
            confidence = "high"
            recommended_action = RecommendedAction.NO_ACTION

        # ========================================================================
        # 4. Generate human-readable reasons from important features
        # ========================================================================
        reasons = _generate_reasons(features, prediction["important_features"])

        processing_time = (time.time() - start_time) * 1000

        logger.info(
            "log_analysis_completed",
            log_id=log_id,
            is_anomaly=is_anomaly,
            risk_score=round(final_score, 3),
            risk_level=risk_level,
            processing_time_ms=round(processing_time, 2),
        )

        # ========================================================================
        # 5. Save to database
        # ========================================================================
        try:
            from backend.db.database import get_db
            from backend.db import crud

            async with get_db() as session:
                # Save anomaly if detected
                if is_anomaly:
                    anomaly_data = {
                        "log_timestamp": parsed_data["timestamp"],
                        "source_ip": parsed_data["source_ip"],
                        "source_port": parsed_data.get("source_port"),
                        "destination_ip": parsed_data.get("destination_ip"),
                        "destination_port": parsed_data.get("destination_port"),
                        "username": parsed_data.get("username"),
                        "hostname": parsed_data.get("hostname"),
                        "event_type": parsed_data.get("event_type", "unknown"),
                        "risk_score": float(final_score),
                        "risk_level": risk_level.value,
                        "is_anomaly": is_anomaly,
                        "confidence": confidence,
                        "isolation_forest_score": float(model_scores["isolation_forest"]),
                        "dbscan_score": float(model_scores["dbscan"]),
                        "gmm_score": float(model_scores["gmm"]),
                        "features": features.to_dict(),
                        "reasons": reasons,
                        "recommended_action": recommended_action.value,
                        "raw_log": request.log_line,
                        "log_source": request.source.value,
                        "processing_time_ms": float(processing_time),
                        "model_version": prediction.get("model_version", "unknown"),
                    }
                    await crud.create_anomaly(session, anomaly_data)

                # Always save log entry
                # Convert datetime to string for JSON serialization
                parsed_fields_json = {
                    k: v.isoformat() if isinstance(v, datetime) else v
                    for k, v in parsed_data.items()
                }

                log_data = {
                    "log_timestamp": parsed_data["timestamp"],
                    "source_ip": parsed_data["source_ip"],
                    "source_port": parsed_data.get("source_port"),
                    "destination_ip": parsed_data.get("destination_ip"),
                    "destination_port": parsed_data.get("destination_port"),
                    "event_type": parsed_data.get("event_type", "unknown"),
                    "username": parsed_data.get("username"),
                    "hostname": parsed_data.get("hostname"),
                    "status_code": parsed_data.get("status_code"),
                    "success": parsed_data.get("success"),
                    "raw_log": request.log_line,
                    "log_source": request.source.value,
                    "parsed_fields": parsed_fields_json,
                    "risk_score": float(final_score),
                }
                await crud.create_log(session, log_data)

        except Exception as e:
            # Log error but don't fail the request
            logger.error("database_save_failed", error=str(e), log_id=log_id)

        return AnalysisResult(
            log_id=log_id,
            is_anomaly=is_anomaly,
            risk_score=round(final_score, 3),
            risk_level=risk_level,
            confidence=confidence,
            features=features.to_dict(),
            reasons=reasons,
            recommended_action=recommended_action,
            similar_anomalies=0,  # TODO: Query database for similar historical anomalies
            model_scores=model_scores,
            processing_time_ms=round(processing_time, 2),
            timestamp=datetime.now(timezone.utc),
        )

    except ValueError as e:
        logger.error("log_parsing_failed", log_id=log_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to parse log: {e}",
        ) from e

    except Exception as e:
        logger.exception("log_analysis_failed", log_id=log_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {e}",
        ) from e


@router.post(
    "/logs/batch",
    response_model=BatchAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze Multiple Logs",
    description="Analyze a batch of logs (up to 1000) for anomalies",
)
async def analyze_batch(request: BatchAnalyzeRequest) -> BatchAnalysisResponse:
    """
    Analyze multiple logs in a batch.

    More efficient than individual calls for bulk analysis.
    Features are extracted once and models process batch together.

    Args:
        request: Batch analysis request

    Returns:
        BatchAnalysisResponse with aggregated results

    Raises:
        HTTPException: 422 if batch validation fails
        HTTPException: 500 if analysis fails
    """
    import time

    start_time = time.time()

    logger.info("batch_analysis_started", batch_size=len(request.logs))

    try:
        # Analyze each log
        results = []
        for log_request in request.logs:
            result = await analyze_log(log_request)
            results.append(result)

        # Calculate statistics
        anomalies_detected = sum(1 for r in results if r.is_anomaly)
        anomaly_rate = anomalies_detected / len(results) if results else 0.0

        processing_time = (time.time() - start_time) * 1000

        logger.info(
            "batch_analysis_completed",
            total_logs=len(results),
            anomalies_detected=anomalies_detected,
            anomaly_rate=round(anomaly_rate, 3),
            processing_time_ms=round(processing_time, 2),
        )

        return BatchAnalysisResponse(
            total_logs=len(results),
            anomalies_detected=anomalies_detected,
            anomaly_rate=round(anomaly_rate, 3),
            results=results,
            processing_time_ms=round(processing_time, 2),
        )

    except Exception as e:
        logger.exception("batch_analysis_failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch analysis failed: {e}",
        ) from e
