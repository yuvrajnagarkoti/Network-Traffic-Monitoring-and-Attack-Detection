"""
Threat intelligence database models.

ThreatScore, IpReputation, and MlPrediction models for the
intelligence and scoring layers.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    String, Integer, Float, Boolean, DateTime, Text,
    Enum as SAEnum, Index,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db, INET, JSONB, ARRAY


class SeverityLevel(str, enum.Enum):
    """Threat severity classification."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatScore(db.Model):
    """Computed threat score for an attack event.

    Aggregates base score, rate modifier, IP reputation,
    ML confidence, and whitelist/blacklist overrides.
    """

    __tablename__ = "threat_scores"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    attack_event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("attack_events.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    base_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rate_modifier: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_modifier: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    recurrence_modifier: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ip_reputation_modifier: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ml_confidence_modifier: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    blacklist_modifier: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    whitelist_override: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    final_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    severity: Mapped[str] = mapped_column(
        SAEnum(SeverityLevel, name="severity_level_enum", create_constraint=True, native_enum=True),
        nullable=False,
        default=SeverityLevel.LOW,
    )
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    calculated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    attack_event: Mapped["AttackEvent"] = relationship(
        "AttackEvent", back_populates="threat_score"
    )
    alert: Mapped[Optional["Alert"]] = relationship(
        "Alert", back_populates="threat_score", uselist=False
    )

    def to_dict(self) -> dict:
        """Serialize threat score with full breakdown."""
        return {
            "id": str(self.id),
            "attack_event_id": str(self.attack_event_id),
            "base_score": self.base_score,
            "rate_modifier": self.rate_modifier,
            "duration_modifier": self.duration_modifier,
            "recurrence_modifier": self.recurrence_modifier,
            "ip_reputation_modifier": self.ip_reputation_modifier,
            "ml_confidence_modifier": self.ml_confidence_modifier,
            "blacklist_modifier": self.blacklist_modifier,
            "whitelist_override": self.whitelist_override,
            "final_score": self.final_score,
            "severity": self.severity.value if isinstance(self.severity, SeverityLevel) else self.severity,
            "explanation": self.explanation,
            "calculated_at": self.calculated_at.isoformat() if self.calculated_at else None,
        }

    def __repr__(self) -> str:
        return f"<ThreatScore {self.final_score} ({self.severity}) for event={self.attack_event_id}>"


class IpReputation(db.Model):
    """IP address reputation data from threat intelligence sources.

    Cached with 24-hour TTL. Primary key is the IP address itself.
    """

    __tablename__ = "ip_reputation"

    ip_address: Mapped[str] = mapped_column(INET, primary_key=True)
    reputation_score: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    categories: Mapped[Optional[list]] = mapped_column(ARRAY(Text), nullable=True)
    sources: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True, default=dict)
    country_code: Mapped[Optional[str]] = mapped_column(String(3), nullable=True)
    asn: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    as_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    last_checked: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    manual_override: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    @property
    def risk_level(self) -> str:
        """Classify risk based on reputation score."""
        if self.reputation_score <= 25:
            return "clean"
        elif self.reputation_score <= 50:
            return "suspicious"
        elif self.reputation_score <= 75:
            return "likely_malicious"
        else:
            return "confirmed_malicious"

    def to_dict(self) -> dict:
        """Serialize IP reputation to dictionary."""
        return {
            "ip_address": self.ip_address,
            "reputation_score": self.reputation_score,
            "risk_level": self.risk_level,
            "is_malicious": self.is_malicious,
            "categories": self.categories,
            "sources": self.sources,
            "country_code": self.country_code,
            "asn": self.asn,
            "as_name": self.as_name,
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
            "manual_override": self.manual_override,
        }

    def __repr__(self) -> str:
        return f"<IpReputation {self.ip_address} score={self.reputation_score} ({self.risk_level})>"


class MlPrediction(db.Model):
    """Machine learning model prediction record.

    Stores individual predictions with feature vectors for
    model performance tracking and retraining.
    """

    __tablename__ = "ml_predictions"
    __table_args__ = (
        Index("ix_ml_predictions_predicted_at", "predicted_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    packet_feature_vector: Mapped[Optional[list]] = mapped_column(
        ARRAY(Float), nullable=True
    )
    prediction: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)
    predicted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    attack_event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("attack_events.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Relationships
    attack_event: Mapped[Optional["AttackEvent"]] = relationship(
        "AttackEvent", back_populates="ml_predictions"
    )

    def to_dict(self) -> dict:
        """Serialize ML prediction to dictionary."""
        return {
            "id": str(self.id),
            "prediction": self.prediction,
            "confidence": self.confidence,
            "model_version": self.model_version,
            "predicted_at": self.predicted_at.isoformat() if self.predicted_at else None,
            "attack_event_id": str(self.attack_event_id) if self.attack_event_id else None,
        }

    def __repr__(self) -> str:
        return f"<MlPrediction {self.prediction} confidence={self.confidence:.2f}>"
