"""
Machine learning database models.

MLFeature and MLModelVersion for feature persistence
and model version tracking.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.extensions import db, JSONB


class MLFeature(db.Model):
    """Extracted feature vector for ML training and inference.

    Stores the 25-element feature vector computed from
    a network flow, with optional attack label.
    """

    __tablename__ = "ml_features"
    __table_args__ = (
        Index("ix_ml_features_extracted_at", "extracted_at"),
        Index("ix_ml_features_is_attack", "is_attack"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    flow_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    features: Mapped[list] = mapped_column(JSONB, nullable=False)
    is_attack: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    attack_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    extracted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def to_dict(self) -> dict:
        """Serialize feature record."""
        return {
            "id": str(self.id),
            "flow_id": self.flow_id,
            "feature_count": len(self.features) if self.features else 0,
            "is_attack": self.is_attack,
            "attack_type": self.attack_type,
            "extracted_at": self.extracted_at.isoformat() if self.extracted_at else None,
        }

    def __repr__(self) -> str:
        return f"<MLFeature flow={self.flow_id} attack={self.is_attack}>"


class MLModelVersion(db.Model):
    """Tracks trained ML model versions.

    Stores metadata for each model version including
    training parameters, validation metrics, and file paths.
    """

    __tablename__ = "ml_model_versions"
    __table_args__ = (
        Index("ix_ml_model_versions_is_active", "is_active"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    version: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    model_path: Mapped[str] = mapped_column(String(500), nullable=False)
    scaler_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    checksum: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    training_samples: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    feature_count: Mapped[int] = mapped_column(Integer, nullable=False, default=25)
    validation_auc: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    contamination: Mapped[float] = mapped_column(Float, nullable=False, default=0.01)
    n_estimators: Mapped[int] = mapped_column(Integer, nullable=False, default=200)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    trained_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def to_dict(self) -> dict:
        """Serialize model version."""
        return {
            "id": str(self.id),
            "version": self.version,
            "model_path": self.model_path,
            "validation_auc": self.validation_auc,
            "training_samples": self.training_samples,
            "is_active": self.is_active,
            "trained_at": self.trained_at.isoformat() if self.trained_at else None,
        }

    def __repr__(self) -> str:
        return f"<MLModelVersion {self.version} active={self.is_active} AUC={self.validation_auc:.3f}>"
