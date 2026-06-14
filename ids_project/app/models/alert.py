"""
Alert and notification database models.

Manages alert lifecycle, analyst comments, and email
notification queue with retry tracking.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    String, Integer, DateTime, Text,
    Enum as SAEnum, Index,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db


class AlertStatus(str, enum.Enum):
    """Alert lifecycle status."""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertSeverity(str, enum.Enum):
    """Alert severity level."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EmailDeliveryStatus(str, enum.Enum):
    """Email delivery tracking status."""
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    PERMANENTLY_FAILED = "permanently_failed"


class Alert(db.Model):
    """Security alert created from scored threat events.

    Supports full lifecycle tracking from creation through
    analyst investigation to resolution.
    """

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_severity_status_created", "severity", "status", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    attack_event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("attack_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    threat_score_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("threat_scores.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(
        SAEnum(AlertSeverity, name="alert_severity_enum", create_constraint=True, native_enum=True),
        nullable=False,
        default=AlertSeverity.MEDIUM,
    )
    status: Mapped[str] = mapped_column(
        SAEnum(AlertStatus, name="alert_status_enum", create_constraint=True, native_enum=True),
        nullable=False,
        default=AlertStatus.NEW,
    )
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    attack_event: Mapped["AttackEvent"] = relationship(
        "AttackEvent", back_populates="alerts"
    )
    threat_score: Mapped[Optional["ThreatScore"]] = relationship(
        "ThreatScore", back_populates="alert"
    )
    assigned_user: Mapped[Optional["User"]] = relationship(
        "User", back_populates="alerts_assigned", foreign_keys=[assigned_to]
    )
    comments: Mapped[list["AlertComment"]] = relationship(
        "AlertComment", back_populates="alert", cascade="all, delete-orphan",
        lazy="dynamic", order_by="AlertComment.created_at"
    )
    email_notifications: Mapped[list["EmailNotification"]] = relationship(
        "EmailNotification", back_populates="alert", cascade="all, delete-orphan", lazy="dynamic"
    )

    def to_dict(self) -> dict:
        """Serialize alert to dictionary."""
        return {
            "id": str(self.id),
            "attack_event_id": str(self.attack_event_id),
            "threat_score_id": str(self.threat_score_id) if self.threat_score_id else None,
            "title": self.title,
            "message": self.message,
            "severity": self.severity.value if isinstance(self.severity, AlertSeverity) else self.severity,
            "status": self.status.value if isinstance(self.status, AlertStatus) else self.status,
            "assigned_to": str(self.assigned_to) if self.assigned_to else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }

    def __repr__(self) -> str:
        return f"<Alert {self.id} [{self.severity}] {self.title[:40]} ({self.status})>"


class AlertComment(db.Model):
    """Analyst comment on an alert for investigation notes."""

    __tablename__ = "alert_comments"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    comment: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    alert: Mapped["Alert"] = relationship("Alert", back_populates="comments")
    user: Mapped[Optional["User"]] = relationship("User")

    def to_dict(self) -> dict:
        """Serialize alert comment to dictionary."""
        return {
            "id": str(self.id),
            "alert_id": str(self.alert_id),
            "user_id": str(self.user_id) if self.user_id else None,
            "comment": self.comment,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<AlertComment alert={self.alert_id} by={self.user_id}>"


class EmailNotification(db.Model):
    """Email notification queue entry with retry tracking.

    Background worker polls pending entries and sends via SMTP.
    Failed deliveries are retried with exponential backoff.
    """

    __tablename__ = "email_notifications"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    alert_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    recipient_email: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    body_template: Mapped[str] = mapped_column(Text, nullable=False)
    sent_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    delivery_status: Mapped[str] = mapped_column(
        SAEnum(
            EmailDeliveryStatus,
            name="email_delivery_status_enum",
            create_constraint=True,
            native_enum=True,
        ),
        nullable=False,
        default=EmailDeliveryStatus.PENDING,
    )
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_retry_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    alert: Mapped[Optional["Alert"]] = relationship(
        "Alert", back_populates="email_notifications"
    )

    def to_dict(self) -> dict:
        """Serialize email notification to dictionary."""
        return {
            "id": str(self.id),
            "alert_id": str(self.alert_id) if self.alert_id else None,
            "recipient_email": self.recipient_email,
            "subject": self.subject,
            "delivery_status": (
                self.delivery_status.value
                if isinstance(self.delivery_status, EmailDeliveryStatus)
                else self.delivery_status
            ),
            "retry_count": self.retry_count,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<EmailNotification to={self.recipient_email} status={self.delivery_status}>"
