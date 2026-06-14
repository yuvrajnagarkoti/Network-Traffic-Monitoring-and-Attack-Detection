"""
Audit logging and system statistics database models.

AuditLog is append-only by design — the application never issues
UPDATE or DELETE on this table. SystemStats stores time-series
performance metrics in 1-minute buckets.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    BigInteger, Integer, Float, String, DateTime, Text, Index,
)
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.extensions import db


class AuditLog(db.Model):
    """Immutable audit trail for security-relevant actions.

    Records all admin actions, authentication events, and
    configuration changes. This table is append-only — no
    UPDATE or DELETE operations are permitted programmatically.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_user_created", "user_id", "created_at"),
        Index("ix_audit_logs_action_created", "action", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    old_value: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    new_value: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    def to_dict(self) -> dict:
        """Serialize audit log entry to dictionary."""
        return {
            "id": self.id,
            "user_id": str(self.user_id) if self.user_id else None,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<AuditLog {self.id} action={self.action} user={self.user_id}>"


class SystemStats(db.Model):
    """System performance metrics in 1-minute time-series buckets.

    Populated by the statistics aggregator every 60 seconds.
    Drives dashboard performance charts and traffic baselines.
    """

    __tablename__ = "system_stats"
    __table_args__ = (
        Index("ix_system_stats_recorded_at", "recorded_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    packets_per_second: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    bytes_per_second: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    active_connections: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    alerts_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    blocked_ips_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    cpu_usage_percent: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    memory_usage_mb: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    db_connections_active: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    packet_drop_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def to_dict(self) -> dict:
        """Serialize system stats to dictionary."""
        return {
            "id": self.id,
            "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second,
            "active_connections": self.active_connections,
            "alerts_count": self.alerts_count,
            "blocked_ips_count": self.blocked_ips_count,
            "cpu_usage_percent": self.cpu_usage_percent,
            "memory_usage_mb": self.memory_usage_mb,
            "db_connections_active": self.db_connections_active,
            "packet_drop_rate": self.packet_drop_rate,
            "recorded_at": self.recorded_at.isoformat() if self.recorded_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<SystemStats pps={self.packets_per_second:.0f} "
            f"alerts={self.alerts_count} at={self.recorded_at}>"
        )
