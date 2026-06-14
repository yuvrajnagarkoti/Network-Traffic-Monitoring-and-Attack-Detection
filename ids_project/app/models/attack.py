"""
Attack detection database models.

AttackEvent is the central detection record. Each attack type
has a specialized detail table for type-specific evidence.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    String, Integer, Float, DateTime, Text,
    Enum as SAEnum, Index,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db, INET, JSONB, ARRAY


class AttackType(str, enum.Enum):
    """Enumeration of detectable attack types."""
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DDOS = "ddos"
    TRAFFIC_ANOMALY = "traffic_anomaly"
    ML_ANOMALY = "ml_anomaly"


class AttackStatus(str, enum.Enum):
    """Attack event lifecycle status."""
    ACTIVE = "active"
    MONITORING = "monitoring"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ScanTechnique(str, enum.Enum):
    """Port scan technique classification."""
    SYN = "syn"
    CONNECT = "connect"
    UDP = "udp"
    FIN = "fin"
    XMAS = "xmas"
    NULL = "null"


class AttackEvent(db.Model):
    """Core attack detection record.

    Created by the detection orchestrator when any detector
    identifies an attack. Linked to type-specific detail tables.
    """

    __tablename__ = "attack_events"
    __table_args__ = (
        Index("ix_attack_events_source_ip_first_seen", "source_ip", "first_seen"),
        Index("ix_attack_events_type_status", "attack_type", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    attack_type: Mapped[str] = mapped_column(
        SAEnum(AttackType, name="attack_type_enum", create_constraint=True, native_enum=True),
        nullable=False,
    )
    source_ip: Mapped[str] = mapped_column(INET, nullable=False, index=True)
    target_ip: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    target_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    evidence: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True, default=dict)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        SAEnum(AttackStatus, name="attack_status_enum", create_constraint=True, native_enum=True),
        nullable=False,
        default=AttackStatus.ACTIVE,
    )

    # Relationships
    port_scan_detail: Mapped[Optional["PortScanDetail"]] = relationship(
        "PortScanDetail", back_populates="attack_event", uselist=False, cascade="all, delete-orphan"
    )
    brute_force_detail: Mapped[Optional["BruteForceDetail"]] = relationship(
        "BruteForceDetail", back_populates="attack_event", uselist=False, cascade="all, delete-orphan"
    )
    ddos_detail: Mapped[Optional["DDoSDetail"]] = relationship(
        "DDoSDetail", back_populates="attack_event", uselist=False, cascade="all, delete-orphan"
    )
    threat_score: Mapped[Optional["ThreatScore"]] = relationship(
        "ThreatScore", back_populates="attack_event", uselist=False, cascade="all, delete-orphan"
    )
    alerts: Mapped[list["Alert"]] = relationship(
        "Alert", back_populates="attack_event", cascade="all, delete-orphan", lazy="dynamic"
    )
    ml_predictions: Mapped[list["MlPrediction"]] = relationship(
        "MlPrediction", back_populates="attack_event", cascade="all, delete-orphan", lazy="dynamic"
    )

    def to_dict(self) -> dict:
        """Serialize attack event to dictionary."""
        return {
            "id": str(self.id),
            "attack_type": self.attack_type.value if isinstance(self.attack_type, AttackType) else self.attack_type,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "evidence": self.evidence,
            "confidence_score": self.confidence_score,
            "packet_count": self.packet_count,
            "duration_seconds": self.duration_seconds,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "status": self.status.value if isinstance(self.status, AttackStatus) else self.status,
        }

    def __repr__(self) -> str:
        return f"<AttackEvent {self.id} {self.attack_type} from {self.source_ip} ({self.status})>"


class PortScanDetail(db.Model):
    """Extended details for port scan attack events."""

    __tablename__ = "port_scan_details"

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
    scanned_ports: Mapped[Optional[list]] = mapped_column(
        ARRAY(Integer), nullable=True
    )
    scan_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    scan_pattern: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    technique: Mapped[Optional[str]] = mapped_column(
        SAEnum(ScanTechnique, name="scan_technique_enum", create_constraint=True, native_enum=True),
        nullable=True,
    )

    # Relationships
    attack_event: Mapped["AttackEvent"] = relationship(
        "AttackEvent", back_populates="port_scan_detail"
    )

    def to_dict(self) -> dict:
        """Serialize port scan details to dictionary."""
        return {
            "id": str(self.id),
            "attack_event_id": str(self.attack_event_id),
            "scanned_ports": self.scanned_ports,
            "scan_rate": self.scan_rate,
            "scan_pattern": self.scan_pattern,
            "technique": self.technique.value if isinstance(self.technique, ScanTechnique) else self.technique,
        }

    def __repr__(self) -> str:
        return f"<PortScanDetail event={self.attack_event_id} ports={len(self.scanned_ports or [])}>"


class BruteForceDetail(db.Model):
    """Extended details for brute force attack events."""

    __tablename__ = "brute_force_details"

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
    targeted_service: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    attempt_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    usernames_tried: Mapped[Optional[list]] = mapped_column(
        ARRAY(Text), nullable=True
    )

    # Relationships
    attack_event: Mapped["AttackEvent"] = relationship(
        "AttackEvent", back_populates="brute_force_detail"
    )

    def to_dict(self) -> dict:
        """Serialize brute force details to dictionary."""
        return {
            "id": str(self.id),
            "attack_event_id": str(self.attack_event_id),
            "targeted_service": self.targeted_service,
            "failed_attempts": self.failed_attempts,
            "attempt_rate": self.attempt_rate,
            "usernames_tried": self.usernames_tried,
        }

    def __repr__(self) -> str:
        return f"<BruteForceDetail event={self.attack_event_id} service={self.targeted_service}>"


class DDoSDetail(db.Model):
    """Extended details for DDoS attack events."""

    __tablename__ = "ddos_details"

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
    attack_vector: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    packets_per_second: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    bytes_per_second: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    contributing_ips: Mapped[Optional[list]] = mapped_column(
        ARRAY(INET), nullable=True
    )
    amplification_factor: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Relationships
    attack_event: Mapped["AttackEvent"] = relationship(
        "AttackEvent", back_populates="ddos_detail"
    )

    def to_dict(self) -> dict:
        """Serialize DDoS details to dictionary."""
        return {
            "id": str(self.id),
            "attack_event_id": str(self.attack_event_id),
            "attack_vector": self.attack_vector,
            "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second,
            "contributing_ips": self.contributing_ips,
            "amplification_factor": self.amplification_factor,
        }

    def __repr__(self) -> str:
        return f"<DDoSDetail event={self.attack_event_id} vector={self.attack_vector}>"
