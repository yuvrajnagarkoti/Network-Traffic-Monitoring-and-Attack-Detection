"""
Packet monitoring database models.

PacketLog is the highest-volume table — designed for partitioning
and bulk inserts. ProtocolStats stores per-minute aggregations.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import BigInteger, Integer, String, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.extensions import db, INET


class PacketLog(db.Model):
    """Raw captured packet metadata.

    High-volume table designed for bulk inserts and date-range partitioning.
    Stores packet headers and hash only — never full payloads.
    """

    __tablename__ = "packet_logs"
    __table_args__ = (
        Index("ix_packet_logs_src_ip_captured_at", "src_ip", "captured_at"),
        Index("ix_packet_logs_dst_ip_captured_at", "dst_ip", "captured_at"),
        Index("ix_packet_logs_protocol_captured_at", "protocol", "captured_at"),
        Index("ix_packet_logs_ports", "src_port", "dst_port"),
        {"schema": None},
    )

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    src_ip: Mapped[str] = mapped_column(INET, nullable=False)
    dst_ip: Mapped[str] = mapped_column(INET, nullable=False)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)
    packet_size: Mapped[int] = mapped_column(Integer, nullable=False)
    flags: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    payload_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    def to_dict(self) -> dict:
        """Serialize packet log to dictionary."""
        return {
            "id": self.id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_size": self.packet_size,
            "flags": self.flags,
            "payload_hash": self.payload_hash,
            "captured_at": self.captured_at.isoformat() if self.captured_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<PacketLog {self.id} {self.protocol} "
            f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port}>"
        )


class ProtocolStats(db.Model):
    """Aggregated protocol statistics per time window.

    Updated every 60 seconds by the statistics aggregator.
    Drives dashboard protocol distribution charts.
    """

    __tablename__ = "protocol_stats"
    __table_args__ = (
        Index("ix_protocol_stats_window", "protocol", "window_start"),
    )

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)
    packet_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    byte_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    unique_src_ips: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unique_dst_ips: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    window_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    def to_dict(self) -> dict:
        """Serialize protocol stats to dictionary."""
        return {
            "id": self.id,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "unique_src_ips": self.unique_src_ips,
            "unique_dst_ips": self.unique_dst_ips,
            "window_start": self.window_start.isoformat() if self.window_start else None,
            "window_end": self.window_end.isoformat() if self.window_end else None,
        }

    def __repr__(self) -> str:
        return f"<ProtocolStats {self.protocol} count={self.packet_count} window={self.window_start}>"
