"""
IP blocking and list management database models.

Manages automatic/manual IP blocks via iptables,
and blacklist/whitelist for reputation scoring.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    String, Boolean, DateTime, Text,
    Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db, INET


class BlockType(str, enum.Enum):
    """IP block origin type."""
    AUTO = "auto"
    MANUAL = "manual"


class IpBlock(db.Model):
    """Active IP block record with iptables rule tracking.

    Supports temporary blocks with auto-expiry and permanent blocks.
    All blocks are audited with reason and originator.
    """

    __tablename__ = "ip_blocks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ip_address: Mapped[str] = mapped_column(INET, nullable=False, unique=True, index=True)
    block_type: Mapped[str] = mapped_column(
        SAEnum(BlockType, name="block_type_enum", create_constraint=True, native_enum=True),
        nullable=False,
        default=BlockType.MANUAL,
    )
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    blocked_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    attack_event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("attack_events.id", ondelete="SET NULL"),
        nullable=True,
    )
    blocked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    firewall_rule_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Relationships
    blocked_by_user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[blocked_by])
    attack_event: Mapped[Optional["AttackEvent"]] = relationship("AttackEvent")

    @property
    def is_expired(self) -> bool:
        """Check if a temporary block has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_permanent(self) -> bool:
        """Check if block is permanent (no expiry)."""
        return self.expires_at is None

    def to_dict(self) -> dict:
        """Serialize IP block to dictionary."""
        return {
            "id": str(self.id),
            "ip_address": self.ip_address,
            "block_type": self.block_type.value if isinstance(self.block_type, BlockType) else self.block_type,
            "reason": self.reason,
            "blocked_by": str(self.blocked_by) if self.blocked_by else None,
            "attack_event_id": str(self.attack_event_id) if self.attack_event_id else None,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active,
            "is_permanent": self.is_permanent,
            "is_expired": self.is_expired,
            "firewall_rule_id": self.firewall_rule_id,
        }

    def __repr__(self) -> str:
        status = "active" if self.is_active else "inactive"
        return f"<IpBlock {self.ip_address} type={self.block_type} {status}>"


class Blacklist(db.Model):
    """Blacklisted IP addresses.

    IPs on the blacklist receive a +20 score modifier and are
    blocked on first contact if score reaches CRITICAL threshold.
    """

    __tablename__ = "blacklist"

    ip_address: Mapped[str] = mapped_column(INET, primary_key=True)
    added_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    is_permanent: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    added_by_user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[added_by])

    def to_dict(self) -> dict:
        """Serialize blacklist entry to dictionary."""
        return {
            "ip_address": self.ip_address,
            "added_by": str(self.added_by) if self.added_by else None,
            "reason": self.reason,
            "source": self.source,
            "added_at": self.added_at.isoformat() if self.added_at else None,
            "is_permanent": self.is_permanent,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }

    def __repr__(self) -> str:
        return f"<Blacklist {self.ip_address} source={self.source}>"


class Whitelist(db.Model):
    """Whitelisted IP addresses.

    Whitelisted IPs are never blocked, never alerted on, and
    always score 0 regardless of detection signals.
    """

    __tablename__ = "whitelist"

    ip_address: Mapped[str] = mapped_column(INET, primary_key=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    added_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    added_by_user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[added_by])

    def to_dict(self) -> dict:
        """Serialize whitelist entry to dictionary."""
        return {
            "ip_address": self.ip_address,
            "description": self.description,
            "added_by": str(self.added_by) if self.added_by else None,
            "added_at": self.added_at.isoformat() if self.added_at else None,
        }

    def __repr__(self) -> str:
        return f"<Whitelist {self.ip_address}>"
