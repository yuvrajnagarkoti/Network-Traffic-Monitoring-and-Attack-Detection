"""
Database models package.

All SQLAlchemy models are imported here so that Flask-Migrate can
discover them when generating migrations.
"""

from app.models.user import User, UserSession
from app.models.packet import PacketLog, ProtocolStats
from app.models.attack import AttackEvent, PortScanDetail, BruteForceDetail, DDoSDetail
from app.models.threat import ThreatScore, IpReputation, MlPrediction
from app.models.alert import Alert, AlertComment, EmailNotification
from app.models.block import IpBlock, Blacklist, Whitelist
from app.models.audit import AuditLog, SystemStats

__all__ = [
    "User",
    "UserSession",
    "PacketLog",
    "ProtocolStats",
    "AttackEvent",
    "PortScanDetail",
    "BruteForceDetail",
    "DDoSDetail",
    "ThreatScore",
    "IpReputation",
    "MlPrediction",
    "Alert",
    "AlertComment",
    "EmailNotification",
    "IpBlock",
    "Blacklist",
    "Whitelist",
    "AuditLog",
    "SystemStats",
]
