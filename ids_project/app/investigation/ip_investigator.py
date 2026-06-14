"""
IP investigator — profiles a suspicious IP address.

Provides:
  - Attack history (all events from this IP)
  - Active / past blocks
  - IP reputation score
  - Packet volume statistics
  - Related /24 subnet activity
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class IPInvestigator:
    """Profile tool for investigating malicious or suspicious IP addresses."""

    def __init__(self, app=None) -> None:
        self.app = app

    def profile(self, ip: str, days: int = 30) -> dict:
        """Build a comprehensive IP profile.

        Args:
            ip:   Target IP address string.
            days: Historical window in days (default 30).

        Returns:
            Dict with attack_events, blocks, reputation, packet_stats,
            subnet_activity, and summary.
        """
        _app = self._get_app()
        with _app.app_context():
            from app.extensions import db
            from app.models.attack import AttackEvent
            from app.models.block import IpBlock
            from app.models.intelligence import IpReputation
            from app.models.packet import PacketLog
            from sqlalchemy import func

            cutoff = datetime.now(timezone.utc) - timedelta(days=days)

            # Attack events from this IP
            events = (
                AttackEvent.query
                .filter(
                    AttackEvent.source_ip == ip,
                    AttackEvent.first_seen >= cutoff,
                )
                .order_by(AttackEvent.first_seen.desc())
                .limit(100)
                .all()
            )

            # Block history
            blocks = (
                IpBlock.query
                .filter(IpBlock.ip_address == ip)
                .order_by(IpBlock.blocked_at.desc())
                .limit(20)
                .all()
            )

            # IP reputation
            rep = IpReputation.query.filter_by(ip_address=ip).first()

            # Packet statistics
            pkt_stats = (
                db.session.query(
                    func.count(PacketLog.id).label("total_packets"),
                    func.sum(PacketLog.packet_size).label("total_bytes"),
                    func.min(PacketLog.captured_at).label("first_seen"),
                    func.max(PacketLog.captured_at).label("last_seen"),
                )
                .filter(PacketLog.src_ip == ip, PacketLog.captured_at >= cutoff)
                .first()
            )

            # Related /24 subnet IPs with attack events
            subnet = ".".join(ip.split(".")[:3]) + "." if "." in ip else ip
            subnet_ips = []
            if "." in ip:
                subnet_cidr = ".".join(ip.split(".")[:3]) + ".0/24"
                subnet_events = (
                    db.session.query(AttackEvent.source_ip, func.count(AttackEvent.id).label("cnt"))
                    .filter(AttackEvent.source_ip.op("<<")(subnet_cidr))
                    .filter(AttackEvent.first_seen >= cutoff)
                    .group_by(AttackEvent.source_ip)
                    .order_by(func.count(AttackEvent.id).desc())
                    .limit(10)
                    .all()
                )
                subnet_ips = [{"ip": str(r.source_ip), "event_count": r.cnt} for r in subnet_events]

            return {
                "ip": ip,
                "days_window": days,
                "attack_events": [
                    e.to_dict() if hasattr(e, "to_dict") else {"id": str(e.id)} for e in events
                ],
                "attack_count": len(events),
                "blocks": [b.to_dict() for b in blocks],
                "is_currently_blocked": any(b.is_active for b in blocks),
                "reputation": rep.to_dict() if rep else None,
                "packet_stats": {
                    "total_packets": int(pkt_stats.total_packets or 0),
                    "total_bytes": int(pkt_stats.total_bytes or 0),
                    "first_seen": pkt_stats.first_seen.isoformat() if pkt_stats.first_seen else None,
                    "last_seen": pkt_stats.last_seen.isoformat() if pkt_stats.last_seen else None,
                },
                "subnet_activity": subnet_ips,
            }

    def _get_app(self):
        if self.app is not None:
            return self.app
        from flask import current_app
        return current_app._get_current_object()
