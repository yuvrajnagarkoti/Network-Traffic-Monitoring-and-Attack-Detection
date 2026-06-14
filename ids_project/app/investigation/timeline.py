"""
Attack timeline reconstructor.

Builds a chronological sequence of packets and events that
triggered a specific alert / attack event.
"""

import logging
from datetime import timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class AttackTimeline:
    """Reconstructs the event sequence for a given attack event."""

    def __init__(self, app=None) -> None:
        self.app = app

    def build(self, attack_event_id: str, context_minutes: int = 5) -> dict:
        """Build a timeline for an attack event.

        Fetches the attack event details, related packets from its source
        IP within the time window, and any associated alerts/scores.

        Args:
            attack_event_id: UUID string of the AttackEvent record.
            context_minutes: Minutes before/after the attack to include.

        Returns:
            Dict with event metadata, timeline entries, and summary.
        """
        _app = self._get_app()
        with _app.app_context():
            from app.models.attack import AttackEvent
            from app.models.packet import PacketLog
            from app.models.alert import Alert
            from app.extensions import db

            event = db.session.get(AttackEvent, attack_event_id)
            if not event:
                return {"error": "Attack event not found"}

            # Time window
            start = event.first_seen - timedelta(minutes=context_minutes)
            end = (event.last_seen or event.first_seen) + timedelta(minutes=context_minutes)

            # Packets from source IP in window
            packets = (
                PacketLog.query
                .filter(
                    PacketLog.src_ip == str(event.source_ip),
                    PacketLog.captured_at >= start,
                    PacketLog.captured_at <= end,
                )
                .order_by(PacketLog.captured_at.asc())
                .limit(500)
                .all()
            )

            # Related alerts
            alerts = Alert.query.filter_by(attack_event_id=attack_event_id).all()

            timeline = []
            for pkt in packets:
                timeline.append({
                    "ts": pkt.captured_at.isoformat(),
                    "type": "packet",
                    "src": f"{pkt.src_ip}:{pkt.src_port}",
                    "dst": f"{pkt.dst_ip}:{pkt.dst_port}",
                    "protocol": pkt.protocol,
                    "size": pkt.packet_size,
                    "flags": pkt.flags,
                })

            return {
                "attack_event": event.to_dict() if hasattr(event, "to_dict") else {"id": str(event.id)},
                "window": {"start": start.isoformat(), "end": end.isoformat()},
                "timeline": timeline,
                "packet_count": len(packets),
                "alerts": [a.to_dict() for a in alerts],
            }

    def _get_app(self):
        if self.app is not None:
            return self.app
        from flask import current_app
        return current_app._get_current_object()
