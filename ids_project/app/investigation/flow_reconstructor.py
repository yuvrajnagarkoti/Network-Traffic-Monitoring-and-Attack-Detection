"""
TCP flow reconstructor.

Reassembles bidirectional TCP packet sequences for a given
source/destination pair within a time window.  The output
contains the ordered packet list and a summary suitable for
display in the investigation dashboard.

Note: Actual PCAP export requires Scapy and is only possible
on Linux hosts where raw packets are captured.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class TCPFlowReconstructor:
    """Reassembles TCP bidirectional flows from the packet_logs table."""

    def __init__(self, app=None) -> None:
        self.app = app

    def reconstruct(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_packets: int = 1000,
    ) -> dict:
        """Fetch and reconstruct a bidirectional TCP flow.

        Args:
            src_ip:      Client-side IP.
            dst_ip:      Server-side IP.
            src_port:    Client source port (optional).
            dst_port:    Server destination port (optional filter).
            start_time:  Window start (defaults to 1 hour ago).
            end_time:    Window end (defaults to now).
            max_packets: Cap on total packets returned.

        Returns:
            Dict with ``flow_packets``, ``stats``, and ``summary``.
        """
        _app = self._get_app()
        with _app.app_context():
            from app.models.packet import PacketLog
            from sqlalchemy import or_, and_

            if start_time is None:
                start_time = datetime.now(timezone.utc) - timedelta(hours=1)
            if end_time is None:
                end_time = datetime.now(timezone.utc)

            # Bidirectional match: A→B or B→A
            direction_a = and_(PacketLog.src_ip == src_ip, PacketLog.dst_ip == dst_ip)
            direction_b = and_(PacketLog.src_ip == dst_ip, PacketLog.dst_ip == src_ip)

            query = (
                PacketLog.query
                .filter(
                    or_(direction_a, direction_b),
                    PacketLog.protocol.in_(["tcp", "TCP"]),
                    PacketLog.captured_at >= start_time,
                    PacketLog.captured_at <= end_time,
                )
                .order_by(PacketLog.captured_at.asc())
                .limit(max_packets)
            )

            if src_port:
                query = query.filter(PacketLog.src_port == src_port)
            if dst_port:
                query = query.filter(PacketLog.dst_port == dst_port)

            packets = query.all()

            total_bytes = sum(p.packet_size for p in packets)
            flags_seen = set()
            for p in packets:
                if p.flags:
                    flags_seen.update(p.flags.split(","))

            flow_packets = []
            for pkt in packets:
                direction = "→" if pkt.src_ip == src_ip else "←"
                flow_packets.append({
                    "ts": pkt.captured_at.isoformat(),
                    "direction": direction,
                    "src": f"{pkt.src_ip}:{pkt.src_port}",
                    "dst": f"{pkt.dst_ip}:{pkt.dst_port}",
                    "size": pkt.packet_size,
                    "flags": pkt.flags,
                    "payload_hash": pkt.payload_hash,
                })

            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "window": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                },
                "stats": {
                    "total_packets": len(packets),
                    "total_bytes": total_bytes,
                    "tcp_flags": sorted(flags_seen),
                },
                "flow_packets": flow_packets,
                "summary": (
                    f"TCP flow {src_ip} ↔ {dst_ip}: "
                    f"{len(packets)} packets, {total_bytes:,} bytes, "
                    f"flags=[{', '.join(sorted(flags_seen))}]"
                ),
            }

    def _get_app(self):
        if self.app is not None:
            return self.app
        from flask import current_app
        return current_app._get_current_object()
