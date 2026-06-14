"""
Packet search engine.

Provides fast, cursor-paginated packet log queries filtered by:
  - source / destination IP (exact or CIDR range via PostgreSQL INET ops)
  - source / destination port
  - protocol
  - packet size range
  - time range

Uses keyset (cursor) pagination for O(1) performance on large tables.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.extensions import db
from app.models.packet import PacketLog

logger = logging.getLogger(__name__)

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50


class PacketSearchEngine:
    """High-performance packet log search with cursor-based pagination."""

    def search(
        self,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        min_size: Optional[int] = None,
        max_size: Optional[int] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        cursor: Optional[int] = None,
        limit: int = _DEFAULT_LIMIT,
        order: str = "desc",
    ) -> dict:
        """Execute a packet search.

        Args:
            src_ip:     Filter by source IP or CIDR (e.g. "192.168.1.0/24").
            dst_ip:     Filter by destination IP or CIDR.
            src_port:   Exact source port match.
            dst_port:   Exact destination port match.
            protocol:   Protocol string: tcp, udp, icmp, etc.
            min_size:   Minimum packet size in bytes.
            max_size:   Maximum packet size in bytes.
            start_time: Include only packets at or after this timestamp.
            end_time:   Include only packets at or before this timestamp.
            cursor:     Last seen packet ID for keyset pagination.
            limit:      Page size (max 200).
            order:      "desc" (newest first) or "asc" (oldest first).

        Returns:
            Dict with ``packets``, ``next_cursor``, ``count``.
        """
        limit = min(limit, _MAX_LIMIT)
        query = db.session.query(PacketLog)

        # IP filters — use PostgreSQL INET << operator for CIDR matching
        if src_ip:
            if "/" in src_ip:
                query = query.filter(
                    PacketLog.src_ip.op("<<")(src_ip)
                )
            else:
                query = query.filter(PacketLog.src_ip == src_ip)

        if dst_ip:
            if "/" in dst_ip:
                query = query.filter(
                    PacketLog.dst_ip.op("<<")(dst_ip)
                )
            else:
                query = query.filter(PacketLog.dst_ip == dst_ip)

        if src_port is not None:
            query = query.filter(PacketLog.src_port == src_port)

        if dst_port is not None:
            query = query.filter(PacketLog.dst_port == dst_port)

        if protocol:
            query = query.filter(PacketLog.protocol == protocol.lower())

        if min_size is not None:
            query = query.filter(PacketLog.packet_size >= min_size)

        if max_size is not None:
            query = query.filter(PacketLog.packet_size <= max_size)

        if start_time:
            query = query.filter(PacketLog.captured_at >= start_time)

        if end_time:
            query = query.filter(PacketLog.captured_at <= end_time)
        else:
            # Default: last 24 hours to avoid unbounded scans
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            query = query.filter(PacketLog.captured_at >= cutoff)

        # Keyset pagination
        if cursor is not None:
            if order == "desc":
                query = query.filter(PacketLog.id < cursor)
            else:
                query = query.filter(PacketLog.id > cursor)

        # Ordering
        if order == "desc":
            query = query.order_by(PacketLog.id.desc())
        else:
            query = query.order_by(PacketLog.id.asc())

        rows = query.limit(limit + 1).all()

        has_more = len(rows) > limit
        rows = rows[:limit]

        next_cursor = rows[-1].id if (has_more and rows) else None

        return {
            "packets": [r.to_dict() for r in rows],
            "count": len(rows),
            "next_cursor": next_cursor,
            "has_more": has_more,
        }
