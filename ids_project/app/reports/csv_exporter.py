"""
Streaming CSV exporter.

Exports packet_logs rows as a memory-efficient streaming CSV response,
supporting up to 1,000,000 rows without OOM risk via Flask generator.
"""

import csv
import io
import logging
from datetime import datetime, timedelta, timezone
from typing import Generator, Optional

from app.models.packet import PacketLog

logger = logging.getLogger(__name__)

_BATCH = 5000   # rows per DB fetch
_CSV_HEADERS = ["id", "src_ip", "dst_ip", "src_port", "dst_port",
                 "protocol", "packet_size", "flags", "captured_at"]


def stream_packets_csv(
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    max_rows: int = 1_000_000,
) -> Generator[str, None, None]:
    """Yield CSV rows as a streaming generator.

    Each call fetches a batch of _BATCH rows using keyset pagination.
    Suitable for use with Flask's ``Response(stream_with_context(gen))``.

    Args:
        src_ip:     Optional source IP filter.
        dst_ip:     Optional destination IP filter.
        protocol:   Optional protocol filter.
        start_time: Start of time window.
        end_time:   End of time window.
        max_rows:   Absolute row cap.

    Yields:
        CSV lines as strings (with newline terminators).
    """
    # Header row
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_CSV_HEADERS)
    yield buf.getvalue()

    if start_time is None:
        start_time = datetime.now(timezone.utc) - timedelta(hours=24)
    if end_time is None:
        end_time = datetime.now(timezone.utc)

    cursor = 0
    total = 0

    while total < max_rows:
        query = PacketLog.query.filter(
            PacketLog.id > cursor,
            PacketLog.captured_at >= start_time,
            PacketLog.captured_at <= end_time,
        )

        if src_ip:
            query = query.filter(PacketLog.src_ip == src_ip)
        if dst_ip:
            query = query.filter(PacketLog.dst_ip == dst_ip)
        if protocol:
            query = query.filter(PacketLog.protocol == protocol.lower())

        batch = query.order_by(PacketLog.id.asc()).limit(_BATCH).all()

        if not batch:
            break

        buf = io.StringIO()
        writer = csv.writer(buf)

        for pkt in batch:
            writer.writerow([
                pkt.id, pkt.src_ip, pkt.dst_ip,
                pkt.src_port, pkt.dst_port,
                pkt.protocol, pkt.packet_size,
                pkt.flags or "",
                pkt.captured_at.isoformat() if pkt.captured_at else "",
            ])

        yield buf.getvalue()
        cursor = batch[-1].id
        total += len(batch)

        if len(batch) < _BATCH:
            break

    logger.info("CSV export complete: %d rows streamed", total)
