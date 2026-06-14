"""
Batch insert manager for packet log storage.

Collects parsed packets in memory and flushes them to PostgreSQL
in batches for high-performance writes. Supports write-ahead
buffering when the database is temporarily unavailable.
"""

import logging
import queue
import threading
import time
from collections import deque
from typing import Optional

from sqlalchemy.exc import OperationalError, SQLAlchemyError

logger = logging.getLogger(__name__)

# Default batch configuration
DEFAULT_BATCH_SIZE = 500
DEFAULT_FLUSH_INTERVAL_MS = 500
DEFAULT_WAL_BUFFER_SIZE = 50_000


class BatchWriter:
    """High-performance batch insert manager.

    Collects parsed packet dictionaries and flushes them to
    the packet_logs table using bulk_insert_mappings() for
    optimal insert performance.

    Flush triggers (whichever comes first):
        - Timer: 500ms since last flush
        - Count: 500 packets accumulated
        - Shutdown: application shutting down (drain all)
    """

    def __init__(
        self,
        app=None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        flush_interval_ms: int = DEFAULT_FLUSH_INTERVAL_MS,
        wal_buffer_size: int = DEFAULT_WAL_BUFFER_SIZE,
    ) -> None:
        """Initialize batch writer.

        Args:
            app: Flask application instance (for app context).
            batch_size: Number of packets to accumulate before flush.
            flush_interval_ms: Maximum milliseconds between flushes.
            wal_buffer_size: Write-ahead buffer capacity when DB is down.
        """
        self.app = app
        self.batch_size = batch_size
        self.flush_interval_ms = flush_interval_ms

        # Main packet collection buffer
        self._buffer: list[dict] = []
        self._buffer_lock = threading.Lock()

        # Write-ahead log for DB unavailability
        self._wal_buffer: deque = deque(maxlen=wal_buffer_size)
        self._db_available = True

        # Background flusher thread
        self._running = False
        self._flush_thread: Optional[threading.Thread] = None

        # Statistics
        self._total_written: int = 0
        self._total_wal: int = 0
        self._total_flush_count: int = 0
        self._last_flush_time: float = time.time()
        self._last_flush_latency_ms: float = 0.0
        self._total_errors: int = 0

    def start(self) -> None:
        """Start the background flush thread."""
        if self._running:
            return

        self._running = True
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            daemon=True,
            name="batch-writer",
        )
        self._flush_thread.start()
        logger.info(
            "Batch writer started (size=%d, interval=%dms)",
            self.batch_size,
            self.flush_interval_ms,
        )

    def stop(self) -> None:
        """Stop the batch writer and flush remaining packets."""
        self._running = False
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=10)

        # Final drain
        self._flush_to_db()
        self._drain_wal()
        logger.info(
            "Batch writer stopped. Total written: %d, WAL remaining: %d",
            self._total_written,
            len(self._wal_buffer),
        )

    def add_packet(self, parsed_packet: dict) -> None:
        """Add a parsed packet to the write buffer.

        Thread-safe: called by multiple processing workers.

        Args:
            parsed_packet: Dictionary from PacketParser.parse().
        """
        # Extract only the fields that map to packet_logs columns
        db_record = {
            "src_ip": parsed_packet["src_ip"],
            "dst_ip": parsed_packet["dst_ip"],
            "src_port": parsed_packet.get("src_port"),
            "dst_port": parsed_packet.get("dst_port"),
            "protocol": parsed_packet.get("protocol", "Unknown"),
            "packet_size": parsed_packet.get("packet_size", 0),
            "flags": parsed_packet.get("flags"),
            "payload_hash": parsed_packet.get("payload_hash"),
            "captured_at": parsed_packet.get("captured_at"),
        }

        with self._buffer_lock:
            self._buffer.append(db_record)

            # Flush immediately if batch size reached
            if len(self._buffer) >= self.batch_size:
                self._flush_to_db()

    def _flush_loop(self) -> None:
        """Background loop that flushes on timer interval."""
        interval_seconds = self.flush_interval_ms / 1000.0

        while self._running:
            try:
                time.sleep(interval_seconds)
                self._flush_to_db()

                # Periodically try to drain WAL if DB is back
                if self._wal_buffer and self._db_available:
                    self._drain_wal()
            except Exception as exc:
                logger.error("Flush loop error: %s", exc)

    def _flush_to_db(self) -> None:
        """Flush the current buffer to PostgreSQL.

        Uses SQLAlchemy bulk_insert_mappings() for performance.
        On failure, packets are moved to the write-ahead buffer.
        """
        with self._buffer_lock:
            if not self._buffer:
                return
            batch = self._buffer.copy()
            self._buffer.clear()

        if not batch:
            return

        start_time = time.monotonic()

        try:
            if self.app is None:
                # Fallback: try to get current app
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.packet import PacketLog

                db.session.bulk_insert_mappings(PacketLog, batch)
                db.session.commit()

            latency_ms = (time.monotonic() - start_time) * 1000
            self._last_flush_latency_ms = latency_ms
            self._total_written += len(batch)
            self._total_flush_count += 1
            self._last_flush_time = time.time()
            self._db_available = True

            if latency_ms > 1000:
                logger.warning(
                    "Batch insert slow: %d packets in %.0fms",
                    len(batch),
                    latency_ms,
                )
            else:
                logger.debug(
                    "Flushed %d packets in %.1fms",
                    len(batch),
                    latency_ms,
                )

        except OperationalError as exc:
            logger.error("Database unavailable during flush: %s", exc)
            self._db_available = False
            self._total_errors += 1
            # Move to WAL buffer
            for record in batch:
                self._wal_buffer.append(record)
                self._total_wal += 1

        except SQLAlchemyError as exc:
            logger.error("Database error during flush: %s", exc)
            self._total_errors += 1
            try:
                if self.app:
                    with self.app.app_context():
                        from app.extensions import db
                        db.session.rollback()
            except Exception:
                pass

        except Exception as exc:
            logger.error("Unexpected flush error: %s", exc, exc_info=True)
            self._total_errors += 1

    def _drain_wal(self) -> None:
        """Attempt to flush write-ahead buffer to database.

        Called when the database becomes available again.
        Flushes in small batches to avoid overwhelming the DB.
        """
        if not self._wal_buffer:
            return

        drain_batch_size = min(len(self._wal_buffer), self.batch_size)
        drain_batch = []

        for _ in range(drain_batch_size):
            if self._wal_buffer:
                drain_batch.append(self._wal_buffer.popleft())

        if not drain_batch:
            return

        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.packet import PacketLog

                db.session.bulk_insert_mappings(PacketLog, drain_batch)
                db.session.commit()

            self._total_written += len(drain_batch)
            logger.info(
                "Drained %d packets from WAL buffer (%d remaining)",
                len(drain_batch),
                len(self._wal_buffer),
            )
        except Exception as exc:
            logger.error("WAL drain failed: %s", exc)
            # Put them back
            for record in reversed(drain_batch):
                self._wal_buffer.appendleft(record)

    @property
    def stats(self) -> dict:
        """Return batch writer statistics."""
        return {
            "total_written": self._total_written,
            "total_wal": self._total_wal,
            "total_flush_count": self._total_flush_count,
            "total_errors": self._total_errors,
            "buffer_size": len(self._buffer),
            "wal_buffer_size": len(self._wal_buffer),
            "db_available": self._db_available,
            "last_flush_latency_ms": round(self._last_flush_latency_ms, 2),
            "batch_size": self.batch_size,
            "flush_interval_ms": self.flush_interval_ms,
        }
