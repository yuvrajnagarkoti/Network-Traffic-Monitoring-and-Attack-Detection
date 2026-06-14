"""
Traffic statistics aggregator.

Collects per-minute traffic statistics from the packet stream
and writes them to the protocol_stats and system_stats tables.
Drives dashboard charts and traffic pattern analysis.
"""

import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Default aggregation interval in seconds
DEFAULT_AGGREGATION_INTERVAL = 60


class StatsAggregator:
    """Computes periodic traffic statistics from the packet stream.

    Runs a background thread that aggregates packet metrics every
    60 seconds and writes to protocol_stats and system_stats tables.

    Thread-safe: metrics are updated by processing workers via
    record_packet() and read by the API via get_current_stats().
    """

    def __init__(
        self,
        app=None,
        interval: int = DEFAULT_AGGREGATION_INTERVAL,
    ) -> None:
        """Initialize statistics aggregator.

        Args:
            app: Flask application instance.
            interval: Aggregation cycle duration in seconds.
        """
        self.app = app
        self.interval = interval

        # Current window counters (reset every cycle)
        self._lock = threading.Lock()
        self._packet_count: int = 0
        self._byte_count: int = 0
        self._protocol_counts: dict[str, int] = defaultdict(int)
        self._protocol_bytes: dict[str, int] = defaultdict(int)
        self._src_ip_counts: dict[str, int] = defaultdict(int)
        self._dst_ip_counts: dict[str, int] = defaultdict(int)
        self._src_ips_per_protocol: dict[str, set] = defaultdict(set)
        self._dst_ips_per_protocol: dict[str, set] = defaultdict(set)
        self._window_start: float = time.time()

        # Latest computed stats (thread-safe read)
        self._latest_stats: dict = {}
        self._latest_protocol_stats: list[dict] = []
        self._latest_top_talkers: list[dict] = []

        # Background thread
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._total_cycles: int = 0

    def record_packet(self, parsed_packet: dict) -> None:
        """Record a packet into the current aggregation window.

        Thread-safe: called by multiple processing workers.

        Args:
            parsed_packet: Parsed packet dictionary.
        """
        with self._lock:
            self._packet_count += 1
            size = parsed_packet.get("packet_size", 0)
            self._byte_count += size

            protocol = parsed_packet.get("protocol", "Unknown")
            self._protocol_counts[protocol] += 1
            self._protocol_bytes[protocol] += size

            src_ip = parsed_packet.get("src_ip", "0.0.0.0")
            dst_ip = parsed_packet.get("dst_ip", "0.0.0.0")
            self._src_ip_counts[src_ip] += 1
            self._dst_ip_counts[dst_ip] += 1
            self._src_ips_per_protocol[protocol].add(src_ip)
            self._dst_ips_per_protocol[protocol].add(dst_ip)

    def start(self) -> None:
        """Start the background aggregation thread."""
        if self._running:
            return

        self._running = True
        self._window_start = time.time()
        self._thread = threading.Thread(
            target=self._aggregation_loop,
            daemon=True,
            name="stats-aggregator",
        )
        self._thread.start()
        logger.info("Stats aggregator started (interval=%ds)", self.interval)

    def stop(self) -> None:
        """Stop the aggregation thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)
        logger.info("Stats aggregator stopped after %d cycles", self._total_cycles)

    def _aggregation_loop(self) -> None:
        """Background loop that computes stats every interval."""
        while self._running:
            time.sleep(self.interval)
            try:
                self._compute_and_store()
            except Exception as exc:
                logger.error("Aggregation cycle error: %s", exc, exc_info=True)

    def _compute_and_store(self) -> None:
        """Compute statistics from current window and persist to DB.

        Resets counters for the next window after computation.
        """
        now = time.time()

        # Snapshot and reset counters atomically
        with self._lock:
            window_duration = max(now - self._window_start, 0.001)
            snapshot = {
                "packet_count": self._packet_count,
                "byte_count": self._byte_count,
                "protocol_counts": dict(self._protocol_counts),
                "protocol_bytes": dict(self._protocol_bytes),
                "src_ip_counts": dict(self._src_ip_counts),
                "dst_ip_counts": dict(self._dst_ip_counts),
                "src_ips_per_protocol": {
                    k: len(v) for k, v in self._src_ips_per_protocol.items()
                },
                "dst_ips_per_protocol": {
                    k: len(v) for k, v in self._dst_ips_per_protocol.items()
                },
                "window_start": self._window_start,
                "window_end": now,
                "window_duration": window_duration,
            }

            # Reset for next window
            self._packet_count = 0
            self._byte_count = 0
            self._protocol_counts = defaultdict(int)
            self._protocol_bytes = defaultdict(int)
            self._src_ip_counts = defaultdict(int)
            self._dst_ip_counts = defaultdict(int)
            self._src_ips_per_protocol = defaultdict(set)
            self._dst_ips_per_protocol = defaultdict(set)
            self._window_start = now

        # Compute derived metrics
        pps = snapshot["packet_count"] / snapshot["window_duration"]
        bps = snapshot["byte_count"] / snapshot["window_duration"]

        # Top talkers (top 10 source IPs by packet count)
        top_talkers = sorted(
            snapshot["src_ip_counts"].items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        top_destinations = sorted(
            snapshot["dst_ip_counts"].items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        # Protocol distribution
        protocol_stats = []
        window_start_dt = datetime.fromtimestamp(
            snapshot["window_start"], tz=timezone.utc
        )
        window_end_dt = datetime.fromtimestamp(
            snapshot["window_end"], tz=timezone.utc
        )

        for protocol, count in snapshot["protocol_counts"].items():
            protocol_stats.append({
                "protocol": protocol,
                "packet_count": count,
                "byte_count": snapshot["protocol_bytes"].get(protocol, 0),
                "unique_src_ips": snapshot["src_ips_per_protocol"].get(protocol, 0),
                "unique_dst_ips": snapshot["dst_ips_per_protocol"].get(protocol, 0),
                "window_start": window_start_dt,
                "window_end": window_end_dt,
            })

        # Update latest stats for API access
        self._latest_stats = {
            "packets_per_second": round(pps, 2),
            "bytes_per_second": round(bps, 2),
            "total_packets": snapshot["packet_count"],
            "total_bytes": snapshot["byte_count"],
            "window_duration": round(snapshot["window_duration"], 2),
            "protocol_distribution": {
                proto: count
                for proto, count in sorted(
                    snapshot["protocol_counts"].items(),
                    key=lambda x: x[1],
                    reverse=True,
                )
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._latest_protocol_stats = protocol_stats
        self._latest_top_talkers = [
            {"ip": ip, "packet_count": count} for ip, count in top_talkers
        ]

        # Persist to database
        self._persist_stats(pps, bps, snapshot, protocol_stats)

        self._total_cycles += 1
        logger.debug(
            "Stats cycle %d: %d packets, %.1f pps, %d protocols",
            self._total_cycles,
            snapshot["packet_count"],
            pps,
            len(snapshot["protocol_counts"]),
        )

    def _persist_stats(
        self,
        pps: float,
        bps: float,
        snapshot: dict,
        protocol_stats: list[dict],
    ) -> None:
        """Write computed statistics to database tables.

        Args:
            pps: Packets per second.
            bps: Bytes per second.
            snapshot: Raw counter snapshot.
            protocol_stats: Per-protocol statistics.
        """
        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.audit import SystemStats
                from app.models.packet import ProtocolStats

                # Write system_stats
                sys_stat = SystemStats(
                    packets_per_second=pps,
                    bytes_per_second=bps,
                    active_connections=0,
                    alerts_count=0,
                    blocked_ips_count=0,
                    packet_drop_rate=0.0,
                    recorded_at=datetime.now(timezone.utc),
                )
                db.session.add(sys_stat)

                # Write protocol_stats
                for ps in protocol_stats:
                    proto_stat = ProtocolStats(
                        protocol=ps["protocol"],
                        packet_count=ps["packet_count"],
                        byte_count=ps["byte_count"],
                        unique_src_ips=ps["unique_src_ips"],
                        unique_dst_ips=ps["unique_dst_ips"],
                        window_start=ps["window_start"],
                        window_end=ps["window_end"],
                    )
                    db.session.add(proto_stat)

                db.session.commit()

        except Exception as exc:
            logger.error("Failed to persist stats: %s", exc)
            try:
                if self.app:
                    with self.app.app_context():
                        from app.extensions import db
                        db.session.rollback()
            except Exception:
                pass

    def get_current_stats(self) -> dict:
        """Get the latest computed statistics.

        Thread-safe read — returns the most recent aggregation result.

        Returns:
            Dictionary with pps, bps, protocol distribution, and timestamp.
        """
        return self._latest_stats.copy() if self._latest_stats else {
            "packets_per_second": 0.0,
            "bytes_per_second": 0.0,
            "total_packets": 0,
            "total_bytes": 0,
            "protocol_distribution": {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_protocol_distribution(self) -> list[dict]:
        """Get the latest protocol distribution.

        Returns:
            List of per-protocol stat dictionaries.
        """
        return [
            {
                "protocol": ps["protocol"],
                "packet_count": ps["packet_count"],
                "byte_count": ps["byte_count"],
            }
            for ps in self._latest_protocol_stats
        ]

    def get_top_talkers(self) -> list[dict]:
        """Get the top 10 source IPs by packet count.

        Returns:
            List of {ip, packet_count} dictionaries.
        """
        return list(self._latest_top_talkers)

    @property
    def stats(self) -> dict:
        """Return aggregator operational statistics."""
        return {
            "total_cycles": self._total_cycles,
            "interval_seconds": self.interval,
            "is_running": self._running,
        }
