"""
TCP/UDP flow tracker.

Maintains a table of active network flows (5-tuple) with
per-flow statistics. Flows expire after 30 seconds of
inactivity and are emitted for ML feature extraction.
"""

import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Flow inactivity timeout in seconds
FLOW_TIMEOUT_SECONDS = 30

# Maximum tracked flows to prevent memory exhaustion
MAX_TRACKED_FLOWS = 100_000


class FlowRecord:
    """Represents a single network flow with accumulated statistics.

    A flow is defined by the 5-tuple: (src_ip, dst_ip, src_port,
    dst_port, protocol). Statistics are accumulated as new packets
    arrive for the flow.
    """

    __slots__ = [
        "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "packet_count", "byte_count", "first_seen", "last_seen",
        "syn_count", "ack_count", "fin_count", "rst_count", "psh_count",
        "urg_count", "unique_dst_ports", "inter_arrival_times",
        "_last_arrival", "_lock",
    ]

    def __init__(self, flow_id: str, parsed_packet: dict) -> None:
        self.flow_id = flow_id
        self.src_ip = parsed_packet["src_ip"]
        self.dst_ip = parsed_packet["dst_ip"]
        self.src_port = parsed_packet.get("src_port")
        self.dst_port = parsed_packet.get("dst_port")
        self.protocol = parsed_packet.get("protocol", "Unknown")

        self.packet_count = 0
        self.byte_count = 0
        self.first_seen = time.time()
        self.last_seen = self.first_seen

        # TCP flag counters
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.urg_count = 0

        # Destination port tracking (for scan detection)
        self.unique_dst_ports: set[int] = set()

        # Inter-arrival times for ML features
        self.inter_arrival_times: list[float] = []
        self._last_arrival: float = self.first_seen
        self._lock = threading.RLock()

    def update(self, parsed_packet: dict) -> None:
        """Update flow with new packet data.

        Thread-safe: uses RLock for concurrent access.

        Args:
            parsed_packet: Parsed packet dictionary from PacketParser.
        """
        with self._lock:
            now = time.time()

            self.packet_count += 1
            self.byte_count += parsed_packet.get("packet_size", 0)
            self.last_seen = now

            # Track inter-arrival time (keep last 100)
            iat = now - self._last_arrival
            if len(self.inter_arrival_times) < 100:
                self.inter_arrival_times.append(iat)
            self._last_arrival = now

            # Track destination ports
            dst_port = parsed_packet.get("dst_port")
            if dst_port is not None:
                self.unique_dst_ports.add(dst_port)

            # Count TCP flags
            flags = parsed_packet.get("flags")
            if flags:
                flag_set = flags.split("|")
                if "SYN" in flag_set:
                    self.syn_count += 1
                if "ACK" in flag_set:
                    self.ack_count += 1
                if "FIN" in flag_set:
                    self.fin_count += 1
                if "RST" in flag_set:
                    self.rst_count += 1
                if "PSH" in flag_set:
                    self.psh_count += 1
                if "URG" in flag_set:
                    self.urg_count += 1

    @property
    def duration(self) -> float:
        """Flow duration in seconds."""
        return self.last_seen - self.first_seen

    @property
    def is_expired(self) -> bool:
        """Check if flow has been inactive for FLOW_TIMEOUT_SECONDS."""
        return (time.time() - self.last_seen) > FLOW_TIMEOUT_SECONDS

    def to_feature_vector(self) -> list[float]:
        """Extract numerical feature vector for ML model.

        Returns 25-element feature vector used by the Isolation Forest
        anomaly detector in Phase 5.

        Returns:
            List of 25 float features.
        """
        with self._lock:
            duration = max(self.duration, 0.001)
            pps = self.packet_count / duration
            bps = self.byte_count / duration
            avg_size = self.byte_count / max(self.packet_count, 1)

            # Inter-arrival time stats
            iats = self.inter_arrival_times if self.inter_arrival_times else [0.0]
            iat_mean = sum(iats) / len(iats)
            iat_min = min(iats)
            iat_max = max(iats)
            iat_std = (sum((x - iat_mean) ** 2 for x in iats) / len(iats)) ** 0.5

            # Flag ratios
            total = max(self.packet_count, 1)
            syn_ratio = self.syn_count / total
            ack_ratio = self.ack_count / total
            fin_ratio = self.fin_count / total
            rst_ratio = self.rst_count / total
            psh_ratio = self.psh_count / total

            return [
                float(self.packet_count),       # 0: packet_count
                float(self.byte_count),          # 1: byte_count
                float(duration),                 # 2: duration
                float(pps),                      # 3: packets_per_second
                float(bps),                      # 4: bytes_per_second
                float(avg_size),                 # 5: avg_packet_size
                float(self.src_port or 0),       # 6: src_port
                float(self.dst_port or 0),       # 7: dst_port
                float(len(self.unique_dst_ports)),  # 8: unique_dst_ports
                float(self.syn_count),           # 9: syn_count
                float(self.ack_count),           # 10: ack_count
                float(self.fin_count),           # 11: fin_count
                float(self.rst_count),           # 12: rst_count
                float(self.psh_count),           # 13: psh_count
                float(self.urg_count),           # 14: urg_count
                float(syn_ratio),                # 15: syn_ratio
                float(ack_ratio),                # 16: ack_ratio
                float(fin_ratio),                # 17: fin_ratio
                float(rst_ratio),                # 18: rst_ratio
                float(psh_ratio),                # 19: psh_ratio
                float(iat_mean),                 # 20: iat_mean
                float(iat_min),                  # 21: iat_min
                float(iat_max),                  # 22: iat_max
                float(iat_std),                  # 23: iat_std
                float(self.ip_version),          # 24: ip_version
            ]

    @property
    def ip_version(self) -> int:
        """Infer IP version from source IP format."""
        return 6 if ":" in self.src_ip else 4

    def to_dict(self) -> dict:
        """Serialize flow record to dictionary."""
        with self._lock:
            return {
                "flow_id": self.flow_id,
                "src_ip": self.src_ip,
                "dst_ip": self.dst_ip,
                "src_port": self.src_port,
                "dst_port": self.dst_port,
                "protocol": self.protocol,
                "packet_count": self.packet_count,
                "byte_count": self.byte_count,
                "duration_seconds": round(self.duration, 3),
                "first_seen": datetime.fromtimestamp(
                    self.first_seen, tz=timezone.utc
                ).isoformat(),
                "last_seen": datetime.fromtimestamp(
                    self.last_seen, tz=timezone.utc
                ).isoformat(),
                "syn_count": self.syn_count,
                "ack_count": self.ack_count,
                "fin_count": self.fin_count,
                "rst_count": self.rst_count,
                "unique_dst_ports": len(self.unique_dst_ports),
            }


class FlowTracker:
    """Tracks active network flows and manages flow lifecycle.

    Flows are created on first packet and updated with subsequent
    packets. Expired flows (30s inactivity) are reaped and
    optionally passed to a callback for ML feature extraction.
    """

    def __init__(
        self,
        on_flow_expired: Optional[Callable[[FlowRecord], None]] = None,
    ) -> None:
        """Initialize flow tracker.

        Args:
            on_flow_expired: Callback invoked when a flow expires.
                Used to trigger ML feature extraction.
        """
        self._flows: dict[str, FlowRecord] = {}
        self._lock = threading.RLock()
        self._on_flow_expired = on_flow_expired
        self._total_flows_created: int = 0
        self._total_flows_expired: int = 0
        self._running = False
        self._reaper_thread: Optional[threading.Thread] = None

    def update(self, parsed_packet: dict) -> FlowRecord:
        """Update or create a flow for the given packet.

        Args:
            parsed_packet: Parsed packet dictionary with flow_id.

        Returns:
            The updated or newly created FlowRecord.
        """
        flow_id = parsed_packet.get("flow_id")
        if not flow_id:
            return None

        with self._lock:
            # Enforce max flow limit (LRU eviction)
            if flow_id not in self._flows and len(self._flows) >= MAX_TRACKED_FLOWS:
                self._evict_oldest_flow()

            if flow_id in self._flows:
                flow = self._flows[flow_id]
                flow.update(parsed_packet)
            else:
                flow = FlowRecord(flow_id, parsed_packet)
                flow.update(parsed_packet)
                self._flows[flow_id] = flow
                self._total_flows_created += 1

            return flow

    def _evict_oldest_flow(self) -> None:
        """Evict the flow with the oldest last_seen timestamp."""
        if not self._flows:
            return
        oldest_id = min(self._flows, key=lambda k: self._flows[k].last_seen)
        evicted = self._flows.pop(oldest_id)
        self._total_flows_expired += 1
        logger.debug("Evicted flow %s (LRU)", oldest_id)
        if self._on_flow_expired:
            try:
                self._on_flow_expired(evicted)
            except Exception as exc:
                logger.error("Error in flow expiry callback: %s", exc)

    def reap_expired(self) -> list[FlowRecord]:
        """Remove and return all expired flows.

        Returns:
            List of expired FlowRecord objects.
        """
        expired = []
        with self._lock:
            expired_ids = [
                fid for fid, flow in self._flows.items() if flow.is_expired
            ]
            for fid in expired_ids:
                flow = self._flows.pop(fid)
                expired.append(flow)
                self._total_flows_expired += 1

        # Invoke callbacks outside of lock
        for flow in expired:
            if self._on_flow_expired:
                try:
                    self._on_flow_expired(flow)
                except Exception as exc:
                    logger.error("Error in flow expiry callback: %s", exc)

        return expired

    def start_reaper(self, interval: float = 10.0) -> None:
        """Start background thread that periodically reaps expired flows.

        Args:
            interval: Seconds between reaper runs.
        """
        self._running = True
        self._reaper_thread = threading.Thread(
            target=self._reaper_loop,
            args=(interval,),
            daemon=True,
            name="flow-reaper",
        )
        self._reaper_thread.start()
        logger.info("Flow reaper started (interval=%.1fs)", interval)

    def _reaper_loop(self, interval: float) -> None:
        """Background loop that reaps expired flows."""
        while self._running:
            try:
                expired = self.reap_expired()
                if expired:
                    logger.debug("Reaped %d expired flows", len(expired))
            except Exception as exc:
                logger.error("Flow reaper error: %s", exc)
            time.sleep(interval)

    def stop_reaper(self) -> None:
        """Stop the flow reaper background thread."""
        self._running = False
        if self._reaper_thread and self._reaper_thread.is_alive():
            self._reaper_thread.join(timeout=5)
            logger.info("Flow reaper stopped")

    def get_flow(self, flow_id: str) -> Optional[FlowRecord]:
        """Get a specific flow by ID."""
        with self._lock:
            return self._flows.get(flow_id)

    def get_active_flows(self) -> list[dict]:
        """Get all active flows as dictionaries."""
        with self._lock:
            return [flow.to_dict() for flow in self._flows.values()]

    @property
    def active_flow_count(self) -> int:
        """Number of currently tracked flows."""
        return len(self._flows)

    @property
    def stats(self) -> dict:
        """Return flow tracker statistics."""
        return {
            "active_flows": self.active_flow_count,
            "total_created": self._total_flows_created,
            "total_expired": self._total_flows_expired,
            "max_capacity": MAX_TRACKED_FLOWS,
        }
