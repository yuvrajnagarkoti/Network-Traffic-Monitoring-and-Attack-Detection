"""
Flow-level feature extractor for ML anomaly detection.

Produces 25-element NumPy feature vectors from FlowRecord
objects or parsed packet dictionaries, suitable for the
Isolation Forest model.
"""

import logging
import time
from collections import defaultdict
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# Ordered feature names — must match training/inference order
FEATURE_NAMES: list[str] = [
    "packet_count",           # 0
    "byte_count",             # 1
    "avg_packet_size",        # 2
    "std_packet_size",        # 3
    "max_packet_size",        # 4
    "min_packet_size",        # 5
    "flow_duration_seconds",  # 6
    "packets_per_second",     # 7
    "bytes_per_second",       # 8
    "syn_count",              # 9
    "ack_count",              # 10
    "fin_count",              # 11
    "rst_count",              # 12
    "syn_ratio",              # 13
    "rst_ratio",              # 14
    "unique_dest_ports",      # 15
    "unique_src_ports",       # 16
    "protocol_tcp",           # 17
    "protocol_udp",           # 18
    "protocol_icmp",          # 19
    "inter_arrival_mean",     # 20
    "inter_arrival_std",      # 21
    "inter_arrival_max",      # 22
    "payload_size_mean",      # 23
    "small_packet_ratio",     # 24
]

NUM_FEATURES = len(FEATURE_NAMES)


class FlowFeatureExtractor:
    """Extracts ML feature vectors from network flow records.

    Maintains in-memory flow state and emits 25-element
    feature vectors when flows expire (30s inactivity).
    """

    def __init__(self) -> None:
        """Initialize feature extractor with empty flow table."""
        # Per-flow accumulator: flow_id → {packet_sizes, timestamps, ...}
        self._flows: dict[str, dict] = {}
        self._total_extracted: int = 0

    def update_flow(self, parsed_packet: dict) -> Optional[np.ndarray]:
        """Update flow state with a new packet.

        Does not emit features — call extract_expired() to get
        completed flow features.

        Args:
            parsed_packet: Parsed packet dictionary from PacketParser.

        Returns:
            None (features emitted via extract_expired).
        """
        flow_id = parsed_packet.get("flow_id")
        if not flow_id:
            return None

        if flow_id not in self._flows:
            self._flows[flow_id] = self._init_flow_state(parsed_packet)

        state = self._flows[flow_id]
        self._accumulate(state, parsed_packet)
        return None

    def extract_expired(self, timeout: float = 30.0) -> list[tuple[str, np.ndarray]]:
        """Extract feature vectors for all expired flows.

        Args:
            timeout: Inactivity timeout in seconds.

        Returns:
            List of (flow_id, feature_vector) tuples.
        """
        now = time.time()
        expired = []

        expired_ids = [
            fid for fid, state in self._flows.items()
            if (now - state["last_seen"]) > timeout
        ]

        for fid in expired_ids:
            state = self._flows.pop(fid)
            vector = self._compute_feature_vector(state)
            if vector is not None:
                expired.append((fid, vector))
                self._total_extracted += 1

        return expired

    def extract_from_flow_record(self, flow_record) -> Optional[np.ndarray]:
        """Extract features directly from a FlowRecord object.

        Used when flow tracker emits an expired flow.

        Args:
            flow_record: FlowRecord from flow_tracker.py.

        Returns:
            25-element NumPy array or None.
        """
        try:
            duration = max(flow_record.duration, 0.001)
            pkt_count = max(flow_record.packet_count, 1)

            # Protocol one-hot
            protocol = flow_record.protocol.upper()
            proto_tcp = 1.0 if "TCP" in protocol else 0.0
            proto_udp = 1.0 if "UDP" in protocol else 0.0
            proto_icmp = 1.0 if "ICMP" in protocol else 0.0

            # Inter-arrival time stats
            iats = flow_record.inter_arrival_times if flow_record.inter_arrival_times else [0.0]
            iat_mean = sum(iats) / len(iats)
            iat_std = (sum((x - iat_mean) ** 2 for x in iats) / len(iats)) ** 0.5
            iat_max = max(iats)

            avg_size = flow_record.byte_count / pkt_count

            features = np.array([
                float(flow_record.packet_count),
                float(flow_record.byte_count),
                float(avg_size),
                0.0,                                    # std_packet_size (N/A from FlowRecord)
                float(avg_size * 1.5),                  # max estimate
                float(avg_size * 0.5),                  # min estimate
                float(duration),
                float(flow_record.packet_count / duration),
                float(flow_record.byte_count / duration),
                float(flow_record.syn_count),
                float(flow_record.ack_count),
                float(flow_record.fin_count),
                float(flow_record.rst_count),
                float(flow_record.syn_count / pkt_count),
                float(flow_record.rst_count / pkt_count),
                float(len(flow_record.unique_dst_ports)),
                1.0,                                    # unique_src_ports (1 per flow)
                proto_tcp,
                proto_udp,
                proto_icmp,
                float(iat_mean * 1e6),                  # microseconds
                float(iat_std * 1e6),
                float(iat_max * 1e6),
                float(avg_size * 0.8),                  # payload estimate
                0.0,                                    # small_packet_ratio
            ], dtype=np.float64)

            return features

        except Exception as exc:
            logger.debug("Failed to extract from FlowRecord: %s", exc)
            return None

    def _init_flow_state(self, packet: dict) -> dict:
        """Create initial flow accumulator state."""
        now = time.time()
        return {
            "flow_id": packet.get("flow_id"),
            "first_seen": now,
            "last_seen": now,
            "packet_count": 0,
            "byte_count": 0,
            "packet_sizes": [],
            "timestamps": [],
            "syn_count": 0,
            "ack_count": 0,
            "fin_count": 0,
            "rst_count": 0,
            "unique_dst_ports": set(),
            "unique_src_ports": set(),
            "protocol": packet.get("protocol", "Unknown"),
            "small_packet_count": 0,
        }

    def _accumulate(self, state: dict, packet: dict) -> None:
        """Accumulate packet data into flow state."""
        now = time.time()
        state["last_seen"] = now
        state["packet_count"] += 1

        size = packet.get("packet_size", 0)
        state["byte_count"] += size
        if len(state["packet_sizes"]) < 1000:
            state["packet_sizes"].append(size)
        if len(state["timestamps"]) < 1000:
            state["timestamps"].append(now)
        if size < 100:
            state["small_packet_count"] += 1

        # Flag tracking
        flags = packet.get("flags", "")
        if "SYN" in flags:
            state["syn_count"] += 1
        if "ACK" in flags:
            state["ack_count"] += 1
        if "FIN" in flags:
            state["fin_count"] += 1
        if "RST" in flags:
            state["rst_count"] += 1

        # Port tracking
        dst_port = packet.get("dst_port")
        src_port = packet.get("src_port")
        if dst_port is not None:
            state["unique_dst_ports"].add(dst_port)
        if src_port is not None:
            state["unique_src_ports"].add(src_port)

    def _compute_feature_vector(self, state: dict) -> Optional[np.ndarray]:
        """Compute 25-element feature vector from flow state.

        Args:
            state: Flow accumulator dictionary.

        Returns:
            NumPy array of 25 float64 features.
        """
        try:
            pkt_count = max(state["packet_count"], 1)
            duration = max(state["last_seen"] - state["first_seen"], 0.001)
            sizes = state["packet_sizes"] if state["packet_sizes"] else [0]

            # Size stats
            avg_size = sum(sizes) / len(sizes)
            std_size = (sum((s - avg_size) ** 2 for s in sizes) / len(sizes)) ** 0.5
            max_size = max(sizes)
            min_size = min(sizes)

            # Inter-arrival times
            timestamps = state["timestamps"]
            if len(timestamps) >= 2:
                iats = [
                    timestamps[i + 1] - timestamps[i]
                    for i in range(len(timestamps) - 1)
                ]
                iat_mean = sum(iats) / len(iats)
                iat_std = (sum((x - iat_mean) ** 2 for x in iats) / len(iats)) ** 0.5
                iat_max = max(iats)
            else:
                iat_mean = iat_std = iat_max = 0.0

            # Protocol one-hot
            protocol = state["protocol"].upper()
            proto_tcp = 1.0 if "TCP" in protocol else 0.0
            proto_udp = 1.0 if "UDP" in protocol else 0.0
            proto_icmp = 1.0 if "ICMP" in protocol else 0.0

            # Small packet ratio
            small_ratio = state["small_packet_count"] / pkt_count

            # Payload estimate (total size minus ~40 bytes header per packet)
            payload_total = max(state["byte_count"] - (pkt_count * 40), 0)
            payload_mean = payload_total / pkt_count

            features = np.array([
                float(pkt_count),                         # 0
                float(state["byte_count"]),               # 1
                float(avg_size),                          # 2
                float(std_size),                          # 3
                float(max_size),                          # 4
                float(min_size),                          # 5
                float(duration),                          # 6
                float(pkt_count / duration),              # 7
                float(state["byte_count"] / duration),    # 8
                float(state["syn_count"]),                # 9
                float(state["ack_count"]),                # 10
                float(state["fin_count"]),                # 11
                float(state["rst_count"]),                # 12
                float(state["syn_count"] / pkt_count),    # 13
                float(state["rst_count"] / pkt_count),    # 14
                float(len(state["unique_dst_ports"])),    # 15
                float(len(state["unique_src_ports"])),    # 16
                proto_tcp,                                # 17
                proto_udp,                                # 18
                proto_icmp,                               # 19
                float(iat_mean * 1e6),                    # 20 (microseconds)
                float(iat_std * 1e6),                     # 21
                float(iat_max * 1e6),                     # 22
                float(payload_mean),                      # 23
                float(small_ratio),                       # 24
            ], dtype=np.float64)

            return features

        except Exception as exc:
            logger.debug("Feature vector computation failed: %s", exc)
            return None

    @property
    def active_flows(self) -> int:
        """Number of flows currently being tracked."""
        return len(self._flows)

    @property
    def total_extracted(self) -> int:
        """Total feature vectors extracted."""
        return self._total_extracted

    @property
    def stats(self) -> dict:
        """Return extractor statistics."""
        return {
            "active_flows": self.active_flows,
            "total_extracted": self._total_extracted,
            "feature_count": NUM_FEATURES,
        }
