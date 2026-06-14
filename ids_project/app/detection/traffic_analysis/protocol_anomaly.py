"""
Protocol anomaly detector.

Detects unusual protocol distributions, DNS tunneling indicators,
and connection tracking anomalies.
"""

import logging
import threading
import time
from collections import defaultdict
from typing import Optional

from app.detection.base_detector import BaseDetector, AttackIndicator

logger = logging.getLogger(__name__)

MAX_TRACKED_IPS = 100_000


class ProtocolAnomalyDetector(BaseDetector):
    """Detects protocol distribution anomalies.

    - ICMP > 30% of traffic = possible ICMP flood
    - DNS packets > 512 bytes = possible DNS tunneling
    - Single IP > 200 concurrent connections
    - > 500 half-open (SYN without SYN-ACK) connections
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        super().__init__(config)
        self._icmp_threshold = self._config.get("icmp_threshold_percent", 30)
        self._dns_max_size = self._config.get("dns_max_packet_size", 512)
        self._max_connections = self._config.get("max_connections_per_ip", 200)
        self._half_open_threshold = self._config.get("half_open_threshold", 500)

        self._lock = threading.Lock()
        self._window_seconds = 60
        self._window_start = time.time()

        # Protocol counters for current window
        self._protocol_counts: dict[str, int] = defaultdict(int)
        self._total_packets: int = 0

        # DNS tunneling tracking
        self._large_dns: list[dict] = []

        # Connection tracking per IP
        self._syn_counts: dict[str, int] = defaultdict(int)
        self._synack_counts: dict[str, int] = defaultdict(int)

    def get_name(self) -> str:
        return "Protocol Anomaly Detector"

    def analyze(self, packet: dict) -> list[AttackIndicator]:
        self._record_analysis()

        protocol = packet.get("protocol", "Unknown")
        src_ip = packet.get("src_ip", "0.0.0.0")
        size = packet.get("packet_size", 0)
        flags = packet.get("flags", "")
        now = time.time()
        indicators = []

        with self._lock:
            self._protocol_counts[protocol] += 1
            self._total_packets += 1

            # Track DNS tunneling candidates
            if protocol == "DNS" and size > self._dns_max_size:
                if len(self._large_dns) < 100:
                    self._large_dns.append({
                        "src_ip": src_ip,
                        "size": size,
                        "timestamp": now,
                    })

            # Track SYN / SYN-ACK for half-open detection
            if "SYN" in flags and "ACK" not in flags:
                self._syn_counts[src_ip] += 1
            elif "SYN" in flags and "ACK" in flags:
                dst_ip = packet.get("dst_ip", "")
                self._synack_counts[dst_ip] += 1

            # Check window elapsed
            elapsed = now - self._window_start
            if elapsed >= self._window_seconds:
                indicators.extend(self._check_anomalies(now))
                self._reset_window(now)

        return indicators

    def _check_anomalies(self, now: float) -> list[AttackIndicator]:
        """Check all anomaly conditions at window boundary."""
        indicators = []

        if self._total_packets == 0:
            return indicators

        # ICMP flood check
        icmp_count = self._protocol_counts.get("ICMP", 0)
        icmp_percent = (icmp_count / self._total_packets) * 100
        if icmp_percent > self._icmp_threshold:
            self._record_alert()
            indicators.append(AttackIndicator(
                attack_type="traffic_anomaly",
                source_ip="0.0.0.0",
                confidence=0.7,
                packet_count=icmp_count,
                detector_name=self.get_name(),
                evidence={
                    "anomaly_type": "icmp_flood",
                    "icmp_percent": round(icmp_percent, 2),
                    "threshold": self._icmp_threshold,
                    "total_packets": self._total_packets,
                },
            ))

        # DNS tunneling check
        if len(self._large_dns) >= 5:
            self._record_alert()
            indicators.append(AttackIndicator(
                attack_type="traffic_anomaly",
                source_ip=self._large_dns[0]["src_ip"],
                confidence=0.65,
                packet_count=len(self._large_dns),
                detector_name=self.get_name(),
                evidence={
                    "anomaly_type": "dns_tunneling",
                    "large_dns_count": len(self._large_dns),
                    "max_dns_size": max(d["size"] for d in self._large_dns),
                    "threshold_size": self._dns_max_size,
                },
            ))

        # Half-open connection check
        total_syns = sum(self._syn_counts.values())
        total_synacks = sum(self._synack_counts.values())
        half_open = total_syns - total_synacks
        if half_open > self._half_open_threshold:
            self._record_alert()
            indicators.append(AttackIndicator(
                attack_type="traffic_anomaly",
                source_ip="0.0.0.0",
                confidence=0.8,
                packet_count=half_open,
                detector_name=self.get_name(),
                evidence={
                    "anomaly_type": "half_open_connections",
                    "half_open_count": half_open,
                    "total_syns": total_syns,
                    "total_synacks": total_synacks,
                    "threshold": self._half_open_threshold,
                },
            ))

        # Excessive connections per IP
        for ip, syn_count in self._syn_counts.items():
            if syn_count > self._max_connections:
                self._record_alert()
                indicators.append(AttackIndicator(
                    attack_type="traffic_anomaly",
                    source_ip=ip,
                    confidence=0.75,
                    packet_count=syn_count,
                    detector_name=self.get_name(),
                    evidence={
                        "anomaly_type": "excessive_connections",
                        "connection_count": syn_count,
                        "threshold": self._max_connections,
                    },
                ))
                break  # Only report top offender per window

        return indicators

    def _reset_window(self, now: float) -> None:
        """Reset all window counters."""
        self._protocol_counts = defaultdict(int)
        self._total_packets = 0
        self._large_dns = []
        self._syn_counts = defaultdict(int)
        self._synack_counts = defaultdict(int)
        self._window_start = now

    def reset_state(self) -> None:
        super().reset_state()
        with self._lock:
            self._reset_window(time.time())
