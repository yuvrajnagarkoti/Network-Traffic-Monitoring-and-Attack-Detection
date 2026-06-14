"""
UDP flood detector.

Detects UDP flood DDoS attacks by tracking UDP packet rate
per destination IP. Also detects amplification attacks.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from app.detection.base_detector import BaseDetector, AttackIndicator

logger = logging.getLogger(__name__)


class UdpFloodDetector(BaseDetector):
    """Detects UDP flood attacks.

    Trigger: >1000 UDP/s to single destination IP.
    Also detects amplification via known amplification ports.
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        super().__init__(config)
        self._udp_threshold = self._config.get("udp_rate_threshold", 1000)
        self._time_window = self._config.get("time_window_seconds", 10)
        self._amplification_ports = set(
            self._config.get("amplification_ports", [53, 123, 1900])
        )

        self._dst_windows: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=20000)
        )
        self._lock = threading.Lock()

    def get_name(self) -> str:
        return "UDP Flood Detector"

    def analyze(self, packet: dict) -> list[AttackIndicator]:
        self._record_analysis()

        if packet.get("layer4") != "UDP":
            return []

        dst_ip = packet.get("dst_ip")
        src_port = packet.get("src_port")
        if not dst_ip:
            return []

        now = time.time()

        with self._lock:
            if dst_ip not in self._dst_windows and len(self._dst_windows) >= 50000:
                return []

            self._dst_windows[dst_ip].append((src_port, now))

            window = self._dst_windows[dst_ip]
            while window and (now - window[0][1]) > self._time_window:
                window.popleft()

            packet_count = len(window)
            duration = max(now - window[0][1], 0.001) if window else 1
            udp_rate = packet_count / duration

            if udp_rate < self._udp_threshold:
                return []

            # Check for amplification
            amp_count = sum(
                1 for port, _ in window if port in self._amplification_ports
            )
            is_amplification = amp_count > packet_count * 0.5

            src_ip = packet.get("src_ip", "0.0.0.0")
            confidence = min(0.7 + (udp_rate / 10000.0), 0.95)

            self._record_alert()
            return [AttackIndicator(
                attack_type="ddos",
                source_ip=src_ip,
                target_ip=dst_ip,
                confidence=confidence,
                packet_count=packet_count,
                duration_seconds=int(duration),
                detector_name=self.get_name(),
                evidence={
                    "attack_vector": "udp_flood",
                    "udp_rate": round(udp_rate, 2),
                    "packet_count": packet_count,
                    "is_amplification": is_amplification,
                    "amplification_packets": amp_count,
                    "target_ip": dst_ip,
                    "window_seconds": self._time_window,
                },
            )]

    def reset_state(self) -> None:
        super().reset_state()
        with self._lock:
            self._dst_windows.clear()
