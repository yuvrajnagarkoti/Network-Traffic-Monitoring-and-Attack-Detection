"""
UDP scan detector.

Detects UDP port scans by tracking source IPs sending UDP
packets to many unique destination ports.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from app.detection.base_detector import BaseDetector, AttackIndicator

logger = logging.getLogger(__name__)

MAX_TRACKED_IPS = 100_000


class UdpScanDetector(BaseDetector):
    """Detects UDP port scanning activity.

    Trigger: Source IP sends UDP to >10 unique destination
    ports within 30 seconds.
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        super().__init__(config)
        self._port_threshold = self._config.get("port_threshold", 10)
        self._time_window = self._config.get("time_window_seconds", 30)

        self._ip_windows: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=500)
        )
        self._lock = threading.Lock()

    def get_name(self) -> str:
        return "UDP Scan Detector"

    def analyze(self, packet: dict) -> list[AttackIndicator]:
        self._record_analysis()

        if packet.get("layer4") != "UDP":
            return []

        src_ip = packet.get("src_ip")
        dst_port = packet.get("dst_port")
        if not src_ip or dst_port is None:
            return []

        now = time.time()

        with self._lock:
            if src_ip not in self._ip_windows and len(self._ip_windows) >= MAX_TRACKED_IPS:
                return []

            self._ip_windows[src_ip].append((dst_port, now))

            window = self._ip_windows[src_ip]
            while window and (now - window[0][1]) > self._time_window:
                window.popleft()

            unique_ports = set(port for port, _ in window)
            if len(unique_ports) < self._port_threshold:
                return []

            duration = max(now - window[0][1], 0.001)
            scan_rate = len(unique_ports) / duration

            self._record_alert()
            return [AttackIndicator(
                attack_type="port_scan",
                source_ip=src_ip,
                confidence=0.75,
                packet_count=len(window),
                duration_seconds=int(duration),
                detector_name=self.get_name(),
                evidence={
                    "scanned_ports": sorted(unique_ports)[:50],
                    "unique_port_count": len(unique_ports),
                    "scan_rate": round(scan_rate, 2),
                    "technique": "udp",
                    "window_seconds": self._time_window,
                },
            )]

    def reset_state(self) -> None:
        super().reset_state()
        with self._lock:
            self._ip_windows.clear()
