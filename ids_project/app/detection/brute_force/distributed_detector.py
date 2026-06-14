"""
Distributed brute force detector.

Detects credential stuffing and distributed brute force attacks
where multiple source IPs target the same service.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from app.detection.base_detector import BaseDetector, AttackIndicator

logger = logging.getLogger(__name__)

# Commonly targeted service ports
AUTH_PORTS = {22, 21, 25, 80, 443, 587, 3389, 8080}


class DistributedBruteForceDetector(BaseDetector):
    """Detects distributed brute force / credential stuffing.

    Pattern: >50 failed auth attempts to same service from >5
    different source IPs within 5 minutes.

    Tracks by (target_ip, target_port) to detect when multiple
    attackers converge on the same target.
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        super().__init__(config)
        self._attempt_threshold = self._config.get("attempt_threshold", 50)
        self._ip_threshold = self._config.get("unique_ip_threshold", 5)
        self._time_window = self._config.get("time_window_seconds", 300)

        # Per-(target_ip, target_port): deque of (src_ip, timestamp)
        self._target_windows: dict[tuple, deque] = defaultdict(
            lambda: deque(maxlen=2000)
        )
        self._lock = threading.Lock()

    def get_name(self) -> str:
        return "Distributed Brute Force Detector"

    def analyze(self, packet: dict) -> list[AttackIndicator]:
        self._record_analysis()

        if packet.get("layer4") != "TCP":
            return []

        dst_port = packet.get("dst_port")
        if dst_port not in AUTH_PORTS:
            return []

        flags = packet.get("flags", "")
        is_relevant = (
            ("SYN" in flags and "ACK" not in flags)
            or "RST" in flags
        )
        if not is_relevant:
            return []

        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        if not src_ip or not dst_ip:
            return []

        target_key = (dst_ip, dst_port)
        now = time.time()

        with self._lock:
            if target_key not in self._target_windows and len(self._target_windows) >= 10000:
                return []

            self._target_windows[target_key].append((src_ip, now))

            window = self._target_windows[target_key]
            while window and (now - window[0][1]) > self._time_window:
                window.popleft()

            # Count total attempts and unique source IPs
            total_attempts = len(window)
            unique_ips = set(ip for ip, _ in window)

            if total_attempts < self._attempt_threshold:
                return []
            if len(unique_ips) < self._ip_threshold:
                return []

            duration = max(now - window[0][1], 0.001)

            self._record_alert()
            return [AttackIndicator(
                attack_type="brute_force",
                source_ip=list(unique_ips)[0],
                target_ip=dst_ip,
                target_port=dst_port,
                confidence=min(0.6 + (len(unique_ips) / 20.0), 0.95),
                packet_count=total_attempts,
                duration_seconds=int(duration),
                detector_name=self.get_name(),
                evidence={
                    "targeted_service": f"PORT_{dst_port}",
                    "failed_attempts": total_attempts,
                    "unique_source_ips": len(unique_ips),
                    "contributing_ips": list(unique_ips)[:20],
                    "attempt_rate": round(total_attempts / duration, 2),
                    "target_ip": dst_ip,
                    "port": dst_port,
                    "window_seconds": self._time_window,
                    "distributed": True,
                },
            )]

    def reset_state(self) -> None:
        super().reset_state()
        with self._lock:
            self._target_windows.clear()
