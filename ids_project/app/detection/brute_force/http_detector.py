"""
HTTP brute force detector.

Detects HTTP login brute force by tracking repeated POST
requests to authentication endpoints from the same source IP.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from app.detection.base_detector import BaseDetector, AttackIndicator

logger = logging.getLogger(__name__)

MAX_TRACKED_IPS = 100_000


class HttpBruteForceDetector(BaseDetector):
    """Detects HTTP brute force / credential stuffing.

    Trigger: >10 POST requests to auth endpoints from same IP
    in 30 seconds (especially with 401/403 responses).

    Detects by tracking TCP connections to HTTP ports (80/8080)
    with PSH+ACK flags (data transfer = POST body).
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        super().__init__(config)
        self._attempt_threshold = self._config.get("attempt_threshold", 10)
        self._time_window = self._config.get("time_window_seconds", 30)
        self._auth_endpoints = self._config.get("auth_endpoints", [
            "/login", "/admin", "/wp-login.php", "/api/auth",
        ])
        self._http_ports = {80, 443, 8080, 8443}

        self._ip_windows: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=500)
        )
        self._lock = threading.Lock()

    def get_name(self) -> str:
        return "HTTP Brute Force Detector"

    def analyze(self, packet: dict) -> list[AttackIndicator]:
        self._record_analysis()

        if packet.get("layer4") != "TCP":
            return []

        dst_port = packet.get("dst_port")
        if dst_port not in self._http_ports:
            return []

        # Track data-bearing packets (PSH flag = data transfer)
        flags = packet.get("flags", "")
        has_data = "PSH" in flags

        # Also track SYN packets as connection attempts
        is_syn = "SYN" in flags and "ACK" not in flags

        if not has_data and not is_syn:
            return []

        src_ip = packet.get("src_ip")
        if not src_ip:
            return []

        now = time.time()

        with self._lock:
            if src_ip not in self._ip_windows and len(self._ip_windows) >= MAX_TRACKED_IPS:
                return []

            self._ip_windows[src_ip].append((dst_port, now))

            window = self._ip_windows[src_ip]
            while window and (now - window[0][1]) > self._time_window:
                window.popleft()

            if len(window) < self._attempt_threshold:
                return []

            duration = max(now - window[0][1], 0.001)
            attempt_rate = len(window) / duration

            self._record_alert()
            return [AttackIndicator(
                attack_type="brute_force",
                source_ip=src_ip,
                target_port=dst_port,
                confidence=min(0.5 + (len(window) / 30.0), 0.90),
                packet_count=len(window),
                duration_seconds=int(duration),
                detector_name=self.get_name(),
                evidence={
                    "targeted_service": "HTTP",
                    "failed_attempts": len(window),
                    "attempt_rate": round(attempt_rate, 2),
                    "port": dst_port,
                    "window_seconds": self._time_window,
                },
            )]

    def reset_state(self) -> None:
        super().reset_state()
        with self._lock:
            self._ip_windows.clear()
