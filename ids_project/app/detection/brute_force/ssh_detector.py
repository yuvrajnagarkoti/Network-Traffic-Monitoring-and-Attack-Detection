"""
SSH brute force detector.

Detects SSH brute force attempts by tracking short-lived TCP
connections to port 22 from the same source IP.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from app.detection.base_detector import BaseDetector, AttackIndicator

logger = logging.getLogger(__name__)

MAX_TRACKED_IPS = 100_000


class SshBruteForceDetector(BaseDetector):
    """Detects SSH brute force attacks.

    Pattern: Repeated short-lived TCP connections to port 22.
    Failed SSH auth causes immediate disconnect (RST or FIN).

    Trigger: >5 connections to port 22 in 60 seconds from same IP,
    where connections are short-lived (SYN followed quickly by RST/FIN).
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        super().__init__(config)
        self._attempt_threshold = self._config.get("attempt_threshold", 5)
        self._time_window = self._config.get("time_window_seconds", 60)
        self._port = self._config.get("port", 22)

        # Per-IP sliding window of connection timestamps
        self._ip_windows: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=200)
        )
        self._lock = threading.Lock()

    def get_name(self) -> str:
        return "SSH Brute Force Detector"

    def analyze(self, packet: dict) -> list[AttackIndicator]:
        self._record_analysis()

        if packet.get("layer4") != "TCP":
            return []

        dst_port = packet.get("dst_port")
        if dst_port != self._port:
            return []

        flags = packet.get("flags", "")
        # Track SYN packets (connection attempts) and RST/FIN (failed auth)
        is_connection_attempt = "SYN" in flags and "ACK" not in flags
        is_connection_failure = "RST" in flags or ("FIN" in flags and "ACK" not in flags)

        if not is_connection_attempt and not is_connection_failure:
            return []

        src_ip = packet.get("src_ip")
        if not src_ip:
            return []

        now = time.time()

        with self._lock:
            if src_ip not in self._ip_windows and len(self._ip_windows) >= MAX_TRACKED_IPS:
                return []

            self._ip_windows[src_ip].append(now)

            window = self._ip_windows[src_ip]
            while window and (now - window[0]) > self._time_window:
                window.popleft()

            if len(window) < self._attempt_threshold:
                return []

            duration = max(now - window[0], 0.001)
            attempt_rate = len(window) / duration

            self._record_alert()
            return [AttackIndicator(
                attack_type="brute_force",
                source_ip=src_ip,
                target_port=self._port,
                confidence=min(0.5 + (len(window) / 20.0), 0.95),
                packet_count=len(window),
                duration_seconds=int(duration),
                detector_name=self.get_name(),
                evidence={
                    "targeted_service": "SSH",
                    "failed_attempts": len(window),
                    "attempt_rate": round(attempt_rate, 2),
                    "port": self._port,
                    "window_seconds": self._time_window,
                },
            )]

    def reset_state(self) -> None:
        super().reset_state()
        with self._lock:
            self._ip_windows.clear()
