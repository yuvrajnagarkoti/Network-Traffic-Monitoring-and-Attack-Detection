"""
Generic brute force detector for FTP, SMTP, RDP.

Provides a configurable per-protocol brute force detector
with individual thresholds for each service.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from app.detection.base_detector import BaseDetector, AttackIndicator

logger = logging.getLogger(__name__)

MAX_TRACKED_IPS = 100_000

# Default per-service configurations
DEFAULT_SERVICES = {
    "ftp": {"port": 21, "attempt_threshold": 5, "time_window_seconds": 60},
    "smtp": {"port": 25, "attempt_threshold": 5, "time_window_seconds": 60},
    "rdp": {"port": 3389, "attempt_threshold": 5, "time_window_seconds": 60},
    "telnet": {"port": 23, "attempt_threshold": 5, "time_window_seconds": 60},
    "mysql": {"port": 3306, "attempt_threshold": 5, "time_window_seconds": 60},
}


class GenericBruteForceDetector(BaseDetector):
    """Configurable brute force detector for multiple services.

    Tracks short-lived TCP connections to known service ports.
    Each service has its own threshold and time window.
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        super().__init__(config)
        self._services = config if config else dict(DEFAULT_SERVICES)

        # Build port-to-service lookup
        self._port_service_map: dict[int, dict] = {}
        for service_name, svc_config in self._services.items():
            port = svc_config.get("port")
            if port:
                self._port_service_map[port] = {
                    "name": service_name.upper(),
                    "threshold": svc_config.get("attempt_threshold", 5),
                    "window": svc_config.get("time_window_seconds", 60),
                }

        # Per-(service, IP) sliding windows
        self._windows: dict[tuple, deque] = defaultdict(
            lambda: deque(maxlen=200)
        )
        self._lock = threading.Lock()

    def get_name(self) -> str:
        return "Generic Brute Force Detector"

    def analyze(self, packet: dict) -> list[AttackIndicator]:
        self._record_analysis()

        if packet.get("layer4") != "TCP":
            return []

        dst_port = packet.get("dst_port")
        if dst_port not in self._port_service_map:
            return []

        flags = packet.get("flags", "")
        is_relevant = (
            ("SYN" in flags and "ACK" not in flags)
            or "RST" in flags
            or ("FIN" in flags)
        )
        if not is_relevant:
            return []

        src_ip = packet.get("src_ip")
        if not src_ip:
            return []

        service = self._port_service_map[dst_port]
        key = (service["name"], src_ip)
        now = time.time()

        with self._lock:
            if key not in self._windows and len(self._windows) >= MAX_TRACKED_IPS:
                return []

            self._windows[key].append(now)

            window = self._windows[key]
            while window and (now - window[0]) > service["window"]:
                window.popleft()

            if len(window) < service["threshold"]:
                return []

            duration = max(now - window[0], 0.001)

            self._record_alert()
            return [AttackIndicator(
                attack_type="brute_force",
                source_ip=src_ip,
                target_port=dst_port,
                confidence=min(0.5 + (len(window) / 20.0), 0.90),
                packet_count=len(window),
                duration_seconds=int(duration),
                detector_name=self.get_name(),
                evidence={
                    "targeted_service": service["name"],
                    "failed_attempts": len(window),
                    "attempt_rate": round(len(window) / duration, 2),
                    "port": dst_port,
                    "window_seconds": service["window"],
                },
            )]

    def reset_state(self) -> None:
        super().reset_state()
        with self._lock:
            self._windows.clear()
