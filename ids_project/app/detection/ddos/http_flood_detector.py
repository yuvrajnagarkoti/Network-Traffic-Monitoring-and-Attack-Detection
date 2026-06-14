"""
HTTP flood detector (Layer 7 DDoS).

Detects HTTP flood attacks by tracking request rate from
multiple source IPs to the same destination endpoint.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from app.detection.base_detector import BaseDetector, AttackIndicator

logger = logging.getLogger(__name__)


class HttpFloodDetector(BaseDetector):
    """Detects HTTP flood (Layer 7 DDoS) attacks.

    Trigger: >500 HTTP requests/s to single endpoint from
    >50 unique source IPs.

    Tracks by destination IP on HTTP ports (80/443/8080).
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        super().__init__(config)
        self._rate_threshold = self._config.get("request_rate_threshold", 500)
        self._ip_threshold = self._config.get("unique_ip_threshold", 50)
        self._time_window = self._config.get("time_window_seconds", 10)
        self._http_ports = {80, 443, 8080, 8443}

        # Per-destination: deque of (src_ip, timestamp)
        self._dst_windows: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=20000)
        )
        self._lock = threading.Lock()

    def get_name(self) -> str:
        return "HTTP Flood Detector"

    def analyze(self, packet: dict) -> list[AttackIndicator]:
        self._record_analysis()

        if packet.get("layer4") != "TCP":
            return []

        dst_port = packet.get("dst_port")
        if dst_port not in self._http_ports:
            return []

        # Track data-bearing packets (PSH = HTTP request body)
        flags = packet.get("flags", "")
        if "PSH" not in flags and "SYN" not in flags:
            return []

        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        if not src_ip or not dst_ip:
            return []

        now = time.time()

        with self._lock:
            if dst_ip not in self._dst_windows and len(self._dst_windows) >= 50000:
                return []

            self._dst_windows[dst_ip].append((src_ip, now))

            window = self._dst_windows[dst_ip]
            while window and (now - window[0][1]) > self._time_window:
                window.popleft()

            request_count = len(window)
            duration = max(now - window[0][1], 0.001) if window else 1
            request_rate = request_count / duration
            unique_ips = set(ip for ip, _ in window)

            if request_rate < self._rate_threshold:
                return []
            if len(unique_ips) < self._ip_threshold:
                return []

            confidence = min(0.7 + (request_rate / 5000.0), 0.95)

            self._record_alert()
            return [AttackIndicator(
                attack_type="ddos",
                source_ip=list(unique_ips)[0],
                target_ip=dst_ip,
                target_port=dst_port,
                confidence=confidence,
                packet_count=request_count,
                duration_seconds=int(duration),
                detector_name=self.get_name(),
                evidence={
                    "attack_vector": "http_flood",
                    "request_rate": round(request_rate, 2),
                    "request_count": request_count,
                    "unique_source_ips": len(unique_ips),
                    "contributing_ips": list(unique_ips)[:20],
                    "target_ip": dst_ip,
                    "target_port": dst_port,
                    "window_seconds": self._time_window,
                },
            )]

    def reset_state(self) -> None:
        super().reset_state()
        with self._lock:
            self._dst_windows.clear()
