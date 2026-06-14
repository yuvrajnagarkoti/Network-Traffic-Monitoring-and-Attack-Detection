"""
Stealth scan detector (FIN/NULL/Xmas).

Detects stealth port scan techniques that use unusual TCP flag
combinations. These are almost never legitimate traffic.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from app.detection.base_detector import BaseDetector, AttackIndicator

logger = logging.getLogger(__name__)

MAX_TRACKED_IPS = 100_000


class StealthScanDetector(BaseDetector):
    """Detects FIN, NULL, and Xmas stealth scans.

    - FIN scan: only FIN flag set
    - NULL scan: no flags set
    - Xmas scan: FIN + PSH + URG flags set

    Even a small number to multiple ports triggers an alert
    because these flag combinations are never legitimate.
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        super().__init__(config)
        self._port_threshold = self._config.get("port_threshold", 3)
        self._time_window = self._config.get("time_window_seconds", 60)
        self._confidence = self._config.get("confidence", 0.95)

        # Per-IP: {src_ip: deque of (scan_type, port, timestamp)}
        self._ip_windows: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=500)
        )
        self._lock = threading.Lock()

    def get_name(self) -> str:
        return "Stealth Scan Detector"

    def analyze(self, packet: dict) -> list[AttackIndicator]:
        self._record_analysis()

        if packet.get("layer4") != "TCP":
            return []

        flags = packet.get("flags")
        if not flags:
            return []

        # Identify stealth scan type
        scan_type = self._classify_stealth(flags)
        if scan_type is None:
            return []

        src_ip = packet.get("src_ip")
        dst_port = packet.get("dst_port")
        if not src_ip or dst_port is None:
            return []

        now = time.time()
        indicators = []

        with self._lock:
            if src_ip not in self._ip_windows and len(self._ip_windows) >= MAX_TRACKED_IPS:
                return []

            self._ip_windows[src_ip].append((scan_type, dst_port, now))

            # Prune expired
            window = self._ip_windows[src_ip]
            while window and (now - window[0][2]) > self._time_window:
                window.popleft()

            # Count unique ports for this scan type
            type_ports = set(
                port for stype, port, _ in window if stype == scan_type
            )

            if len(type_ports) >= self._port_threshold:
                self._record_alert()
                indicators.append(AttackIndicator(
                    attack_type="port_scan",
                    source_ip=src_ip,
                    target_port=dst_port,
                    confidence=self._confidence,
                    packet_count=len(window),
                    duration_seconds=int(now - window[0][2]) if window else 0,
                    detector_name=self.get_name(),
                    evidence={
                        "scan_type": scan_type,
                        "technique": scan_type,
                        "scanned_ports": sorted(type_ports)[:50],
                        "unique_port_count": len(type_ports),
                        "window_seconds": self._time_window,
                    },
                ))

        return indicators

    def _classify_stealth(self, flags: str) -> Optional[str]:
        """Classify TCP flag combination as stealth scan type.

        Args:
            flags: Pipe-separated flag string (e.g. 'FIN|PSH|URG').

        Returns:
            Scan type string or None if not stealth.
        """
        flag_set = set(flags.split("|")) if flags else set()

        # NULL scan: no flags
        if flag_set == {"NONE"} or len(flag_set) == 0:
            return "null"

        # FIN scan: only FIN (no SYN, no ACK)
        if flag_set == {"FIN"}:
            return "fin"

        # Xmas scan: FIN + PSH + URG
        if flag_set == {"FIN", "PSH", "URG"}:
            return "xmas"

        return None

    def reset_state(self) -> None:
        super().reset_state()
        with self._lock:
            self._ip_windows.clear()
