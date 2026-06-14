"""
SYN scan detector.

Detects SYN port scans by tracking the number of unique destination
ports a single source IP sends SYN packets to within a sliding window.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from app.detection.base_detector import BaseDetector, AttackIndicator

logger = logging.getLogger(__name__)

MAX_TRACKED_IPS = 100_000


class SynScanDetector(BaseDetector):
    """Detects SYN port scan activity.

    Trigger: Same source IP sends SYN to >15 unique destination
    ports within 10 seconds.

    Classifies scan pattern:
        - Sequential ports (1,2,3...) = systematic scan
        - Random ports = evasive scan
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        super().__init__(config)
        self._port_threshold = self._config.get("port_threshold", 15)
        self._time_window = self._config.get("time_window_seconds", 10)
        self._slow_window = self._config.get("slow_scan_window_seconds", 300)
        self._fast_rate = self._config.get("fast_scan_rate", 20.0)
        self._slow_rate = self._config.get("slow_scan_rate", 5.0)

        # Per-IP sliding window of (port, timestamp) for fast scan
        self._ip_fast_windows: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=500)
        )
        # Per-IP sliding window for slow scan (5 min)
        self._ip_slow_windows: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=2000)
        )
        self._lock = threading.Lock()

    def get_name(self) -> str:
        return "SYN Scan Detector"

    def analyze(self, packet: dict) -> list[AttackIndicator]:
        self._record_analysis()

        # Only interested in SYN-only packets (no ACK)
        flags = packet.get("flags")
        if not flags or "SYN" not in flags or "ACK" in flags:
            return []

        if packet.get("layer4") != "TCP":
            return []

        src_ip = packet.get("src_ip")
        dst_port = packet.get("dst_port")
        if not src_ip or dst_port is None:
            return []

        now = time.time()
        indicators = []

        with self._lock:
            # Enforce IP tracking limit
            if src_ip not in self._ip_fast_windows and len(self._ip_fast_windows) >= MAX_TRACKED_IPS:
                return []

            # Add to fast window
            self._ip_fast_windows[src_ip].append((dst_port, now))
            self._ip_slow_windows[src_ip].append((dst_port, now))

            # Check fast scan (10s window)
            fast_indicator = self._check_window(
                src_ip, self._ip_fast_windows[src_ip],
                self._time_window, self._port_threshold, now, "fast"
            )
            if fast_indicator:
                indicators.append(fast_indicator)

            # Check slow scan (5 min window)
            if not fast_indicator:
                slow_indicator = self._check_window(
                    src_ip, self._ip_slow_windows[src_ip],
                    self._slow_window, self._port_threshold * 3, now, "slow"
                )
                if slow_indicator:
                    indicators.append(slow_indicator)

        return indicators

    def _check_window(
        self,
        src_ip: str,
        window: deque,
        time_limit: float,
        port_limit: int,
        now: float,
        scan_speed: str,
    ) -> Optional[AttackIndicator]:
        """Check a sliding window for scan threshold breach.

        Args:
            src_ip: Source IP being checked.
            window: Deque of (port, timestamp).
            time_limit: Window duration in seconds.
            port_limit: Unique port threshold.
            now: Current timestamp.
            scan_speed: 'fast' or 'slow'.

        Returns:
            AttackIndicator if threshold breached, None otherwise.
        """
        # Prune expired entries
        while window and (now - window[0][1]) > time_limit:
            window.popleft()

        if not window:
            return None

        # Count unique ports in window
        unique_ports = set(port for port, _ in window)
        if len(unique_ports) < port_limit:
            return None

        # Calculate scan rate
        duration = max(now - window[0][1], 0.001)
        scan_rate = len(unique_ports) / duration

        # Classify scan pattern
        sorted_ports = sorted(unique_ports)
        sequential = all(
            sorted_ports[i + 1] - sorted_ports[i] <= 2
            for i in range(min(len(sorted_ports) - 1, 20))
        ) if len(sorted_ports) > 3 else False

        pattern = "sequential" if sequential else "random"
        confidence = 0.9 if scan_speed == "fast" else 0.7

        self._record_alert()
        return AttackIndicator(
            attack_type="port_scan",
            source_ip=src_ip,
            confidence=confidence,
            packet_count=len(window),
            duration_seconds=int(duration),
            detector_name=self.get_name(),
            evidence={
                "scanned_ports": sorted(unique_ports)[:50],
                "unique_port_count": len(unique_ports),
                "scan_rate": round(scan_rate, 2),
                "scan_pattern": pattern,
                "scan_speed": scan_speed,
                "technique": "syn",
                "window_seconds": time_limit,
            },
        )

    def reset_state(self) -> None:
        super().reset_state()
        with self._lock:
            self._ip_fast_windows.clear()
            self._ip_slow_windows.clear()
