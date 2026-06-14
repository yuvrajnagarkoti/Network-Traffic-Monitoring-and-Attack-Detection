"""
SYN flood detector.

Detects SYN flood DDoS attacks by tracking the ratio of SYN
packets to completed handshakes (SYN-ACK) per destination IP.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from app.detection.base_detector import BaseDetector, AttackIndicator

logger = logging.getLogger(__name__)


class SynFloodDetector(BaseDetector):
    """Detects SYN flood attacks.

    SYN flood = massive SYN volume without completing handshake.

    Trigger: >500 SYN/s to single destination IP with
    SYN-ACK completion rate <10%.
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        super().__init__(config)
        self._syn_threshold = self._config.get("syn_rate_threshold", 500)
        self._completion_threshold = self._config.get("completion_rate_threshold", 0.10)
        self._time_window = self._config.get("time_window_seconds", 10)

        # Per-destination IP: deque of (event_type, timestamp)
        self._dst_windows: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=10000)
        )
        self._lock = threading.Lock()

    def get_name(self) -> str:
        return "SYN Flood Detector"

    def analyze(self, packet: dict) -> list[AttackIndicator]:
        self._record_analysis()

        if packet.get("layer4") != "TCP":
            return []

        flags = packet.get("flags", "")
        dst_ip = packet.get("dst_ip")
        if not dst_ip:
            return []

        is_syn = "SYN" in flags and "ACK" not in flags
        is_synack = "SYN" in flags and "ACK" in flags

        if not is_syn and not is_synack:
            return []

        now = time.time()
        event_type = "syn" if is_syn else "synack"

        with self._lock:
            if dst_ip not in self._dst_windows and len(self._dst_windows) >= 50000:
                return []

            self._dst_windows[dst_ip].append((event_type, now))

            window = self._dst_windows[dst_ip]
            while window and (now - window[0][1]) > self._time_window:
                window.popleft()

            syn_count = sum(1 for t, _ in window if t == "syn")
            synack_count = sum(1 for t, _ in window if t == "synack")

            duration = max(now - window[0][1], 0.001) if window else 1
            syn_rate = syn_count / duration

            if syn_rate < self._syn_threshold:
                return []

            completion_rate = synack_count / max(syn_count, 1)
            if completion_rate > self._completion_threshold:
                return []

            src_ip = packet.get("src_ip", "0.0.0.0")
            confidence = min(0.7 + (syn_rate / 5000.0), 0.98)

            self._record_alert()
            return [AttackIndicator(
                attack_type="ddos",
                source_ip=src_ip,
                target_ip=dst_ip,
                confidence=confidence,
                packet_count=syn_count,
                duration_seconds=int(duration),
                detector_name=self.get_name(),
                evidence={
                    "attack_vector": "syn_flood",
                    "syn_rate": round(syn_rate, 2),
                    "syn_count": syn_count,
                    "synack_count": synack_count,
                    "completion_rate": round(completion_rate, 4),
                    "target_ip": dst_ip,
                    "window_seconds": self._time_window,
                },
            )]

    def reset_state(self) -> None:
        super().reset_state()
        with self._lock:
            self._dst_windows.clear()
