"""
Traffic spike detector.

Detects abnormal traffic volume using z-score analysis
against the rolling baseline.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from app.detection.base_detector import BaseDetector, AttackIndicator
from app.detection.traffic_analysis.baseline_builder import TrafficBaseline

logger = logging.getLogger(__name__)


class TrafficSpikeDetector(BaseDetector):
    """Detects traffic volume spikes using z-score analysis.

    Alert condition: current rate > mean + (z_threshold × stddev).
    Default z_threshold = 3.0 (99.7% confidence).
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        super().__init__(config)
        self._z_threshold = self._config.get("z_score_threshold", 3.0)
        self._min_samples = self._config.get("min_baseline_samples", 10)
        self._window_seconds = 60

        self._baseline = TrafficBaseline(bootstrap_minutes=self._min_samples)

        # Current minute counters
        self._lock = threading.Lock()
        self._current_packets: int = 0
        self._current_bytes: int = 0
        self._current_protocols: dict[str, int] = defaultdict(int)
        self._window_start: float = time.time()
        self._unique_ips: set = set()

    def get_name(self) -> str:
        return "Traffic Spike Detector"

    def analyze(self, packet: dict) -> list[AttackIndicator]:
        self._record_analysis()

        src_ip = packet.get("src_ip")
        size = packet.get("packet_size", 0)
        protocol = packet.get("protocol", "Unknown")
        now = time.time()

        indicators = []

        with self._lock:
            self._current_packets += 1
            self._current_bytes += size
            self._current_protocols[protocol] += 1
            if src_ip:
                self._unique_ips.add(src_ip)

            # Check if window has elapsed
            elapsed = now - self._window_start
            if elapsed >= self._window_seconds:
                pps = self._current_packets / max(elapsed, 0.001)
                bps = self._current_bytes / max(elapsed, 0.001)

                # Record to baseline
                self._baseline.record_sample(
                    pps, bps,
                    dict(self._current_protocols),
                    len(self._unique_ips),
                )

                # Check for spike
                if self._baseline.is_ready:
                    spike = self._check_spike(pps, bps)
                    if spike:
                        indicators.append(spike)

                # Reset window
                self._current_packets = 0
                self._current_bytes = 0
                self._current_protocols = defaultdict(int)
                self._unique_ips = set()
                self._window_start = now

        return indicators

    def _check_spike(self, pps: float, bps: float) -> Optional[AttackIndicator]:
        """Check if current rates exceed baseline z-threshold.

        Args:
            pps: Current packets per second.
            bps: Current bytes per second.

        Returns:
            AttackIndicator if spike detected, None otherwise.
        """
        pps_stats = self._baseline.get_pps_stats()
        bps_stats = self._baseline.get_bps_stats()

        # Calculate z-scores
        pps_mean = pps_stats["mean"]
        pps_std = max(pps_stats["stddev"], 0.001)
        pps_zscore = (pps - pps_mean) / pps_std

        bps_mean = bps_stats["mean"]
        bps_std = max(bps_stats["stddev"], 0.001)
        bps_zscore = (bps - bps_mean) / bps_std

        # Alert if either exceeds threshold
        if pps_zscore <= self._z_threshold and bps_zscore <= self._z_threshold:
            return None

        spike_type = "pps" if pps_zscore > bps_zscore else "bps"
        z_score = max(pps_zscore, bps_zscore)
        confidence = min(0.5 + (z_score / 10.0), 0.95)

        self._record_alert()
        return AttackIndicator(
            attack_type="traffic_anomaly",
            source_ip="0.0.0.0",
            confidence=confidence,
            detector_name=self.get_name(),
            evidence={
                "spike_type": spike_type,
                "current_pps": round(pps, 2),
                "baseline_pps_mean": pps_mean,
                "baseline_pps_stddev": round(pps_std, 2),
                "pps_z_score": round(pps_zscore, 2),
                "current_bps": round(bps, 2),
                "baseline_bps_mean": bps_mean,
                "bps_z_score": round(bps_zscore, 2),
                "z_threshold": self._z_threshold,
            },
        )

    def reset_state(self) -> None:
        super().reset_state()
        with self._lock:
            self._baseline = TrafficBaseline(bootstrap_minutes=self._min_samples)
            self._current_packets = 0
            self._current_bytes = 0
            self._current_protocols = defaultdict(int)
            self._unique_ips = set()
