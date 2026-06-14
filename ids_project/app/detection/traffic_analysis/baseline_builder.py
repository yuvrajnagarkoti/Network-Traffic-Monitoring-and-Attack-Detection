"""
Traffic baseline builder.

Builds a rolling baseline of normal traffic patterns used
by the spike detector and protocol anomaly detector.
"""

import logging
import threading
import time
from collections import deque
from typing import Optional

logger = logging.getLogger(__name__)


class TrafficBaseline:
    """Maintains a rolling baseline of normal traffic metrics.

    Collects per-minute traffic snapshots and computes mean
    and standard deviation for anomaly detection.
    """

    def __init__(
        self,
        bootstrap_minutes: int = 60,
        max_samples: int = 1440,
    ) -> None:
        """Initialize baseline.

        Args:
            bootstrap_minutes: Minutes of data before baseline is valid.
            max_samples: Maximum stored samples (default: 24 hours).
        """
        self.bootstrap_minutes = bootstrap_minutes
        self._samples: deque = deque(maxlen=max_samples)
        self._lock = threading.Lock()
        self._start_time = time.time()

    def record_sample(
        self,
        packets_per_second: float,
        bytes_per_second: float,
        protocol_distribution: dict,
        unique_ips: int = 0,
    ) -> None:
        """Record a 1-minute traffic snapshot.

        Args:
            packets_per_second: Packet rate for the interval.
            bytes_per_second: Byte rate for the interval.
            protocol_distribution: Dict of {protocol: count}.
            unique_ips: Number of unique source IPs.
        """
        sample = {
            "pps": packets_per_second,
            "bps": bytes_per_second,
            "protocols": dict(protocol_distribution),
            "unique_ips": unique_ips,
            "timestamp": time.time(),
        }
        with self._lock:
            self._samples.append(sample)

    @property
    def is_ready(self) -> bool:
        """Check if enough data has been collected for baseline."""
        return len(self._samples) >= self.bootstrap_minutes

    @property
    def sample_count(self) -> int:
        """Number of recorded samples."""
        return len(self._samples)

    def get_pps_stats(self) -> dict:
        """Get packets-per-second mean and standard deviation."""
        return self._compute_stats("pps")

    def get_bps_stats(self) -> dict:
        """Get bytes-per-second mean and standard deviation."""
        return self._compute_stats("bps")

    def get_protocol_baseline(self) -> dict:
        """Get average protocol distribution percentages."""
        with self._lock:
            if not self._samples:
                return {}

            totals = {}
            count = len(self._samples)

            for sample in self._samples:
                for proto, pkt_count in sample["protocols"].items():
                    totals[proto] = totals.get(proto, 0) + pkt_count

            grand_total = sum(totals.values()) or 1
            return {
                proto: round((total / grand_total) * 100, 2)
                for proto, total in sorted(
                    totals.items(), key=lambda x: x[1], reverse=True
                )
            }

    def _compute_stats(self, field: str) -> dict:
        """Compute mean and stddev for a numeric field.

        Args:
            field: Sample field name ('pps' or 'bps').

        Returns:
            Dict with mean, stddev, min, max, count.
        """
        with self._lock:
            if not self._samples:
                return {"mean": 0, "stddev": 0, "min": 0, "max": 0, "count": 0}

            values = [s[field] for s in self._samples]
            n = len(values)
            mean = sum(values) / n
            variance = sum((x - mean) ** 2 for x in values) / max(n, 1)
            stddev = variance ** 0.5

            return {
                "mean": round(mean, 2),
                "stddev": round(stddev, 2),
                "min": round(min(values), 2),
                "max": round(max(values), 2),
                "count": n,
            }

    def to_dict(self) -> dict:
        """Serialize baseline state."""
        return {
            "is_ready": self.is_ready,
            "sample_count": self.sample_count,
            "bootstrap_required": self.bootstrap_minutes,
            "pps_stats": self.get_pps_stats(),
            "bps_stats": self.get_bps_stats(),
            "protocol_baseline": self.get_protocol_baseline(),
        }
