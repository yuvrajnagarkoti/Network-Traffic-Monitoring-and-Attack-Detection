"""
Base detector abstract class and AttackIndicator dataclass.

All detection modules inherit from BaseDetector and return
AttackIndicator instances when suspicious activity is found.
"""

import abc
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class AttackIndicator:
    """Structured detection result from a detector.

    Created by detectors when suspicious activity is found.
    The orchestrator collects these and deduplicates before
    creating AttackEvent database records.
    """

    attack_type: str
    source_ip: str
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    confidence: float = 0.0
    evidence: dict = field(default_factory=dict)
    packet_count: int = 0
    duration_seconds: int = 0
    detector_name: str = ""
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON response."""
        return {
            "attack_type": self.attack_type,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "packet_count": self.packet_count,
            "duration_seconds": self.duration_seconds,
            "detector_name": self.detector_name,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class BaseDetector(abc.ABC):
    """Abstract base class for all attack detectors.

    Each detector implements analyze() to inspect a parsed packet
    and return a list of AttackIndicators (empty if nothing found).

    Subclasses must implement:
        - analyze(packet) → list[AttackIndicator]
        - get_name() → str
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        """Initialize with optional configuration overrides.

        Args:
            config: Dictionary of threshold overrides.
        """
        self._config = config or {}
        self._calls_analyzed: int = 0
        self._alerts_generated: int = 0
        self._last_alert_time: Optional[float] = None
        self._start_time: float = time.time()

    @abc.abstractmethod
    def analyze(self, packet: dict) -> list[AttackIndicator]:
        """Analyze a parsed packet for attack indicators.

        Args:
            packet: Parsed packet dictionary from PacketParser.

        Returns:
            List of AttackIndicator objects. Empty if no attack detected.
        """
        ...

    @abc.abstractmethod
    def get_name(self) -> str:
        """Return the detector's human-readable name."""
        ...

    def get_config(self) -> dict:
        """Return current threshold configuration."""
        return dict(self._config)

    def update_config(self, new_config: dict) -> None:
        """Hot-reload configuration thresholds.

        Args:
            new_config: New threshold values to merge.
        """
        self._config.update(new_config)

    def reset_state(self) -> None:
        """Clear all internal detection state.

        Override in subclasses to clear detector-specific state
        (sliding windows, IP tracking dictionaries, etc).
        """
        self._calls_analyzed = 0
        self._alerts_generated = 0
        self._last_alert_time = None

    def get_stats(self) -> dict:
        """Return detection statistics.

        Returns:
            Dictionary with call count, alert count, and rates.
        """
        uptime = max(time.time() - self._start_time, 1)
        return {
            "detector": self.get_name(),
            "calls_analyzed": self._calls_analyzed,
            "alerts_generated": self._alerts_generated,
            "alert_rate": self._alerts_generated / uptime,
            "uptime_seconds": round(uptime, 2),
            "last_alert_time": self._last_alert_time,
        }

    def _record_alert(self) -> None:
        """Record that an alert was generated."""
        self._alerts_generated += 1
        self._last_alert_time = time.time()

    def _record_analysis(self) -> None:
        """Record that a packet was analyzed."""
        self._calls_analyzed += 1
