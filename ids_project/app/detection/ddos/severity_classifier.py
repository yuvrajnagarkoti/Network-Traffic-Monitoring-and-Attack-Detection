"""
DDoS severity classifier.

Classifies DDoS attacks into severity levels based on
packet rate, attack vectors, and duration.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Default severity thresholds (packets per second)
DEFAULT_SEVERITY_CONFIG = {
    "low_pps": 100,
    "medium_pps": 500,
    "high_pps": 2000,
    "critical_pps": 10000,
}


class DDoSSeverityClassifier:
    """Classifies DDoS attack severity.

    Severity levels:
        - LOW: 100–500 pps, single vector, <5 min
        - MEDIUM: 500–2000 pps, single vector, >5 min
        - HIGH: >2000 pps, multiple vectors, sustained
        - CRITICAL: >10000 pps, service impacting
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        """Initialize with severity thresholds.

        Args:
            config: Override thresholds.
        """
        cfg = config or DEFAULT_SEVERITY_CONFIG
        self._low_pps = cfg.get("low_pps", 100)
        self._medium_pps = cfg.get("medium_pps", 500)
        self._high_pps = cfg.get("high_pps", 2000)
        self._critical_pps = cfg.get("critical_pps", 10000)

    def classify(
        self,
        packets_per_second: float,
        duration_seconds: int = 0,
        attack_vectors: int = 1,
        unique_source_ips: int = 1,
    ) -> dict:
        """Classify DDoS attack severity.

        Args:
            packets_per_second: Current attack packet rate.
            duration_seconds: Attack duration so far.
            attack_vectors: Number of distinct attack vectors.
            unique_source_ips: Number of unique source IPs.

        Returns:
            Classification result with severity, score, and description.
        """
        # Base severity from pps
        if packets_per_second >= self._critical_pps:
            severity = "critical"
            base_score = 95
        elif packets_per_second >= self._high_pps:
            severity = "high"
            base_score = 75
        elif packets_per_second >= self._medium_pps:
            severity = "medium"
            base_score = 50
        elif packets_per_second >= self._low_pps:
            severity = "low"
            base_score = 25
        else:
            severity = "info"
            base_score = 10

        # Duration modifier
        duration_modifier = 0
        if duration_seconds > 600:
            duration_modifier = 15
        elif duration_seconds > 300:
            duration_modifier = 10
        elif duration_seconds > 60:
            duration_modifier = 5

        # Multi-vector modifier
        vector_modifier = min((attack_vectors - 1) * 10, 20)

        # Distributed modifier
        distributed_modifier = 0
        if unique_source_ips > 100:
            distributed_modifier = 15
        elif unique_source_ips > 50:
            distributed_modifier = 10
        elif unique_source_ips > 10:
            distributed_modifier = 5

        final_score = min(
            base_score + duration_modifier + vector_modifier + distributed_modifier,
            100,
        )

        # Recalculate severity from final score
        if final_score >= 90:
            severity = "critical"
        elif final_score >= 70:
            severity = "high"
        elif final_score >= 40:
            severity = "medium"
        elif final_score >= 15:
            severity = "low"

        # Generate description
        description = self._generate_description(
            severity, packets_per_second, duration_seconds,
            attack_vectors, unique_source_ips,
        )

        return {
            "severity": severity,
            "score": final_score,
            "packets_per_second": round(packets_per_second, 2),
            "duration_seconds": duration_seconds,
            "attack_vectors": attack_vectors,
            "unique_source_ips": unique_source_ips,
            "description": description,
            "requires_immediate_action": severity in ("critical", "high"),
        }

    def _generate_description(
        self,
        severity: str,
        pps: float,
        duration: int,
        vectors: int,
        ips: int,
    ) -> str:
        """Generate human-readable severity description."""
        duration_str = (
            f"{duration // 60}m{duration % 60}s" if duration >= 60
            else f"{duration}s"
        )

        parts = [f"{severity.upper()} DDoS attack"]
        parts.append(f"at {pps:.0f} pps")
        parts.append(f"for {duration_str}")

        if vectors > 1:
            parts.append(f"across {vectors} attack vectors")
        if ips > 1:
            parts.append(f"from {ips} source IPs")

        return " ".join(parts)
