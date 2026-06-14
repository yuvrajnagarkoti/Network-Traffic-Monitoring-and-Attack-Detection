"""
Port scan classifier.

Classifies detected port scans as vertical, horizontal, or
network sweep based on the IP/port distribution pattern.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ScanClassifier:
    """Classifies port scan patterns.

    - Vertical scan: single target IP, many ports → host recon
    - Horizontal scan: many target IPs, same port → service scan
    - Network sweep: many target IPs, few ports → discovery
    """

    @staticmethod
    def classify(evidence: dict) -> dict:
        """Classify a port scan from its evidence.

        Args:
            evidence: Evidence dictionary from a scan detector.

        Returns:
            Classification result with scan_class and severity_modifier.
        """
        scanned_ports = evidence.get("scanned_ports", [])
        unique_port_count = evidence.get("unique_port_count", len(scanned_ports))
        unique_target_ips = evidence.get("unique_target_ips", 1)
        technique = evidence.get("technique", "unknown")

        # Classify based on IP/port distribution
        if unique_target_ips <= 2 and unique_port_count > 10:
            scan_class = "vertical"
            description = "Targeted host reconnaissance — many ports, single target"
            severity_modifier = 1.0
        elif unique_target_ips > 5 and unique_port_count <= 3:
            scan_class = "horizontal"
            description = "Service-specific scan — same port across many hosts"
            severity_modifier = 1.3
        elif unique_target_ips > 10 and unique_port_count <= 5:
            scan_class = "network_sweep"
            description = "Network discovery — scanning subnet for live hosts"
            severity_modifier = 1.5
        else:
            scan_class = "mixed"
            description = "Mixed scan pattern"
            severity_modifier = 1.0

        # Technique-based modifier
        technique_modifiers = {
            "syn": 1.0,
            "fin": 1.3,
            "null": 1.3,
            "xmas": 1.4,
            "udp": 0.9,
        }
        technique_mod = technique_modifiers.get(technique, 1.0)

        # Scan rate modifier
        scan_rate = evidence.get("scan_rate", 0)
        if scan_rate > 50:
            rate_description = "aggressive"
            rate_modifier = 1.5
        elif scan_rate > 20:
            rate_description = "fast"
            rate_modifier = 1.2
        elif scan_rate > 5:
            rate_description = "moderate"
            rate_modifier = 1.0
        else:
            rate_description = "slow"
            rate_modifier = 0.8

        return {
            "scan_class": scan_class,
            "description": description,
            "severity_modifier": round(severity_modifier * technique_mod * rate_modifier, 2),
            "technique": technique,
            "rate_description": rate_description,
            "unique_ports": unique_port_count,
            "unique_targets": unique_target_ips,
        }
