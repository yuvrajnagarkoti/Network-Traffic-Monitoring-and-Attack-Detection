"""
Detection orchestrator.

Receives parsed packets and dispatches them to all registered
detectors in parallel. Collects AttackIndicators, deduplicates,
and manages attack state lifecycle.
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from app.detection.base_detector import BaseDetector, AttackIndicator
from app.detection.state_manager import AttackStateManager
from app.detection.config import DetectionConfig

logger = logging.getLogger(__name__)


class DetectionOrchestrator:
    """Orchestrates all detection modules.

    Dispatches each packet to all registered detectors in parallel
    using a thread pool. Collects returned AttackIndicators and
    routes them to the state manager for dedup and persistence.
    """

    def __init__(
        self,
        app=None,
        config: Optional[DetectionConfig] = None,
        max_workers: int = 8,
    ) -> None:
        """Initialize the orchestrator.

        Args:
            app: Flask application instance.
            config: Detection threshold configuration.
            max_workers: Thread pool size for parallel detection.
        """
        self.app = app
        self.config = config or DetectionConfig()
        self._detectors: list[BaseDetector] = []
        self._state_manager = AttackStateManager(
            app=app,
            resolve_timeout=self.config.get(
                "state_manager", "resolve_timeout_seconds", default=300
            ),
            max_tracked=self.config.get(
                "state_manager", "max_tracked_attacks", default=10000
            ),
        )
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="detector",
        )
        self._lock = threading.Lock()
        self._total_packets: int = 0
        self._total_indicators: int = 0
        self._running = False

    def register_detector(self, detector: BaseDetector) -> None:
        """Register a detector with the orchestrator.

        Args:
            detector: BaseDetector subclass instance.
        """
        self._detectors.append(detector)
        logger.info("Registered detector: %s", detector.get_name())

    def register_all_detectors(self) -> None:
        """Register all built-in detectors.

        Instantiates and registers every detection module with
        appropriate configuration sections.
        """
        from app.detection.port_scan.syn_detector import SynScanDetector
        from app.detection.port_scan.stealth_detector import StealthScanDetector
        from app.detection.port_scan.udp_scan_detector import UdpScanDetector
        from app.detection.brute_force.ssh_detector import SshBruteForceDetector
        from app.detection.brute_force.http_detector import HttpBruteForceDetector
        from app.detection.brute_force.generic_detector import GenericBruteForceDetector
        from app.detection.brute_force.distributed_detector import DistributedBruteForceDetector
        from app.detection.traffic_analysis.spike_detector import TrafficSpikeDetector
        from app.detection.traffic_analysis.protocol_anomaly import ProtocolAnomalyDetector
        from app.detection.ddos.syn_flood_detector import SynFloodDetector
        from app.detection.ddos.udp_flood_detector import UdpFloodDetector
        from app.detection.ddos.http_flood_detector import HttpFloodDetector

        port_scan_cfg = self.config.get("port_scan", default={})
        brute_cfg = self.config.get("brute_force", default={})
        traffic_cfg = self.config.get("traffic_analysis", default={})
        ddos_cfg = self.config.get("ddos", default={})

        detectors = [
            SynScanDetector(config=port_scan_cfg.get("syn_scan", {})),
            StealthScanDetector(config=port_scan_cfg.get("stealth_scan", {})),
            UdpScanDetector(config=port_scan_cfg.get("udp_scan", {})),
            SshBruteForceDetector(config=brute_cfg.get("ssh", {})),
            HttpBruteForceDetector(config=brute_cfg.get("http", {})),
            GenericBruteForceDetector(config=brute_cfg.get("generic", {})),
            DistributedBruteForceDetector(config=brute_cfg.get("distributed", {})),
            TrafficSpikeDetector(config=traffic_cfg.get("spike", {})),
            ProtocolAnomalyDetector(config=traffic_cfg.get("protocol_anomaly", {})),
            SynFloodDetector(config=ddos_cfg.get("syn_flood", {})),
            UdpFloodDetector(config=ddos_cfg.get("udp_flood", {})),
            HttpFloodDetector(config=ddos_cfg.get("http_flood", {})),
        ]

        for detector in detectors:
            self.register_detector(detector)

        logger.info("Registered %d detectors", len(detectors))

    def analyze_packet(self, parsed_packet: dict) -> list[AttackIndicator]:
        """Dispatch a packet to all detectors and collect results.

        Runs all detectors in parallel via thread pool.
        Indicators are routed to the state manager.

        Args:
            parsed_packet: Parsed packet from PacketParser.

        Returns:
            List of AttackIndicators found by all detectors.
        """
        self._total_packets += 1
        all_indicators: list[AttackIndicator] = []

        # Submit to all detectors in parallel
        futures = {
            self._executor.submit(
                self._safe_analyze, detector, parsed_packet
            ): detector
            for detector in self._detectors
        }

        for future in as_completed(futures, timeout=5.0):
            try:
                indicators = future.result()
                if indicators:
                    all_indicators.extend(indicators)
            except Exception as exc:
                detector = futures[future]
                logger.debug(
                    "Detector %s error: %s",
                    detector.get_name(),
                    exc,
                )

        # Route indicators to state manager
        for indicator in all_indicators:
            self._state_manager.update_or_create(indicator)
            self._total_indicators += 1

        return all_indicators

    def _safe_analyze(
        self, detector: BaseDetector, packet: dict
    ) -> list[AttackIndicator]:
        """Safely run a detector's analyze method.

        Catches all exceptions to prevent one detector from
        crashing the entire pipeline.

        Args:
            detector: Detector to run.
            packet: Parsed packet.

        Returns:
            List of AttackIndicator objects or empty list.
        """
        try:
            return detector.analyze(packet)
        except Exception as exc:
            logger.debug(
                "Detector %s failed on packet: %s",
                detector.get_name(),
                exc,
            )
            return []

    def start(self) -> None:
        """Start the orchestrator and state manager."""
        self._running = True
        self._state_manager.start_resolver(interval=30.0)
        logger.info(
            "Detection orchestrator started with %d detectors",
            len(self._detectors),
        )

    def stop(self) -> None:
        """Stop the orchestrator and clean up."""
        self._running = False
        self._state_manager.stop_resolver()
        self._executor.shutdown(wait=False)
        logger.info("Detection orchestrator stopped")

    def get_active_attacks(self) -> list[dict]:
        """Get all currently active attacks."""
        return self._state_manager.get_active_attacks()

    def get_detector_stats(self) -> list[dict]:
        """Get statistics from all registered detectors."""
        return [d.get_stats() for d in self._detectors]

    @property
    def stats(self) -> dict:
        """Return orchestrator statistics."""
        return {
            "total_packets_analyzed": self._total_packets,
            "total_indicators": self._total_indicators,
            "registered_detectors": len(self._detectors),
            "state_manager": self._state_manager.stats,
            "is_running": self._running,
        }
