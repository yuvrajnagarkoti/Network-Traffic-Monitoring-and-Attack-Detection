"""
Unit tests for the Attack Detection Engine.
"""

from app.detection.orchestrator import DetectionOrchestrator
from app.detection.config import DetectionConfig


def test_orchestrator_registration(app):
    """Test that DetectionOrchestrator registers detectors correctly."""
    config = DetectionConfig()
    orchestrator = DetectionOrchestrator(app=app, config=config)
    orchestrator.register_all_detectors()

    assert len(orchestrator._detectors) > 0
    detector_names = [d.__class__.__name__ for d in orchestrator._detectors]
    
    # We should have various detector classes registered
    assert any("SynFlood" in name or "Ddos" in name or "Flood" in name for name in detector_names)
    assert any("PortScan" in name or "Scan" in name or "SynDetector" in name for name in detector_names)
