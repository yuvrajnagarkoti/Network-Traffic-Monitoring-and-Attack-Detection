"""
Unit tests for the ThreatScorer and ResponseEngine components.
"""

import uuid
from datetime import datetime, timezone, timedelta
from app.models.attack import AttackEvent, AttackType, AttackStatus
from app.models.block import IpBlock, BlockType
from app.models.alert import Alert, AlertSeverity, EmailNotification, EmailDeliveryStatus
from app.scoring.threat_scorer import ThreatScorer
from app.scoring.response_engine import ResponseEngine
from app.extensions import db


def test_scoring_modifiers(app, db_session):
    """Test that ThreatScorer correctly calculates modifiers and base score."""
    event = AttackEvent(
        id=uuid.uuid4(),
        attack_type=AttackType.PORT_SCAN,
        source_ip="192.0.2.1",
        target_ip="10.0.0.5",
        target_port=22,
        confidence_score=0.8,
        packet_count=100,
        duration_seconds=10,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        status=AttackStatus.ACTIVE,
        evidence={"technique": "syn"}
    )
    db_session.add(event)
    db_session.commit()

    scorer = ThreatScorer(app=app)
    score_breakdown = scorer.score_attack(event)

    assert "final_score" in score_breakdown
    assert 0 <= score_breakdown["final_score"] <= 100
    assert score_breakdown["source_ip"] == "192.0.2.1"
    assert score_breakdown["attack_type"] == "port_scan"


def test_response_engine_critical(app, db_session):
    """Test ResponseEngine triggers IP block and email for CRITICAL threats (score >= 75)."""
    response_engine = ResponseEngine(app=app)
    breakdown = {
        "attack_event_id": str(uuid.uuid4()),
        "threat_score_id": str(uuid.uuid4()),
        "source_ip": "198.51.100.10",
        "attack_type": "ddos",
        "final_score": 85,
        "severity": "critical",
        "explanation": "Volumetric traffic spike detected.",
        "scored_at": datetime.now(timezone.utc).isoformat()
    }

    result = response_engine.process_scored_alert(breakdown)

    assert result["action"] == "critical_response"
    assert "alert_created" in result["actions"]
    assert "ip_blocked" in result["actions"]
    assert "email_queued" in result["actions"]

    # Verify database state
    alert = Alert.query.filter_by(id=result["alert_id"]).first()
    assert alert is not None
    assert alert.severity == AlertSeverity.CRITICAL

    block = IpBlock.query.filter_by(ip_address="198.51.100.10", is_active=True).first()
    assert block is not None
    assert block.block_type == BlockType.AUTO

    email = EmailNotification.query.filter_by(alert_id=result["alert_id"]).first()
    assert email is not None
    assert email.recipient_email == app.config.get("MAIL_DEFAULT_SENDER", "admin@localhost")


def test_response_engine_low(app, db_session):
    """Test ResponseEngine logs only for LOW threats (score < 25)."""
    response_engine = ResponseEngine(app=app)
    breakdown = {
        "attack_event_id": str(uuid.uuid4()),
        "threat_score_id": str(uuid.uuid4()),
        "source_ip": "198.51.100.20",
        "attack_type": "port_scan",
        "final_score": 15,
        "severity": "low",
        "explanation": "Single port scanned.",
        "scored_at": datetime.now(timezone.utc).isoformat()
    }

    result = response_engine.process_scored_alert(breakdown)

    assert result["action"] == "low_response"
    assert "logged" in result["actions"]
    assert result["alert_id"] is None
