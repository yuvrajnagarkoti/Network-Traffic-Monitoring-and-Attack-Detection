"""
Threat scorer.

Main scoring algorithm that aggregates base scores and all
modifiers into a final 0–100 threat score with severity
classification and human-readable explanation.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.scoring.severity_classifier import SeverityLevel
from app.scoring import modifiers
from app.scoring.score_explanation import generate_explanation

logger = logging.getLogger(__name__)


class ThreatScorer:
    """Computes unified 0–100 threat scores for attack events.

    Combines:
    - Base score by attack type (0–50)
    - Rate modifier (+0 to +20)
    - Duration modifier (+0 to +10)
    - Recurrence modifier (+0 to +10)
    - IP reputation modifier (-10 to +15)
    - ML confidence modifier (+0 to +10)
    - Blacklist modifier (+0 to +20)
    - Critical asset modifier (+0 to +10)
    - Whitelist override (→ score = 0)

    Final score clamped to 0–100.
    """

    def __init__(self, app=None) -> None:
        """Initialize scorer.

        Args:
            app: Flask application instance.
        """
        self.app = app
        self._total_scored: int = 0

    def calculate(self, attack_event: dict) -> dict:
        """Calculate threat score for an attack event.

        Args:
            attack_event: Attack event dictionary with at minimum:
                - attack_type: str
                - source_ip: str
                - packet_count: int (optional)
                - duration_seconds: int (optional)
                - evidence: dict (optional)

        Returns:
            Score result dictionary with breakdown and explanation.
        """
        attack_type = attack_event.get("attack_type", "unknown")
        source_ip = attack_event.get("source_ip", "0.0.0.0")
        target_ip = attack_event.get("target_ip")
        evidence = attack_event.get("evidence", {})
        duration_seconds = attack_event.get("duration_seconds", 0)

        # Extract rate from evidence
        pps = evidence.get("syn_rate", 0) or evidence.get("udp_rate", 0) or evidence.get("request_rate", 0)
        aps = evidence.get("attempt_rate", 0) or evidence.get("scan_rate", 0)

        # ── Whitelist check (last step per roadmap, overrides everything) ──
        is_whitelisted = modifiers.whitelist_check(source_ip, self.app)

        if is_whitelisted:
            breakdown = self._whitelist_breakdown(attack_type, source_ip)
            self._total_scored += 1
            return breakdown

        # ── Compute all modifiers ──
        base = modifiers.base_score(attack_type)
        rate_mod = modifiers.rate_modifier(pps, aps)
        dur_mod = modifiers.duration_modifier(duration_seconds)
        rec_mod = modifiers.recurrence_modifier(source_ip, self.app)
        rep_mod = modifiers.ip_reputation_modifier(source_ip, self.app)
        ml_mod = modifiers.ml_confidence_modifier(source_ip, self.app)
        bl_mod = modifiers.blacklist_modifier(source_ip, self.app)
        ca_mod = modifiers.critical_asset_modifier(target_ip, self.app) if target_ip else 0

        # ── Aggregate and clamp ──
        raw_score = base + rate_mod + dur_mod + rec_mod + rep_mod + ml_mod + bl_mod + ca_mod
        final_score = max(0, min(100, raw_score))
        severity = SeverityLevel.classify(final_score)

        # ── Build breakdown ──
        breakdown = {
            "final_score": final_score,
            "severity": severity,
            "attack_type": attack_type,
            "source_ip": source_ip,
            "base_score": base,
            "rate_modifier": rate_mod,
            "rate_value": max(pps, aps),
            "duration_modifier": dur_mod,
            "duration_seconds": duration_seconds,
            "recurrence_modifier": rec_mod,
            "ip_reputation_modifier": rep_mod,
            "ml_confidence_modifier": ml_mod,
            "blacklist_modifier": bl_mod,
            "critical_asset_modifier": ca_mod,
            "whitelist_override": False,
            "raw_score": raw_score,
            "scored_at": datetime.now(timezone.utc).isoformat(),
        }

        breakdown["explanation"] = generate_explanation(breakdown)

        self._total_scored += 1

        logger.info(
            "Scored %s from %s: %d (%s)",
            attack_type, source_ip, final_score, severity,
        )

        return breakdown

    def persist_score(self, attack_event_id: str, breakdown: dict) -> Optional[str]:
        """Persist threat score to database.

        Args:
            attack_event_id: UUID of the attack event.
            breakdown: Score breakdown from calculate().

        Returns:
            Threat score UUID or None on failure.
        """
        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.threat import ThreatScore, SeverityLevel as SeverityEnum

                severity_map = {
                    "low": SeverityEnum.LOW,
                    "medium": SeverityEnum.MEDIUM,
                    "high": SeverityEnum.HIGH,
                    "critical": SeverityEnum.CRITICAL,
                }

                score_record = ThreatScore(
                    attack_event_id=attack_event_id,
                    base_score=breakdown["base_score"],
                    rate_modifier=breakdown["rate_modifier"],
                    duration_modifier=breakdown["duration_modifier"],
                    recurrence_modifier=breakdown["recurrence_modifier"],
                    ip_reputation_modifier=breakdown["ip_reputation_modifier"],
                    ml_confidence_modifier=breakdown["ml_confidence_modifier"],
                    blacklist_modifier=breakdown["blacklist_modifier"],
                    whitelist_override=breakdown["whitelist_override"],
                    final_score=breakdown["final_score"],
                    severity=severity_map.get(
                        breakdown["severity"], SeverityEnum.LOW
                    ),
                    explanation=breakdown.get("explanation", ""),
                )

                db.session.add(score_record)
                db.session.commit()

                return str(score_record.id)

        except Exception as exc:
            logger.error("Failed to persist threat score: %s", exc)
            return None

    def decay_score(self, current_score: int, hours_since_evidence: float) -> int:
        """Apply time-based score decay.

        Formula: current_score × 0.9^hours_since_evidence.

        Args:
            current_score: Current threat score.
            hours_since_evidence: Hours since last evidence packet.

        Returns:
            Decayed score (integer, minimum 0).
        """
        if hours_since_evidence <= 0:
            return current_score

        decayed = current_score * (0.9 ** hours_since_evidence)
        return max(0, int(decayed))

    def _whitelist_breakdown(self, attack_type: str, source_ip: str) -> dict:
        """Build a zeroed-out breakdown for whitelisted IPs."""
        breakdown = {
            "final_score": 0,
            "severity": SeverityLevel.LOW,
            "attack_type": attack_type,
            "source_ip": source_ip,
            "base_score": 0,
            "rate_modifier": 0,
            "rate_value": 0,
            "duration_modifier": 0,
            "duration_seconds": 0,
            "recurrence_modifier": 0,
            "ip_reputation_modifier": 0,
            "ml_confidence_modifier": 0,
            "blacklist_modifier": 0,
            "critical_asset_modifier": 0,
            "whitelist_override": True,
            "raw_score": 0,
            "scored_at": datetime.now(timezone.utc).isoformat(),
        }
        breakdown["explanation"] = generate_explanation(breakdown)
        return breakdown

    @property
    def stats(self) -> dict:
        """Return scorer statistics."""
        return {"total_scored": self._total_scored}
