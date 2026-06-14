"""
Automated response engine.

Evaluates scored threats and triggers appropriate actions:
- CRITICAL (≥75): auto IP block + immediate email + create alert
- HIGH (50-74): email alert + create alert
- MEDIUM (25-49): create alert only
- LOW (0-24): log only

All automatic decisions are audit-logged. Includes a score
decay daemon that reduces scores over time without new evidence.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class ResponseEngine:
    """Automated threat response decision engine.

    Processes scored alerts from the priority queue and
    triggers appropriate response actions based on severity.
    """

    # Score thresholds
    CRITICAL_THRESHOLD = 75
    HIGH_THRESHOLD = 50
    MEDIUM_THRESHOLD = 25

    def __init__(self, app=None) -> None:
        self.app = app
        self._stats = {
            "total_processed": 0,
            "critical_responses": 0,
            "high_responses": 0,
            "medium_responses": 0,
            "low_responses": 0,
            "blocks_triggered": 0,
            "emails_queued": 0,
            "alerts_created": 0,
        }

    def process_scored_alert(self, score_breakdown: dict) -> dict:
        """Process a scored alert and trigger appropriate response.

        Args:
            score_breakdown: Threat score breakdown from ThreatScorer.

        Returns:
            Response action summary dict.
        """
        final_score = score_breakdown.get("final_score", 0)
        severity = score_breakdown.get("severity", "low")
        source_ip = score_breakdown.get("source_ip", "unknown")
        attack_type = score_breakdown.get("attack_type", "unknown")
        is_whitelisted = score_breakdown.get("whitelist_override", False)

        self._stats["total_processed"] += 1

        # Whitelisted IPs never trigger responses
        if is_whitelisted:
            logger.info("Skipping response for whitelisted IP %s", source_ip)
            return {
                "action": "none",
                "reason": "whitelisted",
                "source_ip": source_ip,
            }

        if final_score >= self.CRITICAL_THRESHOLD:
            return self._handle_critical(score_breakdown)
        elif final_score >= self.HIGH_THRESHOLD:
            return self._handle_high(score_breakdown)
        elif final_score >= self.MEDIUM_THRESHOLD:
            return self._handle_medium(score_breakdown)
        else:
            return self._handle_low(score_breakdown)

    def _handle_critical(self, breakdown: dict) -> dict:
        """CRITICAL response: auto-block + email + alert."""
        self._stats["critical_responses"] += 1
        source_ip = breakdown["source_ip"]
        actions = []

        # Create alert in database
        alert_id = self._create_alert(breakdown)
        if alert_id:
            actions.append("alert_created")
            self._stats["alerts_created"] += 1

        # Trigger automatic IP block
        block_result = self._trigger_ip_block(breakdown, alert_id)
        if block_result:
            actions.append("ip_blocked")
            self._stats["blocks_triggered"] += 1

        # Queue immediate email notification
        email_result = self._queue_email(breakdown, alert_id, urgent=True)
        if email_result:
            actions.append("email_queued")
            self._stats["emails_queued"] += 1

        # Audit log
        self._audit_log(
            action="auto_response_critical",
            resource_type="threat_score",
            details={
                "source_ip": source_ip,
                "score": breakdown["final_score"],
                "actions_taken": actions,
            },
        )

        logger.warning(
            "CRITICAL response for %s (score=%d): %s",
            source_ip, breakdown["final_score"], ", ".join(actions),
        )

        return {
            "action": "critical_response",
            "source_ip": source_ip,
            "score": breakdown["final_score"],
            "actions": actions,
            "alert_id": alert_id,
        }

    def _handle_high(self, breakdown: dict) -> dict:
        """HIGH response: email + alert."""
        self._stats["high_responses"] += 1
        source_ip = breakdown["source_ip"]
        actions = []

        alert_id = self._create_alert(breakdown)
        if alert_id:
            actions.append("alert_created")
            self._stats["alerts_created"] += 1

        email_result = self._queue_email(breakdown, alert_id, urgent=False)
        if email_result:
            actions.append("email_queued")
            self._stats["emails_queued"] += 1

        self._audit_log(
            action="auto_response_high",
            resource_type="threat_score",
            details={
                "source_ip": source_ip,
                "score": breakdown["final_score"],
                "actions_taken": actions,
            },
        )

        logger.info(
            "HIGH response for %s (score=%d): %s",
            source_ip, breakdown["final_score"], ", ".join(actions),
        )

        return {
            "action": "high_response",
            "source_ip": source_ip,
            "score": breakdown["final_score"],
            "actions": actions,
            "alert_id": alert_id,
        }

    def _handle_medium(self, breakdown: dict) -> dict:
        """MEDIUM response: create alert only."""
        self._stats["medium_responses"] += 1
        source_ip = breakdown["source_ip"]

        alert_id = self._create_alert(breakdown)
        if alert_id:
            self._stats["alerts_created"] += 1

        logger.info(
            "MEDIUM response for %s (score=%d): alert created",
            source_ip, breakdown["final_score"],
        )

        return {
            "action": "medium_response",
            "source_ip": source_ip,
            "score": breakdown["final_score"],
            "actions": ["alert_created"] if alert_id else [],
            "alert_id": alert_id,
        }

    def _handle_low(self, breakdown: dict) -> dict:
        """LOW response: log only, no alert or notification."""
        self._stats["low_responses"] += 1

        logger.debug(
            "LOW response for %s (score=%d): logged only",
            breakdown["source_ip"], breakdown["final_score"],
        )

        return {
            "action": "low_response",
            "source_ip": breakdown["source_ip"],
            "score": breakdown["final_score"],
            "actions": ["logged"],
            "alert_id": None,
        }

    def _create_alert(self, breakdown: dict) -> Optional[str]:
        """Persist an alert record to the database.

        Returns:
            Alert UUID string or None on failure.
        """
        try:
            app = self._get_app()
            with app.app_context():
                from app.extensions import db
                from app.models.alert import Alert, AlertSeverity

                severity_map = {
                    "low": AlertSeverity.LOW,
                    "medium": AlertSeverity.MEDIUM,
                    "high": AlertSeverity.HIGH,
                    "critical": AlertSeverity.CRITICAL,
                }

                title = (
                    f"{breakdown.get('severity', 'unknown').upper()} — "
                    f"{breakdown.get('attack_type', 'unknown').replace('_', ' ').title()} "
                    f"from {breakdown.get('source_ip', 'unknown')}"
                )

                alert = Alert(
                    attack_event_id=breakdown.get("attack_event_id"),
                    threat_score_id=breakdown.get("threat_score_id"),
                    title=title,
                    message=breakdown.get("explanation", ""),
                    severity=severity_map.get(
                        breakdown.get("severity", "low"), AlertSeverity.LOW
                    ),
                )

                db.session.add(alert)
                db.session.commit()

                return str(alert.id)

        except Exception as exc:
            logger.error("Failed to create alert: %s", exc)
            return None

    def _trigger_ip_block(
        self, breakdown: dict, alert_id: Optional[str] = None
    ) -> bool:
        """Request IP block through the protection module.

        Returns:
            True if block was successfully requested.
        """
        try:
            app = self._get_app()
            source_ip = breakdown["source_ip"]
            reason = (
                f"Auto-blocked: score {breakdown['final_score']} "
                f"({breakdown.get('severity', 'unknown').upper()}) — "
                f"{breakdown.get('attack_type', 'unknown')}"
            )

            blocker = app.extensions.get("protection", {}).get("blocker")
            if blocker:
                res = blocker.block(
                    ip=source_ip,
                    reason=reason,
                    duration_hours=24,
                    attack_event_id=breakdown.get("attack_event_id"),
                    block_type="auto",
                )
                return res.get("success", False)

            # Fallback if blocker not initialized
            with app.app_context():
                from app.extensions import db
                from app.models.block import IpBlock, BlockType

                # Check if already blocked
                existing = IpBlock.query.filter_by(
                    ip_address=source_ip, is_active=True
                ).first()

                if existing:
                    logger.info("IP %s already blocked, skipping", source_ip)
                    return False

                # Create block record (24-hour default for auto-blocks)
                block = IpBlock(
                    ip_address=source_ip,
                    block_type=BlockType.AUTO,
                    reason=reason,
                    attack_event_id=breakdown.get("attack_event_id"),
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                    is_active=True,
                )

                db.session.add(block)
                db.session.commit()

                logger.warning("Auto-blocked IP %s for 24 hours (fallback)", source_ip)
                return True

        except Exception as exc:
            logger.error("Failed to trigger IP block: %s", exc)
            return False

    def _queue_email(
        self,
        breakdown: dict,
        alert_id: Optional[str],
        urgent: bool = False,
    ) -> bool:
        """Queue an email notification for the alert.

        Returns:
            True if email was successfully queued.
        """
        try:
            app = self._get_app()
            with app.app_context():
                from app.extensions import db
                from app.models.alert import EmailNotification

                recipient = app.config.get(
                    "ALERT_EMAIL_RECIPIENT",
                    app.config.get("MAIL_DEFAULT_SENDER", "admin@localhost"),
                )

                urgency = "🚨 URGENT" if urgent else "⚠️"
                subject = (
                    f"{urgency} [{breakdown.get('severity', 'unknown').upper()}] "
                    f"{breakdown.get('attack_type', 'unknown').replace('_', ' ').title()} "
                    f"detected from {breakdown.get('source_ip', 'unknown')}"
                )

                body = (
                    f"Threat Score: {breakdown.get('final_score', 0)}/100\n"
                    f"Severity: {breakdown.get('severity', 'unknown').upper()}\n"
                    f"Attack Type: {breakdown.get('attack_type', 'unknown')}\n"
                    f"Source IP: {breakdown.get('source_ip', 'unknown')}\n\n"
                    f"Score Breakdown:\n"
                    f"{breakdown.get('explanation', 'N/A')}\n\n"
                    f"Time: {breakdown.get('scored_at', 'N/A')}\n"
                )

                notification = EmailNotification(
                    alert_id=alert_id,
                    recipient_email=recipient,
                    subject=subject,
                    body_template=body,
                )

                db.session.add(notification)
                db.session.commit()

                return True

        except Exception as exc:
            logger.error("Failed to queue email: %s", exc)
            return False

    def _audit_log(
        self,
        action: str,
        resource_type: str,
        details: dict,
    ) -> None:
        """Write an audit log entry for the automatic action."""
        try:
            app = self._get_app()
            with app.app_context():
                from app.extensions import db
                from app.models.audit import AuditLog

                log = AuditLog(
                    action=action,
                    resource_type=resource_type,
                    new_value=details,
                )

                db.session.add(log)
                db.session.commit()

        except Exception as exc:
            logger.error("Failed to write audit log: %s", exc)

    def run_score_decay(self) -> dict:
        """Decay active threat scores that have no new evidence.

        Formula: current_score × 0.9^(hours_since_last_evidence)

        Transitions attacks from ACTIVE to MONITORING when score
        drops below the MEDIUM threshold (25).

        Returns:
            Summary of decay operations performed.
        """
        results = {"decayed": 0, "transitioned": 0, "errors": 0}

        try:
            app = self._get_app()
            with app.app_context():
                from app.extensions import db
                from app.models.threat import ThreatScore, SeverityLevel
                from app.models.attack import AttackEvent
                from app.scoring.severity_classifier import SeverityLevel as SevClass

                # Get all non-zero scores for active attacks
                active_scores = (
                    db.session.query(ThreatScore)
                    .join(AttackEvent)
                    .filter(
                        AttackEvent.status == "active",
                        ThreatScore.final_score > 0,
                    )
                    .all()
                )

                now = datetime.now(timezone.utc)

                for ts in active_scores:
                    try:
                        hours_elapsed = (
                            now - ts.calculated_at
                        ).total_seconds() / 3600.0

                        if hours_elapsed < 0.5:
                            continue  # Skip if scored less than 30 min ago

                        decayed = int(ts.final_score * (0.9 ** hours_elapsed))
                        decayed = max(0, decayed)

                        if decayed == ts.final_score:
                            continue

                        old_score = ts.final_score
                        ts.final_score = decayed
                        ts.severity = SeverityLevel(
                            SevClass.classify(decayed)
                        )

                        results["decayed"] += 1

                        # Transition attack if score drops below 25
                        if decayed < self.MEDIUM_THRESHOLD:
                            attack = ts.attack_event
                            if attack and attack.status == "active":
                                attack.status = "monitoring"
                                results["transitioned"] += 1
                                logger.info(
                                    "Attack %s transitioned to MONITORING "
                                    "(score decayed %d → %d)",
                                    attack.id, old_score, decayed,
                                )

                    except Exception as exc:
                        results["errors"] += 1
                        logger.error("Score decay error for %s: %s", ts.id, exc)

                db.session.commit()

        except Exception as exc:
            results["errors"] += 1
            logger.error("Score decay job failed: %s", exc)

        if results["decayed"] > 0:
            logger.info(
                "Score decay: %d decayed, %d transitioned to monitoring",
                results["decayed"], results["transitioned"],
            )

        return results

    def _get_app(self):
        """Get Flask app instance."""
        if self.app is not None:
            return self.app
        from flask import current_app
        return current_app._get_current_object()

    @property
    def stats(self) -> dict:
        """Return response engine statistics."""
        return {**self._stats}
