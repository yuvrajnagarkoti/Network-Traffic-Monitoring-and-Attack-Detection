"""
Alert lifecycle manager.

CRUD operations for alerts with status transitions,
analyst assignment, commenting, and bulk operations.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.extensions import db
from app.models.alert import Alert, AlertComment, AlertStatus, AlertSeverity

logger = logging.getLogger(__name__)

# Valid status transitions
_VALID_TRANSITIONS = {
    AlertStatus.NEW: {AlertStatus.ACKNOWLEDGED, AlertStatus.FALSE_POSITIVE},
    AlertStatus.ACKNOWLEDGED: {AlertStatus.INVESTIGATING, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE},
    AlertStatus.INVESTIGATING: {AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE},
    AlertStatus.RESOLVED: {AlertStatus.INVESTIGATING},  # reopen
    AlertStatus.FALSE_POSITIVE: set(),  # terminal
}


class AlertManager:
    """Manages alert lifecycle, querying, and analyst operations."""

    def __init__(self, app=None) -> None:
        self.app = app

    def get_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        attack_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        assigned_to: Optional[str] = None,
        hours: int = 24,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """Query alerts with filters.

        Returns:
            Dict with alerts list, total count, and pagination info.
        """
        query = Alert.query

        if severity:
            try:
                sev_enum = AlertSeverity(severity.lower())
                query = query.filter(Alert.severity == sev_enum)
            except ValueError:
                pass

        if status:
            try:
                status_enum = AlertStatus(status.lower())
                query = query.filter(Alert.status == status_enum)
            except ValueError:
                pass

        if source_ip:
            from app.models.attack import AttackEvent
            query = query.join(AttackEvent).filter(
                AttackEvent.source_ip == source_ip
            )

        if assigned_to:
            query = query.filter(Alert.assigned_to == assigned_to)

        if hours:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            query = query.filter(Alert.created_at >= cutoff)

        total = query.count()
        alerts = (
            query.order_by(Alert.created_at.desc())
            .offset(offset)
            .limit(min(limit, 200))
            .all()
        )

        return {
            "alerts": [a.to_dict() for a in alerts],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def get_alert(self, alert_id: str) -> Optional[dict]:
        """Get single alert with comments."""
        alert = db.session.get(Alert, alert_id)
        if not alert:
            return None

        result = alert.to_dict()
        result["comments"] = [
            c.to_dict() for c in alert.comments.order_by(
                AlertComment.created_at.asc()
            ).all()
        ]
        return result

    def update_status(
        self,
        alert_id: str,
        new_status: str,
        user_id: Optional[str] = None,
    ) -> dict:
        """Update alert status with lifecycle validation.

        Returns:
            Result dict with success/error info.
        """
        alert = db.session.get(Alert, alert_id)
        if not alert:
            return {"error": "Alert not found", "status_code": 404}

        try:
            new_status_enum = AlertStatus(new_status.lower())
        except ValueError:
            return {"error": f"Invalid status: {new_status}", "status_code": 400}

        current = alert.status if isinstance(alert.status, AlertStatus) else AlertStatus(alert.status)
        valid_next = _VALID_TRANSITIONS.get(current, set())

        if new_status_enum not in valid_next:
            return {
                "error": f"Cannot transition from {current.value} to {new_status_enum.value}",
                "status_code": 400,
            }

        old_status = current.value
        alert.status = new_status_enum

        if new_status_enum == AlertStatus.ACKNOWLEDGED:
            alert.acknowledged_at = datetime.now(timezone.utc)
        elif new_status_enum in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
            alert.resolved_at = datetime.now(timezone.utc)

        db.session.commit()

        logger.info(
            "Alert %s status: %s → %s (by user %s)",
            alert_id, old_status, new_status_enum.value, user_id,
        )

        return {
            "id": str(alert.id),
            "old_status": old_status,
            "new_status": new_status_enum.value,
            "status_code": 200,
        }

    def assign_alert(
        self, alert_id: str, analyst_id: str
    ) -> dict:
        """Assign alert to an analyst."""
        alert = db.session.get(Alert, alert_id)
        if not alert:
            return {"error": "Alert not found", "status_code": 404}

        alert.assigned_to = analyst_id
        db.session.commit()

        return {"id": str(alert.id), "assigned_to": analyst_id, "status_code": 200}

    def add_comment(
        self,
        alert_id: str,
        user_id: str,
        comment_text: str,
    ) -> dict:
        """Add analyst comment to an alert."""
        alert = db.session.get(Alert, alert_id)
        if not alert:
            return {"error": "Alert not found", "status_code": 404}

        comment = AlertComment(
            alert_id=alert_id,
            user_id=user_id,
            comment=comment_text,
        )

        db.session.add(comment)
        db.session.commit()

        return {"comment": comment.to_dict(), "status_code": 201}

    def bulk_acknowledge(
        self,
        severity: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> dict:
        """Bulk acknowledge all NEW alerts of a given severity."""
        query = Alert.query.filter(Alert.status == AlertStatus.NEW)

        if severity:
            try:
                sev_enum = AlertSeverity(severity.lower())
                query = query.filter(Alert.severity == sev_enum)
            except ValueError:
                pass

        now = datetime.now(timezone.utc)
        count = query.update(
            {
                Alert.status: AlertStatus.ACKNOWLEDGED,
                Alert.acknowledged_at: now,
            },
            synchronize_session="fetch",
        )
        db.session.commit()

        logger.info(
            "Bulk acknowledged %d alerts (severity=%s, by=%s)",
            count, severity, user_id,
        )

        return {"acknowledged_count": count, "status_code": 200}

    def get_statistics(self, hours: int = 24) -> dict:
        """Alert statistics: counts, MTTA, MTTR."""
        from sqlalchemy import func

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Counts by status
        status_counts = dict(
            db.session.query(Alert.status, func.count(Alert.id))
            .filter(Alert.created_at >= cutoff)
            .group_by(Alert.status)
            .all()
        )

        # Counts by severity
        severity_counts = dict(
            db.session.query(Alert.severity, func.count(Alert.id))
            .filter(Alert.created_at >= cutoff)
            .group_by(Alert.severity)
            .all()
        )

        # Mean Time to Acknowledge
        mtta_result = (
            db.session.query(
                func.avg(
                    func.extract("epoch", Alert.acknowledged_at - Alert.created_at)
                )
            )
            .filter(
                Alert.acknowledged_at.isnot(None),
                Alert.created_at >= cutoff,
            )
            .scalar()
        )

        # Mean Time to Resolve
        mttr_result = (
            db.session.query(
                func.avg(
                    func.extract("epoch", Alert.resolved_at - Alert.created_at)
                )
            )
            .filter(
                Alert.resolved_at.isnot(None),
                Alert.created_at >= cutoff,
            )
            .scalar()
        )

        return {
            "time_window_hours": hours,
            "by_status": {
                (s.value if hasattr(s, "value") else str(s)): c
                for s, c in status_counts.items()
            },
            "by_severity": {
                (s.value if hasattr(s, "value") else str(s)): c
                for s, c in severity_counts.items()
            },
            "mtta_seconds": round(float(mtta_result), 1) if mtta_result else None,
            "mttr_seconds": round(float(mttr_result), 1) if mttr_result else None,
            "total": sum(status_counts.values()),
        }

    def expire_low_alerts(self, max_age_hours: int = 24) -> int:
        """Auto-expire LOW alerts older than max_age_hours.

        Returns:
            Number of alerts expired.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

        count = (
            Alert.query.filter(
                Alert.severity == AlertSeverity.LOW,
                Alert.status == AlertStatus.NEW,
                Alert.created_at < cutoff,
            )
            .update(
                {Alert.status: AlertStatus.RESOLVED, Alert.resolved_at: datetime.now(timezone.utc)},
                synchronize_session="fetch",
            )
        )
        db.session.commit()

        if count > 0:
            logger.info("Auto-expired %d LOW alerts older than %dh", count, max_age_hours)

        return count
