"""
Real-time alert broadcaster.

Emits SocketIO events to connected dashboard clients whenever a new
alert is created or an existing alert changes status.

Namespace: /alerts
Events emitted:
  - new_alert       : {alert dict}
  - alert_updated   : {alert dict}
  - alert_stats     : {counts by severity/status}
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class AlertStreamer:
    """Broadcasts alert events over WebSocket using Flask-SocketIO."""

    NAMESPACE = "/alerts"

    def __init__(self, socketio=None) -> None:
        self._socketio = socketio

    def set_socketio(self, socketio) -> None:
        """Inject SocketIO instance after app creation."""
        self._socketio = socketio

    # ------------------------------------------------------------------
    # Public emit helpers
    # ------------------------------------------------------------------

    def emit_new_alert(self, alert_dict: dict) -> None:
        """Broadcast a newly created alert to all connected clients."""
        if not self._socketio:
            return
        try:
            self._socketio.emit(
                "new_alert",
                self._enrich(alert_dict),
                namespace=self.NAMESPACE,
            )
            logger.debug("Streamed new_alert id=%s", alert_dict.get("id"))
        except Exception as exc:
            logger.error("Failed to emit new_alert: %s", exc)

    def emit_alert_updated(self, alert_dict: dict) -> None:
        """Broadcast an alert status/assignment change."""
        if not self._socketio:
            return
        try:
            self._socketio.emit(
                "alert_updated",
                self._enrich(alert_dict),
                namespace=self.NAMESPACE,
            )
            logger.debug("Streamed alert_updated id=%s", alert_dict.get("id"))
        except Exception as exc:
            logger.error("Failed to emit alert_updated: %s", exc)

    def emit_stats(self, stats: dict) -> None:
        """Broadcast aggregate alert statistics (counts, MTTA/MTTR)."""
        if not self._socketio:
            return
        try:
            self._socketio.emit(
                "alert_stats",
                stats,
                namespace=self.NAMESPACE,
            )
        except Exception as exc:
            logger.error("Failed to emit alert_stats: %s", exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _enrich(self, alert_dict: dict) -> dict:
        """Add server timestamp to outgoing payload."""
        enriched = dict(alert_dict)
        enriched["server_ts"] = datetime.now(timezone.utc).isoformat()
        return enriched
