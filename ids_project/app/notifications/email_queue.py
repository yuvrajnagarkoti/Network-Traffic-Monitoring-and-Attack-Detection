"""
Email notification queue worker.

Polls the email_notifications table for PENDING records and dispatches
them via EmailSender.  Failed deliveries are retried up to 3 times
using exponential back-off delays (5 min, 25 min, 2 h).

After MAX_RETRIES failures the record is marked PERMANENTLY_FAILED and
no further attempts are made.

Rate limiting: enforces a maximum of 10 emails per hour per recipient
to prevent mailbox flooding.
"""

import logging
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_RETRY_DELAYS = [
    timedelta(minutes=5),
    timedelta(minutes=25),
    timedelta(hours=2),
]
_RATE_LIMIT = 10          # max emails per hour per recipient
_POLL_INTERVAL = 60       # seconds between poll cycles


class EmailQueueWorker:
    """Background worker that drains the email_notifications queue.

    Usage::

        worker = EmailQueueWorker(app=app, sender=email_sender)
        worker.start()
    """

    def __init__(self, app=None, sender=None) -> None:
        self.app = app
        self.sender = sender
        self._running = False
        self._thread: Optional[threading.Thread] = None
        # {recipient: [(sent_at, ...), ...]}
        self._rate_tracker: dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the background polling thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run,
            name="email-queue-worker",
            daemon=True,
        )
        self._thread.start()
        logger.info("Email queue worker started (poll=%ds)", _POLL_INTERVAL)

    def stop(self) -> None:
        """Signal the worker to stop after the current cycle."""
        self._running = False

    # ------------------------------------------------------------------
    # Internal worker loop
    # ------------------------------------------------------------------

    def _run(self) -> None:
        """Main loop — polls every _POLL_INTERVAL seconds."""
        import time
        while self._running:
            try:
                self._process_batch()
            except Exception as exc:
                logger.error("Email queue worker error: %s", exc)
            time.sleep(_POLL_INTERVAL)

    def _process_batch(self) -> None:
        """Fetch and attempt delivery for all pending / retry-ready records."""
        _app = self._get_app()
        with _app.app_context():
            from app.extensions import db
            from app.models.alert import EmailNotification, EmailDeliveryStatus

            now = datetime.now(timezone.utc)

            # Pending records or those past their next retry time
            pending = (
                EmailNotification.query
                .filter(
                    EmailNotification.delivery_status.in_([
                        EmailDeliveryStatus.PENDING,
                        EmailDeliveryStatus.FAILED,
                    ]),
                    EmailNotification.retry_count < _MAX_RETRIES,
                )
                .order_by(EmailNotification.created_at.asc())
                .limit(50)
                .all()
            )

            for notif in pending:
                # Skip if not yet past the retry back-off window
                if notif.delivery_status == EmailDeliveryStatus.FAILED:
                    delay = _RETRY_DELAYS[min(notif.retry_count, len(_RETRY_DELAYS) - 1)]
                    next_attempt = (notif.last_retry_at or notif.created_at) + delay
                    if now < next_attempt:
                        continue

                # Enforce per-recipient rate limit
                if not self._check_rate_limit(notif.recipient_email, now):
                    logger.warning(
                        "Rate limit reached for %s, skipping", notif.recipient_email
                    )
                    continue

                success = self.sender.send(
                    recipient=notif.recipient_email,
                    subject=notif.subject,
                    body=notif.body_template,
                )

                notif.last_retry_at = now
                if success:
                    notif.delivery_status = EmailDeliveryStatus.SENT
                    notif.sent_at = now
                    self._record_sent(notif.recipient_email, now)
                    logger.info("Delivered email to %s", notif.recipient_email)
                else:
                    notif.retry_count += 1
                    if notif.retry_count >= _MAX_RETRIES:
                        notif.delivery_status = EmailDeliveryStatus.PERMANENTLY_FAILED
                        logger.error(
                            "Permanently failed email to %s after %d retries",
                            notif.recipient_email, _MAX_RETRIES,
                        )
                    else:
                        notif.delivery_status = EmailDeliveryStatus.FAILED

            db.session.commit()

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _check_rate_limit(self, recipient: str, now: datetime) -> bool:
        """Return True if we are still under the per-hour rate limit."""
        with self._lock:
            window_start = now - timedelta(hours=1)
            self._rate_tracker[recipient] = [
                t for t in self._rate_tracker[recipient] if t > window_start
            ]
            return len(self._rate_tracker[recipient]) < _RATE_LIMIT

    def _record_sent(self, recipient: str, now: datetime) -> None:
        """Record a successful send for rate limit tracking."""
        with self._lock:
            self._rate_tracker[recipient].append(now)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_app(self):
        if self.app is not None:
            return self.app
        from flask import current_app
        return current_app._get_current_object()
