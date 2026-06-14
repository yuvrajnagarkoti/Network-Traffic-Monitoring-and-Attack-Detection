"""
Alert priority queue.

Dispatches scored alerts using a min-heap priority queue so
that CRITICAL threats are always processed before lower-severity
events, regardless of arrival order.
"""

import logging
import queue
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


@dataclass(order=True)
class PrioritizedAlert:
    """Alert wrapper for priority queue ordering.

    Priority = 100 - threat_score, so the highest score
    (most dangerous) gets the lowest priority number and
    is dequeued first by Python's min-heap.
    """

    priority: int
    sequence: int = field(compare=True)
    alert_data: dict = field(compare=False)


class AlertPriorityQueue:
    """Thread-safe priority dispatcher for scored threat alerts.

    Usage::

        apq = AlertPriorityQueue()
        apq.register_handler(my_handler_fn)
        apq.enqueue(score_breakdown)
        apq.start()
    """

    def __init__(self, maxsize: int = 10000) -> None:
        self._queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=maxsize)
        self._handlers: list[Callable] = []
        self._sequence: int = 0
        self._lock = threading.Lock()
        self._worker: Optional[threading.Thread] = None
        self._running = False
        self._stats = {
            "enqueued": 0,
            "dispatched": 0,
            "dropped": 0,
            "errors": 0,
        }

    def register_handler(self, handler: Callable[[dict], None]) -> None:
        """Register a callback invoked for each dequeued alert.

        Args:
            handler: Callable accepting a score breakdown dict.
        """
        self._handlers.append(handler)
        logger.info("Registered alert handler: %s", handler.__name__)

    def enqueue(self, score_breakdown: dict) -> bool:
        """Add a scored alert to the priority queue.

        Args:
            score_breakdown: Threat score breakdown from ThreatScorer.

        Returns:
            True if enqueued, False if queue is full.
        """
        final_score = score_breakdown.get("final_score", 0)
        priority = 100 - final_score  # lower number = higher priority

        with self._lock:
            self._sequence += 1
            seq = self._sequence

        item = PrioritizedAlert(
            priority=priority,
            sequence=seq,
            alert_data=score_breakdown,
        )

        try:
            self._queue.put_nowait(item)
            self._stats["enqueued"] += 1
            logger.debug(
                "Enqueued alert priority=%d score=%d",
                priority, final_score,
            )
            return True
        except queue.Full:
            self._stats["dropped"] += 1
            logger.warning(
                "Alert queue full — dropped alert with score %d",
                final_score,
            )
            return False

    def start(self) -> None:
        """Start the background dispatch worker thread."""
        if self._running:
            return

        self._running = True
        self._worker = threading.Thread(
            target=self._dispatch_loop,
            name="alert-priority-dispatcher",
            daemon=True,
        )
        self._worker.start()
        logger.info("Alert priority dispatcher started")

    def stop(self) -> None:
        """Stop the dispatch worker."""
        self._running = False
        # Unblock the worker with a sentinel
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass

        if self._worker and self._worker.is_alive():
            self._worker.join(timeout=5)
        logger.info("Alert priority dispatcher stopped")

    def _dispatch_loop(self) -> None:
        """Worker loop that dequeues and dispatches alerts."""
        while self._running:
            try:
                item = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            # Sentinel check for shutdown
            if item is None:
                break

            if not isinstance(item, PrioritizedAlert):
                continue

            self._dispatch(item.alert_data)
            self._queue.task_done()

    def _dispatch(self, alert_data: dict) -> None:
        """Send alert data to all registered handlers."""
        for handler in self._handlers:
            try:
                handler(alert_data)
                self._stats["dispatched"] += 1
            except Exception as exc:
                self._stats["errors"] += 1
                logger.error(
                    "Alert handler %s failed: %s",
                    handler.__name__, exc,
                )

    @property
    def pending(self) -> int:
        """Number of alerts waiting in the queue."""
        return self._queue.qsize()

    @property
    def stats(self) -> dict:
        """Return queue statistics."""
        return {**self._stats, "pending": self.pending}
