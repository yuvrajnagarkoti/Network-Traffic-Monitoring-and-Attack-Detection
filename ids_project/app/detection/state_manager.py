"""
Attack state manager.

Maintains an in-memory table of active attacks. Attacks are
created on first detection, updated on subsequent evidence,
and resolved after 5 minutes of inactivity. Resolved attacks
are persisted to the attack_events table.
"""

import logging
import threading
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class AttackState:
    """Represents a currently active attack being tracked.

    Accumulates evidence from multiple detection cycles until
    the attack resolves (no new evidence for resolve_timeout).
    """

    __slots__ = [
        "attack_id", "attack_type", "source_ip", "target_ip", "target_port",
        "first_seen", "last_seen", "confidence", "packet_count",
        "evidence_list", "contributing_detectors", "status",
    ]

    def __init__(
        self,
        attack_type: str,
        source_ip: str,
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
    ) -> None:
        self.attack_id = str(uuid.uuid4())
        self.attack_type = attack_type
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.target_port = target_port
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.confidence = 0.0
        self.packet_count = 0
        self.evidence_list: list[dict] = []
        self.contributing_detectors: set[str] = set()
        self.status = "active"

    def update(self, indicator) -> None:
        """Update attack state with new detection evidence.

        Args:
            indicator: AttackIndicator from a detector.
        """
        self.last_seen = time.time()
        self.confidence = max(self.confidence, indicator.confidence)
        self.packet_count += indicator.packet_count

        if indicator.target_ip and not self.target_ip:
            self.target_ip = indicator.target_ip
        if indicator.target_port and not self.target_port:
            self.target_port = indicator.target_port

        # Keep last 50 evidence entries to bound memory
        if len(self.evidence_list) < 50:
            self.evidence_list.append(indicator.evidence)

        self.contributing_detectors.add(indicator.detector_name)

    @property
    def duration_seconds(self) -> int:
        """Duration from first_seen to last_seen."""
        return int(self.last_seen - self.first_seen)

    def is_expired(self, timeout: int) -> bool:
        """Check if attack has been inactive for timeout seconds."""
        return (time.time() - self.last_seen) > timeout

    def to_dict(self) -> dict:
        """Serialize active attack state."""
        return {
            "attack_id": self.attack_id,
            "attack_type": self.attack_type,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "confidence": self.confidence,
            "packet_count": self.packet_count,
            "duration_seconds": self.duration_seconds,
            "first_seen": datetime.fromtimestamp(
                self.first_seen, tz=timezone.utc
            ).isoformat(),
            "last_seen": datetime.fromtimestamp(
                self.last_seen, tz=timezone.utc
            ).isoformat(),
            "evidence_count": len(self.evidence_list),
            "detectors": list(self.contributing_detectors),
            "status": self.status,
        }


class AttackStateManager:
    """Manages the lifecycle of active attack tracking.

    Active attacks are stored in memory keyed by (attack_type, src_ip).
    Resolved attacks (no new evidence for resolve_timeout) are
    persisted to the database and removed from memory.
    """

    def __init__(
        self,
        app=None,
        resolve_timeout: int = 300,
        max_tracked: int = 10000,
    ) -> None:
        """Initialize state manager.

        Args:
            app: Flask application instance.
            resolve_timeout: Seconds of inactivity before resolving.
            max_tracked: Maximum tracked attacks (memory bound).
        """
        self.app = app
        self.resolve_timeout = resolve_timeout
        self.max_tracked = max_tracked

        self._active: OrderedDict[tuple, AttackState] = OrderedDict()
        self._lock = threading.RLock()

        self._total_created: int = 0
        self._total_resolved: int = 0
        self._running = False
        self._resolver_thread: Optional[threading.Thread] = None

    def update_or_create(self, indicator) -> AttackState:
        """Update an existing attack or create a new one.

        Deduplicates by (attack_type, source_ip) — if an active
        attack exists for the same type+IP within the resolve
        window, it is updated rather than creating a new record.

        Args:
            indicator: AttackIndicator from a detector.

        Returns:
            The updated or newly created AttackState.
        """
        key = (indicator.attack_type, indicator.source_ip)

        with self._lock:
            if key in self._active:
                state = self._active[key]
                state.update(indicator)
                # Move to end (LRU ordering)
                self._active.move_to_end(key)
                return state

            # Enforce capacity limit
            if len(self._active) >= self.max_tracked:
                self._evict_oldest()

            state = AttackState(
                attack_type=indicator.attack_type,
                source_ip=indicator.source_ip,
                target_ip=indicator.target_ip,
                target_port=indicator.target_port,
            )
            state.update(indicator)
            self._active[key] = state
            self._total_created += 1

            logger.info(
                "New attack detected: %s from %s (confidence=%.2f)",
                indicator.attack_type,
                indicator.source_ip,
                indicator.confidence,
            )
            return state

    def _evict_oldest(self) -> None:
        """Evict the oldest active attack (LRU)."""
        if self._active:
            key, state = self._active.popitem(last=False)
            self._persist_resolved(state)
            self._total_resolved += 1

    def get_active_attacks(self) -> list[dict]:
        """Get all active attacks as dictionaries."""
        with self._lock:
            return [state.to_dict() for state in self._active.values()]

    def get_attack(self, attack_type: str, source_ip: str) -> Optional[dict]:
        """Get a specific active attack by type and source IP."""
        with self._lock:
            key = (attack_type, source_ip)
            state = self._active.get(key)
            return state.to_dict() if state else None

    def resolve_expired(self) -> list[AttackState]:
        """Resolve all attacks that have been inactive for resolve_timeout.

        Returns:
            List of resolved AttackState objects.
        """
        resolved = []
        with self._lock:
            expired_keys = [
                key for key, state in self._active.items()
                if state.is_expired(self.resolve_timeout)
            ]
            for key in expired_keys:
                state = self._active.pop(key)
                state.status = "resolved"
                resolved.append(state)
                self._total_resolved += 1

        # Persist outside lock
        for state in resolved:
            self._persist_resolved(state)

        if resolved:
            logger.info("Resolved %d expired attacks", len(resolved))

        return resolved

    def _persist_resolved(self, state: AttackState) -> None:
        """Persist a resolved attack to the attack_events table.

        Args:
            state: Resolved AttackState to persist.
        """
        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.attack import AttackEvent, AttackStatus

                event = AttackEvent(
                    attack_type=state.attack_type,
                    source_ip=state.source_ip,
                    target_ip=state.target_ip,
                    target_port=state.target_port,
                    evidence={
                        "entries": state.evidence_list[-10:],
                        "detectors": list(state.contributing_detectors),
                    },
                    confidence_score=state.confidence,
                    packet_count=state.packet_count,
                    duration_seconds=state.duration_seconds,
                    first_seen=datetime.fromtimestamp(
                        state.first_seen, tz=timezone.utc
                    ),
                    last_seen=datetime.fromtimestamp(
                        state.last_seen, tz=timezone.utc
                    ),
                    status=AttackStatus.RESOLVED,
                )
                db.session.add(event)
                db.session.commit()

                logger.debug(
                    "Persisted resolved attack: %s from %s",
                    state.attack_type,
                    state.source_ip,
                )

        except Exception as exc:
            logger.error("Failed to persist attack: %s", exc)

    def start_resolver(self, interval: float = 30.0) -> None:
        """Start background thread that periodically resolves expired attacks.

        Args:
            interval: Seconds between resolver runs.
        """
        self._running = True
        self._resolver_thread = threading.Thread(
            target=self._resolver_loop,
            args=(interval,),
            daemon=True,
            name="attack-resolver",
        )
        self._resolver_thread.start()
        logger.info("Attack resolver started (interval=%.0fs)", interval)

    def _resolver_loop(self, interval: float) -> None:
        """Background loop that resolves expired attacks."""
        while self._running:
            try:
                self.resolve_expired()
            except Exception as exc:
                logger.error("Resolver error: %s", exc)
            time.sleep(interval)

    def stop_resolver(self) -> None:
        """Stop the resolver background thread."""
        self._running = False
        if self._resolver_thread and self._resolver_thread.is_alive():
            self._resolver_thread.join(timeout=5)

    @property
    def active_count(self) -> int:
        """Number of currently active attacks."""
        return len(self._active)

    @property
    def stats(self) -> dict:
        """Return state manager statistics."""
        return {
            "active_attacks": self.active_count,
            "total_created": self._total_created,
            "total_resolved": self._total_resolved,
            "max_tracked": self.max_tracked,
            "resolve_timeout": self.resolve_timeout,
        }
