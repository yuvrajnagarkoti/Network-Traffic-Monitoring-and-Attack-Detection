"""
WebSocket event emitter for real-time packet monitoring.

Emits packet events and traffic statistics updates to connected
dashboard clients via Flask-SocketIO.
"""

import logging
import threading
import time
from typing import Optional

from flask_socketio import Namespace, emit

logger = logging.getLogger(__name__)

# Emit every Nth packet to avoid overwhelming the browser
PACKET_EMIT_INTERVAL = 10

# Traffic stats update interval in seconds
STATS_EMIT_INTERVAL = 5


class PacketNamespace(Namespace):
    """WebSocket namespace for packet monitoring events.

    Handles client connections to /packets and emits:
        - packet_event: every 10th captured packet
        - traffic_stats_update: every 5 seconds
    """

    def on_connect(self):
        """Handle new WebSocket connection."""
        logger.info("Client connected to /packets namespace")
        emit("connected", {"message": "Connected to packet feed"})

    def on_disconnect(self):
        """Handle WebSocket disconnection."""
        logger.info("Client disconnected from /packets namespace")


class PacketEventEmitter:
    """Emits packet events and stats updates via WebSocket.

    Manages emission rate to prevent client overload:
        - Packets: every 10th packet
        - Stats: every 5 seconds
    """

    def __init__(self, socketio=None) -> None:
        """Initialize the event emitter.

        Args:
            socketio: Flask-SocketIO instance.
        """
        self.socketio = socketio
        self._packet_counter: int = 0
        self._running = False
        self._stats_thread: Optional[threading.Thread] = None
        self._stats_getter = None

    def set_stats_source(self, stats_getter) -> None:
        """Set the function that provides current traffic stats.

        Args:
            stats_getter: Callable that returns stats dictionary.
        """
        self._stats_getter = stats_getter

    def emit_packet(self, parsed_packet: dict) -> None:
        """Emit a packet event to connected clients.

        Only emits every PACKET_EMIT_INTERVAL-th packet to prevent
        client browser from being overwhelmed.

        Args:
            parsed_packet: Parsed packet dictionary.
        """
        if self.socketio is None:
            return

        self._packet_counter += 1
        if self._packet_counter % PACKET_EMIT_INTERVAL != 0:
            return

        # Build lightweight event payload (exclude large fields)
        event_data = {
            "src_ip": parsed_packet.get("src_ip"),
            "dst_ip": parsed_packet.get("dst_ip"),
            "src_port": parsed_packet.get("src_port"),
            "dst_port": parsed_packet.get("dst_port"),
            "protocol": parsed_packet.get("protocol"),
            "packet_size": parsed_packet.get("packet_size"),
            "flags": parsed_packet.get("flags"),
            "captured_at": (
                parsed_packet["captured_at"].isoformat()
                if parsed_packet.get("captured_at")
                else None
            ),
        }

        try:
            self.socketio.emit(
                "packet_event",
                event_data,
                namespace="/packets",
            )
        except Exception as exc:
            logger.debug("Failed to emit packet event: %s", exc)

    def start_stats_emitter(self) -> None:
        """Start background thread that emits traffic stats periodically."""
        if self._running:
            return

        self._running = True
        self._stats_thread = threading.Thread(
            target=self._stats_emit_loop,
            daemon=True,
            name="stats-emitter",
        )
        self._stats_thread.start()
        logger.info("Stats emitter started (interval=%ds)", STATS_EMIT_INTERVAL)

    def stop_stats_emitter(self) -> None:
        """Stop the stats emitter thread."""
        self._running = False
        if self._stats_thread and self._stats_thread.is_alive():
            self._stats_thread.join(timeout=5)

    def _stats_emit_loop(self) -> None:
        """Background loop emitting traffic stats every N seconds."""
        while self._running:
            time.sleep(STATS_EMIT_INTERVAL)
            try:
                if self.socketio and self._stats_getter:
                    stats = self._stats_getter()
                    self.socketio.emit(
                        "traffic_stats_update",
                        stats,
                        namespace="/packets",
                    )
            except Exception as exc:
                logger.debug("Failed to emit stats update: %s", exc)

    @property
    def stats(self) -> dict:
        """Return emitter statistics."""
        return {
            "total_packets_emitted": self._packet_counter // PACKET_EMIT_INTERVAL,
            "emit_interval": PACKET_EMIT_INTERVAL,
            "stats_interval": STATS_EMIT_INTERVAL,
            "is_running": self._running,
        }
