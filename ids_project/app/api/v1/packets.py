"""
Packet monitoring REST API endpoints.

Provides live traffic data, protocol distribution, top talkers,
capture status, and capture control endpoints.
"""

import logging
import queue
import threading
from datetime import datetime, timezone
from typing import Optional

from flask import Blueprint, jsonify, request, current_app

from app.capture.parser import PacketParser
from app.capture.sniffer import PacketCapture
from app.capture.flow_tracker import FlowTracker
from app.capture.batch_writer import BatchWriter
from app.capture.stats_aggregator import StatsAggregator
from app.capture.events import PacketEventEmitter, PacketNamespace

logger = logging.getLogger(__name__)

packets_bp = Blueprint("packets", __name__)

# ============================================
# Module-level capture engine state
# ============================================
# These are initialized via init_capture_engine()
# and accessed by the API endpoints.

_capture: Optional[PacketCapture] = None
_parser: Optional[PacketParser] = None
_flow_tracker: Optional[FlowTracker] = None
_batch_writer: Optional[BatchWriter] = None
_stats_aggregator: Optional[StatsAggregator] = None
_event_emitter: Optional[PacketEventEmitter] = None
_processing_workers: list[threading.Thread] = []
_processing_running: bool = False


def init_capture_engine(app, socketio) -> None:
    """Initialize the complete packet capture pipeline.

    Called once during application startup. Creates and wires
    all capture components together.

    Args:
        app: Flask application instance.
        socketio: Flask-SocketIO instance.
    """
    global _capture, _parser, _flow_tracker, _batch_writer
    global _stats_aggregator, _event_emitter

    sim_mode = not _is_linux() or app.config.get("CAPTURE_SIMULATION", True)
    interface = app.config.get("CAPTURE_INTERFACE", "eth0")
    bpf_filter = app.config.get("CAPTURE_BPF_FILTER", "ip")
    queue_size = app.config.get("PACKET_QUEUE_SIZE", 10000)
    sim_pps = app.config.get("SIMULATION_PPS", 100)

    _capture = PacketCapture(
        interface=interface,
        bpf_filter=bpf_filter,
        queue_size=queue_size,
        simulation_mode=sim_mode,
        simulation_pps=sim_pps,
    )

    _parser = PacketParser(dedup_window_size=1000)
    _flow_tracker = FlowTracker()
    _batch_writer = BatchWriter(
        app=app,
        batch_size=app.config.get("BATCH_INSERT_SIZE", 500),
        flush_interval_ms=app.config.get("BATCH_FLUSH_INTERVAL_MS", 500),
    )
    _stats_aggregator = StatsAggregator(app=app, interval=60)

    _event_emitter = PacketEventEmitter(socketio=socketio)
    _event_emitter.set_stats_source(_stats_aggregator.get_current_stats)

    # Register WebSocket namespace
    socketio.on_namespace(PacketNamespace("/packets"))

    logger.info(
        "Capture engine initialized (simulation=%s, interface=%s)",
        sim_mode,
        interface,
    )


def start_capture_engine() -> dict:
    """Start all capture pipeline components.

    Returns:
        Status dictionary with component states.
    """
    global _processing_running

    if _capture is None:
        return {"error": "Capture engine not initialized"}

    if _capture.is_running:
        return {"status": "already_running", "message": "Capture is already active"}

    # Start components in dependency order
    _capture.start()
    _batch_writer.start()
    _stats_aggregator.start()
    _flow_tracker.start_reaper(interval=10.0)
    _event_emitter.start_stats_emitter()

    # Start processing worker pool
    _processing_running = True
    _start_processing_workers(num_workers=4)

    logger.info("Capture engine started — all components active")
    return {
        "status": "started",
        "simulation_mode": _capture.simulation_mode,
        "interface": _capture.interface,
    }


def stop_capture_engine() -> dict:
    """Stop all capture pipeline components gracefully.

    Returns:
        Status dictionary with final statistics.
    """
    global _processing_running

    if _capture is None or not _capture.is_running:
        return {"status": "not_running", "message": "Capture is not active"}

    _processing_running = False

    # Stop in reverse dependency order
    _event_emitter.stop_stats_emitter()
    _capture.stop()
    _flow_tracker.stop_reaper()

    # Wait for processing workers to drain
    for worker in _processing_workers:
        if worker.is_alive():
            worker.join(timeout=5)

    _stats_aggregator.stop()
    _batch_writer.stop()

    logger.info("Capture engine stopped")
    return {
        "status": "stopped",
        "capture_stats": _capture.stats,
        "writer_stats": _batch_writer.stats,
    }


def _start_processing_workers(num_workers: int = 4) -> None:
    """Start the packet processing worker pool.

    Each worker dequeues packets, parses them, updates flows,
    records stats, emits events, and pushes to batch writer.

    Args:
        num_workers: Number of processing threads.
    """
    global _processing_workers
    _processing_workers = []

    for i in range(num_workers):
        worker = threading.Thread(
            target=_processing_worker_loop,
            args=(i,),
            daemon=True,
            name=f"packet-worker-{i}",
        )
        worker.start()
        _processing_workers.append(worker)

    logger.info("Started %d processing workers", num_workers)


def _processing_worker_loop(worker_id: int) -> None:
    """Main loop for a packet processing worker.

    Dequeues raw packets from the capture queue, parses them,
    and feeds them through the processing pipeline.

    Args:
        worker_id: Worker identifier for logging.
    """
    while _processing_running:
        try:
            # Block for up to 100ms waiting for a packet
            raw_packet = _capture.packet_queue.get(timeout=0.1)
        except queue.Empty:
            continue
        except Exception:
            continue

        try:
            # Parse the packet
            parsed = _parser.parse(raw_packet)
            if parsed is None:
                continue

            # Update flow tracker
            _flow_tracker.update(parsed)

            # Record statistics
            _stats_aggregator.record_packet(parsed)

            # Emit WebSocket event (throttled)
            _event_emitter.emit_packet(parsed)

            # Queue for batch database insert
            _batch_writer.add_packet(parsed)

        except Exception as exc:
            logger.debug("Worker %d processing error: %s", worker_id, exc)


def _is_linux() -> bool:
    """Check if running on Linux."""
    import platform
    return platform.system() == "Linux"


# ============================================
# REST API Endpoints
# ============================================

@packets_bp.route("/api/v1/packets/live", methods=["GET"])
def get_live_packets():
    """Return the last 60 seconds of packet statistics.

    Returns traffic summary including packet counts, byte counts,
    and protocol distribution for the most recent window.
    """
    if _stats_aggregator is None:
        return jsonify({"error": "Capture engine not initialized"}), 503

    stats = _stats_aggregator.get_current_stats()
    return jsonify(stats), 200


@packets_bp.route("/api/v1/packets/protocols", methods=["GET"])
def get_protocol_distribution():
    """Return protocol distribution for the latest aggregation window.

    Query params:
        - limit: Max protocols to return (default: 20)
    """
    if _stats_aggregator is None:
        return jsonify({"error": "Capture engine not initialized"}), 503

    limit = request.args.get("limit", 20, type=int)
    protocols = _stats_aggregator.get_protocol_distribution()[:limit]

    return jsonify({
        "protocols": protocols,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), 200


@packets_bp.route("/api/v1/packets/top-talkers", methods=["GET"])
def get_top_talkers():
    """Return top 10 source IPs by packet count.

    Query params:
        - limit: Max IPs to return (default: 10)
    """
    if _stats_aggregator is None:
        return jsonify({"error": "Capture engine not initialized"}), 503

    limit = request.args.get("limit", 10, type=int)
    talkers = _stats_aggregator.get_top_talkers()[:limit]

    return jsonify({
        "top_talkers": talkers,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), 200


@packets_bp.route("/api/v1/packets/stats", methods=["GET"])
def get_packet_stats():
    """Return current packets/second, bytes/second, and queue depth.

    Combines metrics from the capture engine, parser, flow tracker,
    batch writer, and stats aggregator.
    """
    result = {
        "capture": _capture.stats if _capture else {},
        "parser": _parser.stats if _parser else {},
        "flow_tracker": _flow_tracker.stats if _flow_tracker else {},
        "batch_writer": _batch_writer.stats if _batch_writer else {},
        "aggregator": _stats_aggregator.stats if _stats_aggregator else {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return jsonify(result), 200


@packets_bp.route("/api/v1/capture/status", methods=["GET"])
def get_capture_status():
    """Return current capture engine status.

    Includes: is_running, interface, packets captured/dropped,
    queue depth, and uptime.
    """
    if _capture is None:
        return jsonify({
            "is_running": False,
            "message": "Capture engine not initialized",
        }), 200

    return jsonify(_capture.stats), 200


@packets_bp.route("/api/v1/capture/start", methods=["POST"])
def start_capture():
    """Start the packet capture engine.

    Admin-only endpoint. Starts capture on the configured
    interface or in simulation mode.

    TODO: Add @require_permission('MANAGE_SYSTEM_CONFIG') in Phase 9
    """
    result = start_capture_engine()
    status_code = 200 if result.get("status") != "error" else 500
    return jsonify(result), status_code


@packets_bp.route("/api/v1/capture/stop", methods=["POST"])
def stop_capture():
    """Stop the packet capture engine gracefully.

    Admin-only endpoint. Drains remaining packets before stopping.

    TODO: Add @require_permission('MANAGE_SYSTEM_CONFIG') in Phase 9
    """
    result = stop_capture_engine()
    return jsonify(result), 200
