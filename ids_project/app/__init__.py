"""
Application factory for the Network IDS system.

Creates and configures the Flask application with all extensions,
blueprints, and middleware registered.
"""

import os
import logging
from typing import Optional

from flask import Flask

from app.config import config_by_name
from app.extensions import db, migrate, socketio, login_manager, bcrypt, csrf


def create_app(config_name: Optional[str] = None) -> Flask:
    """Create and configure the Flask application.

    Args:
        config_name: Configuration environment name.
                     One of: 'development', 'testing', 'production'.
                     Defaults to FLASK_ENV or 'development'.

    Returns:
        Configured Flask application instance.
    """
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__)
    app.config.from_object(config_by_name.get(config_name, config_by_name["default"]))

    _register_extensions(app)
    _register_blueprints(app)
    _register_error_handlers(app)
    _configure_logging(app)
    _init_capture_engine(app)

    return app


def _register_extensions(app: Flask) -> None:
    """Initialize all Flask extensions with the application."""
    db.init_app(app)
    migrate.init_app(app, db)
    socketio.init_app(app, cors_allowed_origins="*", async_mode="eventlet")
    login_manager.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        import uuid
        from app.models.user import User
        try:
            return db.session.get(User, uuid.UUID(user_id))
        except (ValueError, TypeError):
            return None


def _register_blueprints(app: Flask) -> None:
    """Register all Flask blueprints."""
    from app.api.v1.health import health_bp
    from app.api.v1.packets import packets_bp
    from app.api.v1.attacks import attacks_bp
    from app.api.v1.reputation import reputation_bp
    from app.api.v1.ml import ml_bp
    from app.api.v1.threats import threats_bp
    from app.api.v1.alerts import alerts_bp
    from app.api.v1.blocks import blocks_bp
    from app.api.v1.search import search_bp
    from app.api.v1.reports import reports_bp
    from app.api.v1.investigation import investigation_bp
    from app.auth.routes import auth_bp, auth_api_bp
    from app.dashboard.routes import dashboard_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(packets_bp)
    app.register_blueprint(attacks_bp)
    app.register_blueprint(reputation_bp)
    app.register_blueprint(ml_bp)
    app.register_blueprint(threats_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(blocks_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(investigation_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(auth_api_bp)
    app.register_blueprint(dashboard_bp)


def _register_error_handlers(app: Flask) -> None:
    """Register global error handlers that return JSON for API routes."""
    from flask import jsonify

    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": "Bad Request", "message": str(error.description)}), 400

    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({"error": "Unauthorized", "message": "Authentication required."}), 401

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({"error": "Forbidden", "message": "Insufficient permissions."}), 403

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Not Found", "message": "Resource not found."}), 404

    @app.errorhandler(429)
    def rate_limited(error):
        return jsonify({"error": "Too Many Requests", "message": "Rate limit exceeded."}), 429

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal server error: {error}", exc_info=True)
        return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred."}), 500


def _configure_logging(app: Flask) -> None:
    """Configure application logging."""
    from app.core.logging_config import setup_logging

    if not app.testing:
        setup_logging(app)
    else:
        logging.basicConfig(level=logging.DEBUG)


def _init_capture_engine(app: Flask) -> None:
    """Initialize all core backend engines and REST API endpoints.

    Wires all pipeline components together. Starts background queues
    and workers only in non-testing environments.
    """
    from app.api.v1.packets import init_capture_engine
    from app.detection.orchestrator import DetectionOrchestrator
    from app.detection.config import DetectionConfig
    from app.api.v1.attacks import init_detection_engine
    from app.ml.feature_extractor import FlowFeatureExtractor
    from app.ml.feature_store import FeatureStore
    from app.ml.trainer import ModelTrainer
    from app.ml.inference import AnomalyDetector
    from app.ml.model_manager import ModelManager
    from app.ml.drift_detector import DriftDetector
    from app.intelligence.ip_reputation import IPReputationService
    from app.api.v1.reputation import init_reputation_service
    from app.api.v1.ml import init_ml_api
    from app.scoring.threat_scorer import ThreatScorer
    from app.scoring.response_engine import ResponseEngine
    from app.scoring.alert_priority import AlertPriorityQueue
    from app.api.v1.threats import init_threats_api
    from app.alerts.manager import AlertManager
    from app.alerts.aggregator import CampaignAggregator
    from app.alerts.streamer import AlertStreamer
    from app.api.v1.alerts import init_alerts_api
    from app.protection.ip_blocker import IPBlocker
    from app.protection.list_manager import ListManager
    from app.api.v1.blocks import init_blocks_api
    from app.search.packet_search import PacketSearchEngine
    from app.api.v1.search import init_search_api
    from app.investigation.timeline import AttackTimeline
    from app.investigation.ip_investigator import IPInvestigator
    from app.investigation.flow_reconstructor import TCPFlowReconstructor
    from app.api.v1.investigation import init_investigation_api
    from app.notifications.email_sender import EmailSender
    from app.notifications.email_queue import EmailQueueWorker

    with app.app_context():
        # Initialize capture pipeline
        init_capture_engine(app, socketio)

        # Initialize detection engine
        detection_config = DetectionConfig()
        orchestrator = DetectionOrchestrator(app=app, config=detection_config)
        orchestrator.register_all_detectors()
        init_detection_engine(app, orchestrator)

        # Store orchestrator on app for access by capture workers
        app.extensions['orchestrator'] = orchestrator
        app.logger.info('Detection engine initialized with %d detectors',
                        len(orchestrator._detectors))

        # Initialize ML pipeline
        feature_extractor = FlowFeatureExtractor()
        feature_store = FeatureStore(app=app)
        trainer = ModelTrainer()
        anomaly_detector = AnomalyDetector()
        model_manager = ModelManager(app=app)
        drift_detector = DriftDetector()

        # Try to load existing model
        anomaly_detector.load_model()

        app.extensions['ml'] = {
            'feature_extractor': feature_extractor,
            'feature_store': feature_store,
            'trainer': trainer,
            'anomaly_detector': anomaly_detector,
            'model_manager': model_manager,
            'drift_detector': drift_detector,
        }

        # Wire ML API
        init_ml_api(
            app, model_manager, anomaly_detector,
            drift_detector, feature_store, trainer,
        )
        app.logger.info('ML pipeline initialized (model loaded: %s)',
                        anomaly_detector.is_loaded)

        # Initialize intelligence service
        reputation_service = IPReputationService(app=app)
        app.extensions['reputation'] = reputation_service
        init_reputation_service(app, reputation_service)
        app.logger.info('Intelligence service initialized')

        # Initialize scoring and response engine (Phase 6)
        scorer = ThreatScorer(app=app)
        response_engine = ResponseEngine(app=app)
        alert_queue = AlertPriorityQueue()

        # Response engine handles dispatched alerts
        alert_queue.register_handler(response_engine.process_scored_alert)

        app.extensions['scorer'] = scorer
        app.extensions['response_engine'] = response_engine
        app.extensions['alert_queue'] = alert_queue

        init_threats_api(app, scorer, response_engine)
        app.logger.info('Scoring and response engine initialized')

        # Initialize alerts components (Phase 7)
        alert_streamer = AlertStreamer(socketio)
        alert_manager = AlertManager(app=app)
        campaign_aggregator = CampaignAggregator()
        init_alerts_api(app, alert_manager, campaign_aggregator, alert_streamer)

        app.extensions['alerts'] = {
            'manager': alert_manager,
            'aggregator': campaign_aggregator,
            'streamer': alert_streamer,
        }

        # Initialize protection components (Phase 7)
        ip_blocker = IPBlocker(app=app)
        list_manager = ListManager(app=app)
        init_blocks_api(app, ip_blocker, list_manager)

        app.extensions['protection'] = {
            'blocker': ip_blocker,
            'list_manager': list_manager,
        }

        # Initialize search components (Phase 8)
        search_engine = PacketSearchEngine()
        init_search_api(app, search_engine)

        app.extensions['search'] = {
            'engine': search_engine,
        }

        # Initialize investigation components (Phase 8)
        timeline = AttackTimeline(app=app)
        ip_investigator = IPInvestigator(app=app)
        flow_reconstructor = TCPFlowReconstructor(app=app)
        init_investigation_api(app, timeline, ip_investigator, flow_reconstructor)

        app.extensions['investigation'] = {
            'timeline': timeline,
            'ip_investigator': ip_investigator,
            'flow_reconstructor': flow_reconstructor,
        }

        # Initialize notifications components (Phase 7)
        email_sender = EmailSender(app=app)
        email_queue_worker = EmailQueueWorker(app=app, sender=email_sender)

        app.extensions['notifications'] = {
            'sender': email_sender,
            'worker': email_queue_worker,
        }

        # Start background dispatch queues and worker loops if not testing
        if not app.testing:
            alert_queue.start()
            email_queue_worker.start()
            app.logger.info('Background worker and queue threads started')
