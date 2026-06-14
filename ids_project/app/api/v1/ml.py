"""
Machine Learning REST API endpoints.

Provides model status, manual retraining trigger,
and drift detection status.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

ml_bp = Blueprint("ml", __name__)

# Module-level references
_model_manager = None
_anomaly_detector = None
_drift_detector = None
_feature_store = None
_trainer = None


def init_ml_api(
    app,
    model_manager,
    anomaly_detector,
    drift_detector,
    feature_store,
    trainer,
) -> None:
    """Wire ML components into the API.

    Args:
        app: Flask application instance.
        model_manager: ModelManager instance.
        anomaly_detector: AnomalyDetector instance.
        drift_detector: DriftDetector instance.
        feature_store: FeatureStore instance.
        trainer: ModelTrainer instance.
    """
    global _model_manager, _anomaly_detector, _drift_detector
    global _feature_store, _trainer

    _model_manager = model_manager
    _anomaly_detector = anomaly_detector
    _drift_detector = drift_detector
    _feature_store = feature_store
    _trainer = trainer

    logger.info("ML API initialized")


@ml_bp.route("/api/v1/ml/model/status", methods=["GET"])
def get_model_status():
    """Return current ML model status.

    Includes: version, AUC, training samples, last trained,
    inference stats, and drift detection status.
    """
    if _model_manager is None:
        return jsonify({"error": "ML engine not initialized"}), 503

    active_model = _model_manager.get_active_model()
    all_versions = _model_manager.get_all_versions()

    result = {
        "active_model": active_model,
        "all_versions": all_versions,
        "inference": _anomaly_detector.stats if _anomaly_detector else {},
        "drift": _drift_detector.stats if _drift_detector else {},
        "feature_store": _feature_store.stats if _feature_store else {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    return jsonify(result), 200


@ml_bp.route("/api/v1/ml/model/retrain", methods=["POST"])
def trigger_retraining():
    """Trigger manual model retraining.

    Admin endpoint. Fetches training data from feature store,
    trains a new model, evaluates, and deploys if AUC > 0.80.

    Request body (optional):
        {"min_auc": 0.80, "days": 7, "limit": 50000}

    TODO: Add @require_permission('MANAGE_SYSTEM_CONFIG') in Phase 9
    """
    if _trainer is None or _feature_store is None:
        return jsonify({"error": "ML engine not initialized"}), 503

    data = request.get_json() or {}
    min_auc = data.get("min_auc", 0.80)
    days = data.get("days", 7)
    limit = data.get("limit", 50000)

    try:
        # Retrieve training data
        X, y = _feature_store.get_training_data(
            limit=limit, days=days, exclude_attacks=True
        )

        if len(X) < 100:
            return jsonify({
                "error": f"Insufficient training data: {len(X)} samples (need 100+)",
                "suggestion": "Run capture in simulation mode to generate more data",
            }), 400

        # Split validation set if we have labeled data
        X_val, y_val = None, None
        if len(y) > 0 and sum(y) > 0:
            from sklearn.model_selection import train_test_split
            X_train, X_val, _, y_val = train_test_split(
                X, y, test_size=0.2, stratify=y, random_state=42
            )
        else:
            X_train = X

        # Train model
        result = _trainer.train(
            X_train=X_train,
            X_val=X_val,
            y_val=y_val,
            min_auc=min_auc,
        )

        if result.get("success"):
            # Register new model version
            version = _model_manager.register_model(result)

            # Load into inference engine
            _anomaly_detector.load_model(result["model_path"])

            # Update drift baseline
            if _drift_detector:
                _drift_detector.set_baseline(X_train)

            result["deployed_version"] = version

        return jsonify(result), 200

    except Exception as exc:
        logger.error("Retraining failed: %s", exc, exc_info=True)
        return jsonify({"error": str(exc)}), 500


@ml_bp.route("/api/v1/ml/drift", methods=["GET"])
def get_drift_status():
    """Return current feature drift detection status.

    Shows which features have drifted from the training
    distribution and whether retraining is recommended.
    """
    if _drift_detector is None:
        return jsonify({"error": "Drift detector not initialized"}), 503

    result = _drift_detector.check_drift()
    return jsonify(result), 200


@ml_bp.route("/api/v1/ml/model/rollback", methods=["POST"])
def rollback_model():
    """Rollback to the previous model version.

    Admin endpoint. Restores the previous model if the
    current one underperforms.

    TODO: Add @require_permission('MANAGE_SYSTEM_CONFIG') in Phase 9
    """
    if _model_manager is None:
        return jsonify({"error": "ML engine not initialized"}), 503

    version = _model_manager.rollback()
    if version:
        # Reload model
        active = _model_manager.get_active_model()
        if active and _anomaly_detector:
            _anomaly_detector.load_model(active["model_path"])

        return jsonify({
            "success": True,
            "restored_version": version,
        }), 200
    else:
        return jsonify({
            "success": False,
            "error": "No previous version available for rollback",
        }), 400
