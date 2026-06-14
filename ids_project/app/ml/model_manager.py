"""
ML model version manager.

Tracks model versions, handles deployment decisions,
and provides rollback capability.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_MODEL_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "models"
)

MAX_VERSIONS = 3


class ModelManager:
    """Manages ML model versions and deployment lifecycle.

    Tracks all trained models in the ml_model_versions table.
    Keeps the last 3 versions. Supports rollback if a new
    model underperforms.
    """

    def __init__(self, app=None, model_dir: str = DEFAULT_MODEL_DIR) -> None:
        """Initialize model manager.

        Args:
            app: Flask application instance.
            model_dir: Directory containing model files.
        """
        self.app = app
        self.model_dir = model_dir
        self._current_version: Optional[str] = None
        os.makedirs(self.model_dir, exist_ok=True)

    def register_model(self, training_result: dict) -> Optional[str]:
        """Register a newly trained model version.

        Args:
            training_result: Result dictionary from ModelTrainer.train().

        Returns:
            Model version string or None on failure.
        """
        if not training_result.get("success"):
            return None

        version = training_result["version"]

        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.ml import MLModelVersion

                model_record = MLModelVersion(
                    version=version,
                    model_path=training_result["model_path"],
                    scaler_path=training_result.get("scaler_path"),
                    checksum=training_result.get("checksum"),
                    training_samples=training_result["training_samples"],
                    feature_count=training_result["feature_count"],
                    validation_auc=training_result.get("auc", 0.0),
                    contamination=training_result.get("contamination", 0.01),
                    n_estimators=training_result.get("n_estimators", 200),
                    is_active=True,
                    trained_at=datetime.now(timezone.utc),
                )

                # Deactivate previous active model
                db.session.query(MLModelVersion).filter(
                    MLModelVersion.is_active == True  # noqa: E712
                ).update({"is_active": False})

                db.session.add(model_record)
                db.session.commit()

                self._current_version = version
                self._cleanup_old_versions()

                logger.info("Registered model version: %s", version)
                return version

        except Exception as exc:
            logger.error("Failed to register model: %s", exc)
            return None

    def get_active_model(self) -> Optional[dict]:
        """Get the currently active model version info.

        Returns:
            Dictionary with model metadata or None.
        """
        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.ml import MLModelVersion

                active = (
                    db.session.query(MLModelVersion)
                    .filter(MLModelVersion.is_active == True)  # noqa: E712
                    .first()
                )

                if active:
                    return {
                        "version": active.version,
                        "model_path": active.model_path,
                        "checksum": active.checksum,
                        "training_samples": active.training_samples,
                        "validation_auc": active.validation_auc,
                        "trained_at": active.trained_at.isoformat() if active.trained_at else None,
                        "is_active": True,
                    }

                return None

        except Exception as exc:
            logger.error("Failed to get active model: %s", exc)
            return None

    def rollback(self) -> Optional[str]:
        """Rollback to the previous model version.

        Returns:
            Version string of the restored model or None.
        """
        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.ml import MLModelVersion

                # Get all versions ordered by training date
                versions = (
                    db.session.query(MLModelVersion)
                    .order_by(MLModelVersion.trained_at.desc())
                    .limit(3)
                    .all()
                )

                if len(versions) < 2:
                    logger.warning("No previous version to rollback to")
                    return None

                # Deactivate current
                for v in versions:
                    v.is_active = False

                # Activate previous
                previous = versions[1]
                previous.is_active = True
                db.session.commit()

                self._current_version = previous.version
                logger.info("Rolled back to model version: %s", previous.version)
                return previous.version

        except Exception as exc:
            logger.error("Rollback failed: %s", exc)
            return None

    def get_all_versions(self) -> list[dict]:
        """Get all tracked model versions.

        Returns:
            List of version metadata dictionaries.
        """
        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.ml import MLModelVersion

                versions = (
                    db.session.query(MLModelVersion)
                    .order_by(MLModelVersion.trained_at.desc())
                    .all()
                )

                return [
                    {
                        "version": v.version,
                        "validation_auc": v.validation_auc,
                        "training_samples": v.training_samples,
                        "is_active": v.is_active,
                        "trained_at": v.trained_at.isoformat() if v.trained_at else None,
                    }
                    for v in versions
                ]

        except Exception as exc:
            logger.error("Failed to list versions: %s", exc)
            return []

    def _cleanup_old_versions(self) -> None:
        """Remove model files older than MAX_VERSIONS."""
        try:
            model_files = sorted(
                [f for f in os.listdir(self.model_dir) if f.endswith(".pkl")],
                reverse=True,
            )

            # Group by version prefix (model_ and scaler_ share a version)
            versions = set()
            for f in model_files:
                parts = f.replace("model_", "").replace("scaler_", "").replace(".pkl", "")
                versions.add(parts)

            versions_sorted = sorted(versions, reverse=True)

            if len(versions_sorted) <= MAX_VERSIONS:
                return

            old_versions = versions_sorted[MAX_VERSIONS:]
            for old_ver in old_versions:
                for prefix in ["model_", "scaler_"]:
                    path = os.path.join(self.model_dir, f"{prefix}{old_ver}.pkl")
                    if os.path.exists(path):
                        os.remove(path)
                        logger.debug("Removed old model file: %s", path)

        except Exception as exc:
            logger.debug("Cleanup error: %s", exc)
