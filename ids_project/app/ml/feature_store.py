"""
Feature vector persistence store.

Saves extracted feature vectors to the ml_features table
and provides retrieval functions for model training.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)


class FeatureStore:
    """Persists and retrieves ML feature vectors.

    Writes feature vectors to the database as JSONB for
    training dataset construction. Labels attack-related
    flows by cross-referencing with attack_events.
    """

    def __init__(self, app=None) -> None:
        """Initialize feature store.

        Args:
            app: Flask application instance.
        """
        self.app = app
        self._total_stored: int = 0

    def store_feature_vector(
        self,
        flow_id: str,
        feature_vector: np.ndarray,
        is_attack: bool = False,
        attack_type: Optional[str] = None,
    ) -> None:
        """Persist a feature vector to the database.

        Args:
            flow_id: Flow identifier.
            feature_vector: 25-element NumPy array.
            is_attack: Whether this flow is from an attack.
            attack_type: Type of attack if is_attack is True.
        """
        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.ml import MLFeature

                feature = MLFeature(
                    flow_id=flow_id,
                    features=feature_vector.tolist(),
                    is_attack=is_attack,
                    attack_type=attack_type,
                    extracted_at=datetime.now(timezone.utc),
                )
                db.session.add(feature)
                db.session.commit()
                self._total_stored += 1

        except Exception as exc:
            logger.debug("Failed to store feature vector: %s", exc)

    def store_batch(
        self,
        vectors: list[tuple[str, np.ndarray]],
        is_attack: bool = False,
    ) -> int:
        """Store multiple feature vectors in a single transaction.

        Args:
            vectors: List of (flow_id, feature_vector) tuples.
            is_attack: Whether these flows are attacks.

        Returns:
            Number of vectors successfully stored.
        """
        if not vectors:
            return 0

        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.ml import MLFeature

                records = [
                    {
                        "flow_id": flow_id,
                        "features": vector.tolist(),
                        "is_attack": is_attack,
                        "extracted_at": datetime.now(timezone.utc),
                    }
                    for flow_id, vector in vectors
                ]

                db.session.bulk_insert_mappings(MLFeature, records)
                db.session.commit()
                self._total_stored += len(records)
                return len(records)

        except Exception as exc:
            logger.error("Failed to store feature batch: %s", exc)
            return 0

    def get_training_data(
        self,
        limit: int = 50000,
        days: int = 7,
        exclude_attacks: bool = True,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Retrieve feature vectors for model training.

        Args:
            limit: Maximum vectors to retrieve.
            days: Look-back window in days.
            exclude_attacks: If True, only return normal traffic.

        Returns:
            Tuple of (X feature matrix, y labels array).
        """
        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.ml import MLFeature

                cutoff = datetime.now(timezone.utc) - timedelta(days=days)
                query = db.session.query(MLFeature).filter(
                    MLFeature.extracted_at >= cutoff
                )

                if exclude_attacks:
                    query = query.filter(MLFeature.is_attack == False)  # noqa: E712

                query = query.order_by(MLFeature.extracted_at.desc()).limit(limit)
                records = query.all()

                if not records:
                    return np.array([]), np.array([])

                X = np.array([r.features for r in records], dtype=np.float64)
                y = np.array(
                    [1 if r.is_attack else 0 for r in records],
                    dtype=np.int32,
                )

                logger.info(
                    "Retrieved %d training samples (%d normal, %d attack)",
                    len(records),
                    int(np.sum(y == 0)),
                    int(np.sum(y == 1)),
                )
                return X, y

        except Exception as exc:
            logger.error("Failed to retrieve training data: %s", exc)
            return np.array([]), np.array([])

    def get_recent_vectors(self, count: int = 100) -> np.ndarray:
        """Get the most recent feature vectors for inference.

        Args:
            count: Number of vectors to retrieve.

        Returns:
            Feature matrix (count × 25).
        """
        try:
            if self.app is None:
                from flask import current_app
                app = current_app._get_current_object()
            else:
                app = self.app

            with app.app_context():
                from app.extensions import db
                from app.models.ml import MLFeature

                records = (
                    db.session.query(MLFeature)
                    .order_by(MLFeature.extracted_at.desc())
                    .limit(count)
                    .all()
                )

                if not records:
                    return np.array([])

                return np.array(
                    [r.features for r in records], dtype=np.float64
                )

        except Exception as exc:
            logger.error("Failed to retrieve recent vectors: %s", exc)
            return np.array([])

    @property
    def stats(self) -> dict:
        """Return store statistics."""
        return {"total_stored": self._total_stored}
