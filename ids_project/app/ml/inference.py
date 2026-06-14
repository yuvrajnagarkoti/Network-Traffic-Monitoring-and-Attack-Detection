"""
Anomaly detection inference engine.

Loads a trained Isolation Forest model and provides
real-time anomaly scoring for flow feature vectors.
"""

import hashlib
import logging
import os
import threading
import time
from typing import Optional

import joblib
import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_MODEL_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "models"
)


class AnomalyDetector:
    """Real-time anomaly detection inference engine.

    Loads a trained Pipeline (StandardScaler + IsolationForest)
    and scores incoming feature vectors as normal or anomalous.

    Anomaly scores are normalized to 0–1 where higher = more anomalous.
    """

    def __init__(self, model_dir: str = DEFAULT_MODEL_DIR) -> None:
        """Initialize inference engine.

        Args:
            model_dir: Directory containing model files.
        """
        self.model_dir = model_dir
        self._pipeline = None
        self._model_version: Optional[str] = None
        self._model_checksum: Optional[str] = None
        self._lock = threading.Lock()
        self._total_predictions: int = 0
        self._total_anomalies: int = 0
        self._loaded = False

    def load_model(
        self,
        model_path: Optional[str] = None,
        expected_checksum: Optional[str] = None,
    ) -> bool:
        """Load a trained model from disk.

        Args:
            model_path: Explicit path to model pickle file.
                If None, loads the latest model from model_dir.
            expected_checksum: SHA-256 checksum to verify integrity.

        Returns:
            True if model loaded successfully.
        """
        try:
            if model_path is None:
                model_path = self._find_latest_model()
                if model_path is None:
                    logger.warning("No model files found in %s", self.model_dir)
                    return False

            # Verify checksum if provided
            if expected_checksum:
                actual_checksum = self._compute_checksum(model_path)
                if actual_checksum != expected_checksum:
                    logger.error(
                        "Model checksum mismatch: expected %s, got %s",
                        expected_checksum[:16],
                        actual_checksum[:16],
                    )
                    return False

            with self._lock:
                self._pipeline = joblib.load(model_path)
                self._model_version = os.path.basename(model_path)
                self._model_checksum = self._compute_checksum(model_path)
                self._loaded = True

            logger.info("Loaded model: %s", self._model_version)
            return True

        except Exception as exc:
            logger.error("Failed to load model: %s", exc)
            return False

    def predict(self, feature_vector: np.ndarray) -> dict:
        """Predict whether a single flow is anomalous.

        Args:
            feature_vector: 25-element NumPy array.

        Returns:
            Dict with is_anomaly, anomaly_score (0-1), confidence.
        """
        if not self._loaded or self._pipeline is None:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "error": "Model not loaded",
            }

        try:
            X = feature_vector.reshape(1, -1)
            X = self._clean_input(X)

            with self._lock:
                # decision_function: negative = more anomalous
                raw_score = self._pipeline.decision_function(X)[0]
                prediction = self._pipeline.predict(X)[0]

            # Normalize score to 0-1 (higher = more anomalous)
            # IsolationForest scores typically range from -0.5 to 0.5
            anomaly_score = max(0.0, min(1.0, 0.5 - raw_score))

            is_anomaly = prediction == -1
            confidence = anomaly_score if is_anomaly else (1.0 - anomaly_score)

            self._total_predictions += 1
            if is_anomaly:
                self._total_anomalies += 1

            return {
                "is_anomaly": bool(is_anomaly),
                "anomaly_score": round(float(anomaly_score), 4),
                "confidence": round(float(confidence), 4),
                "raw_score": round(float(raw_score), 4),
            }

        except Exception as exc:
            logger.debug("Prediction failed: %s", exc)
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "error": str(exc),
            }

    def predict_batch(self, feature_matrix: np.ndarray) -> list[dict]:
        """Predict anomalies for a batch of feature vectors.

        Args:
            feature_matrix: N × 25 NumPy array.

        Returns:
            List of prediction dictionaries.
        """
        if not self._loaded or self._pipeline is None:
            return []

        if len(feature_matrix) == 0:
            return []

        try:
            X = self._clean_input(feature_matrix)

            with self._lock:
                raw_scores = self._pipeline.decision_function(X)
                predictions = self._pipeline.predict(X)

            results = []
            for i in range(len(X)):
                anomaly_score = max(0.0, min(1.0, 0.5 - raw_scores[i]))
                is_anomaly = predictions[i] == -1
                confidence = anomaly_score if is_anomaly else (1.0 - anomaly_score)

                results.append({
                    "is_anomaly": bool(is_anomaly),
                    "anomaly_score": round(float(anomaly_score), 4),
                    "confidence": round(float(confidence), 4),
                })

                self._total_predictions += 1
                if is_anomaly:
                    self._total_anomalies += 1

            return results

        except Exception as exc:
            logger.error("Batch prediction failed: %s", exc)
            return []

    def _find_latest_model(self) -> Optional[str]:
        """Find the most recent model file in model_dir."""
        if not os.path.exists(self.model_dir):
            return None

        model_files = [
            f for f in os.listdir(self.model_dir)
            if f.startswith("model_") and f.endswith(".pkl")
        ]

        if not model_files:
            return None

        model_files.sort(reverse=True)
        return os.path.join(self.model_dir, model_files[0])

    def _clean_input(self, X: np.ndarray) -> np.ndarray:
        """Clean input data for inference."""
        X = X.copy()
        X[np.isinf(X)] = 0.0
        X[np.isnan(X)] = 0.0
        return X

    def _compute_checksum(self, filepath: str) -> str:
        """Compute SHA-256 checksum for integrity verification."""
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    @property
    def is_loaded(self) -> bool:
        """Check if a model is loaded and ready for inference."""
        return self._loaded

    @property
    def stats(self) -> dict:
        """Return inference engine statistics."""
        anomaly_rate = (
            self._total_anomalies / max(self._total_predictions, 1)
        )
        return {
            "model_loaded": self._loaded,
            "model_version": self._model_version,
            "total_predictions": self._total_predictions,
            "total_anomalies": self._total_anomalies,
            "anomaly_rate": round(anomaly_rate, 4),
        }
