"""
Feature drift detector.

Monitors the distribution of incoming feature vectors against
the training distribution. Alerts on concept drift when the
network behavior changes significantly.
"""

import logging
import threading
from collections import deque
from typing import Optional

import numpy as np

from app.ml.feature_extractor import FEATURE_NAMES, NUM_FEATURES

logger = logging.getLogger(__name__)

# Default drift thresholds
DRIFT_FEATURE_THRESHOLD = 0.30  # Alert if >30% of features drifted
DRIFT_SIGMA_THRESHOLD = 2.0    # Feature considered drifted if shift >2σ
DRIFT_WINDOW_SIZE = 500         # Compare last N vectors to baseline


class DriftDetector:
    """Monitors feature distribution for concept drift.

    Concept drift occurs when the network's normal behavior
    changes so significantly that the ML model's training
    distribution no longer represents current traffic.

    Detection: compare mean of recent feature vectors against
    training distribution mean. If >30% of features shift by
    >2 standard deviations, concept drift is flagged.
    """

    def __init__(self) -> None:
        """Initialize drift detector."""
        self._training_mean: Optional[np.ndarray] = None
        self._training_std: Optional[np.ndarray] = None
        self._recent_vectors: deque = deque(maxlen=DRIFT_WINDOW_SIZE)
        self._lock = threading.Lock()
        self._drift_detected: bool = False
        self._last_check_result: Optional[dict] = None
        self._total_checks: int = 0

    def set_baseline(self, X_train: np.ndarray) -> None:
        """Set the training distribution as baseline.

        Called after model training with the training data.

        Args:
            X_train: Training feature matrix (N × 25).
        """
        with self._lock:
            self._training_mean = np.nanmean(X_train, axis=0)
            self._training_std = np.nanstd(X_train, axis=0)
            # Prevent division by zero
            self._training_std[self._training_std < 1e-6] = 1.0
            self._drift_detected = False

        logger.info(
            "Drift baseline set from %d training samples", len(X_train)
        )

    def record_vector(self, vector: np.ndarray) -> None:
        """Record an incoming feature vector for drift monitoring.

        Args:
            vector: 25-element NumPy array.
        """
        with self._lock:
            self._recent_vectors.append(vector)

    def check_drift(self) -> dict:
        """Check for concept drift in recent feature vectors.

        Returns:
            Dictionary with drift_detected, drifted_features,
            drift_percentage, and per-feature shift details.
        """
        with self._lock:
            if self._training_mean is None:
                return {
                    "drift_detected": False,
                    "error": "No baseline set",
                }

            if len(self._recent_vectors) < 50:
                return {
                    "drift_detected": False,
                    "message": f"Insufficient data: {len(self._recent_vectors)}/50 vectors",
                }

            recent_matrix = np.array(list(self._recent_vectors))
            recent_mean = np.nanmean(recent_matrix, axis=0)

            # Calculate z-scores of shift
            shifts = np.abs(recent_mean - self._training_mean) / self._training_std
            drifted_mask = shifts > DRIFT_SIGMA_THRESHOLD
            drift_count = int(np.sum(drifted_mask))
            drift_percentage = drift_count / NUM_FEATURES

            self._drift_detected = drift_percentage > DRIFT_FEATURE_THRESHOLD
            self._total_checks += 1

            # Build per-feature drift details
            drifted_features = []
            for i, (name, shifted, z) in enumerate(
                zip(FEATURE_NAMES, drifted_mask, shifts)
            ):
                if shifted:
                    drifted_features.append({
                        "feature": name,
                        "index": i,
                        "z_score_shift": round(float(z), 2),
                        "training_mean": round(float(self._training_mean[i]), 4),
                        "recent_mean": round(float(recent_mean[i]), 4),
                    })

            result = {
                "drift_detected": self._drift_detected,
                "drift_percentage": round(drift_percentage * 100, 1),
                "drifted_feature_count": drift_count,
                "total_features": NUM_FEATURES,
                "threshold_percentage": DRIFT_FEATURE_THRESHOLD * 100,
                "sigma_threshold": DRIFT_SIGMA_THRESHOLD,
                "sample_size": len(self._recent_vectors),
                "drifted_features": drifted_features,
                "requires_retraining": self._drift_detected,
            }

            self._last_check_result = result

            if self._drift_detected:
                logger.warning(
                    "CONCEPT DRIFT DETECTED: %.1f%% of features shifted (threshold: %.0f%%)",
                    drift_percentage * 100,
                    DRIFT_FEATURE_THRESHOLD * 100,
                )

            return result

    @property
    def is_drifted(self) -> bool:
        """Check if concept drift has been detected."""
        return self._drift_detected

    @property
    def stats(self) -> dict:
        """Return drift detector statistics."""
        return {
            "baseline_set": self._training_mean is not None,
            "recent_vector_count": len(self._recent_vectors),
            "drift_detected": self._drift_detected,
            "total_checks": self._total_checks,
            "last_result": self._last_check_result,
        }
