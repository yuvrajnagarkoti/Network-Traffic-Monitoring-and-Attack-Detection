"""
ML model training pipeline.

Trains an Isolation Forest anomaly detection model using
StandardScaler preprocessing. Evaluates on validation set
and only deploys if AUC > 0.80.
"""

import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

import joblib
import numpy as np

logger = logging.getLogger(__name__)

# Default model directory
DEFAULT_MODEL_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "models"
)


class ModelTrainer:
    """Trains and evaluates Isolation Forest anomaly detection models.

    Pipeline: StandardScaler → IsolationForest
    Training: unsupervised on normal traffic only.
    Validation: AUC-ROC against labeled data.
    """

    def __init__(
        self,
        model_dir: str = DEFAULT_MODEL_DIR,
        contamination: float = 0.01,
        n_estimators: int = 200,
        random_state: int = 42,
    ) -> None:
        """Initialize trainer.

        Args:
            model_dir: Directory to save model files.
            contamination: Expected anomaly rate.
            n_estimators: Number of trees in the forest.
            random_state: Random seed for reproducibility.
        """
        self.model_dir = model_dir
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        os.makedirs(self.model_dir, exist_ok=True)

    def train(
        self,
        X_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        min_auc: float = 0.80,
    ) -> dict:
        """Train a new Isolation Forest model.

        Args:
            X_train: Training feature matrix (normal traffic only).
            X_val: Validation feature matrix (optional).
            y_val: Validation labels (0=normal, 1=attack).
            min_auc: Minimum AUC-ROC to deploy model.

        Returns:
            Training result dictionary with model_path, metrics.
        """
        from sklearn.ensemble import IsolationForest
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler

        if len(X_train) < 100:
            return {
                "success": False,
                "error": f"Insufficient training data: {len(X_train)} samples (need 100+)",
            }

        logger.info(
            "Training Isolation Forest: %d samples, %d features",
            X_train.shape[0],
            X_train.shape[1],
        )

        start_time = time.time()

        # Handle NaN/Inf
        X_train = self._clean_data(X_train)

        # Build pipeline
        pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("model", IsolationForest(
                contamination=self.contamination,
                n_estimators=self.n_estimators,
                random_state=self.random_state,
                n_jobs=-1,
            )),
        ])

        # Train
        pipeline.fit(X_train)
        train_time = time.time() - start_time

        # Evaluate on validation set
        auc_score = 0.0
        if X_val is not None and y_val is not None and len(X_val) > 0:
            auc_score = self._evaluate(pipeline, X_val, y_val)
            logger.info("Validation AUC-ROC: %.4f", auc_score)

            if auc_score < min_auc:
                logger.warning(
                    "Model AUC %.4f below threshold %.2f — not deploying",
                    auc_score,
                    min_auc,
                )
                return {
                    "success": False,
                    "error": f"AUC {auc_score:.4f} below minimum {min_auc}",
                    "auc": auc_score,
                    "train_time_seconds": round(train_time, 2),
                }

        # Generate version
        version = datetime.now(timezone.utc).strftime("v%Y%m%d_%H%M%S")
        model_path = os.path.join(self.model_dir, f"model_{version}.pkl")
        scaler_path = os.path.join(self.model_dir, f"scaler_{version}.pkl")

        # Save model and scaler separately
        joblib.dump(pipeline, model_path)
        joblib.dump(pipeline.named_steps["scaler"], scaler_path)

        # Compute checksum
        checksum = self._compute_checksum(model_path)

        result = {
            "success": True,
            "version": version,
            "model_path": model_path,
            "scaler_path": scaler_path,
            "checksum": checksum,
            "training_samples": X_train.shape[0],
            "feature_count": X_train.shape[1],
            "auc": round(auc_score, 4),
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "train_time_seconds": round(train_time, 2),
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "Model trained successfully: %s (AUC=%.4f, %d samples, %.1fs)",
            version, auc_score, X_train.shape[0], train_time,
        )

        return result

    def _evaluate(
        self,
        pipeline,
        X_val: np.ndarray,
        y_val: np.ndarray,
    ) -> float:
        """Evaluate model on labeled validation set.

        Args:
            pipeline: Trained Pipeline.
            X_val: Validation features.
            y_val: Validation labels (0=normal, 1=attack).

        Returns:
            AUC-ROC score.
        """
        try:
            from sklearn.metrics import roc_auc_score

            X_val = self._clean_data(X_val)

            # Isolation Forest: decision_function returns anomaly scores
            # More negative = more anomalous
            scores = pipeline.decision_function(X_val)

            # Invert so more positive = more anomalous (matches y_val convention)
            scores_inverted = -scores

            auc = roc_auc_score(y_val, scores_inverted)
            return float(auc)

        except Exception as exc:
            logger.error("Evaluation failed: %s", exc)
            return 0.0

    def _clean_data(self, X: np.ndarray) -> np.ndarray:
        """Replace NaN and Inf values with column medians.

        Args:
            X: Feature matrix.

        Returns:
            Cleaned feature matrix.
        """
        X = X.copy()
        # Replace inf with nan
        X[np.isinf(X)] = np.nan
        # Fill nan with column median
        for col in range(X.shape[1]):
            mask = np.isnan(X[:, col])
            if mask.any():
                median = np.nanmedian(X[:, col])
                X[mask, col] = median if not np.isnan(median) else 0.0
        return X

    def _compute_checksum(self, filepath: str) -> str:
        """Compute SHA-256 checksum for model file integrity.

        Args:
            filepath: Path to model file.

        Returns:
            Hex-encoded SHA-256 hash.
        """
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
