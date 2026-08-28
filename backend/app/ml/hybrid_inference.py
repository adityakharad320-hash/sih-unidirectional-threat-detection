"""
Hybrid Inference Interface.
Loads the latest RF and IF models, runs fusion, returns FusionResult.
"""
import joblib, logging
from pathlib import Path
from app.config import MODELS_DIR
from app.ml.fusion import ThreatFusionEngine, FusionResult
from app.telemetry.feature_schema import TelemetryFeatureVector_v2

logger = logging.getLogger(__name__)


def _load_latest(prefix: str) -> dict:
    candidates = sorted(MODELS_DIR.glob(f"{prefix}_*.joblib"), reverse=True)
    if not candidates:
        raise FileNotFoundError(f"No saved model with prefix '{prefix}' in {MODELS_DIR}")
    return joblib.load(candidates[0])


class HybridInferenceEngine:
    def __init__(self):
        logger.info("[Hybrid] Loading Random Forest ...")
        rf_artifact = _load_latest("random_forest")
        logger.info("[Hybrid] Loading Isolation Forest ...")
        if_artifact = _load_latest("isolation_forest")
        self.engine = ThreatFusionEngine(rf_artifact, if_artifact)
        logger.info("[Hybrid] Engine ready.")

    def predict(self, fv: TelemetryFeatureVector_v2) -> FusionResult:
        features_dict = fv.to_dict()
        return self.engine.predict(fv, features_dict)
