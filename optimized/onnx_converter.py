"""
ONNX Model Exporter, Runtime Tuner & Consistency Benchmark Suite.

Implements Requirements 14 & 15:
- Exports trained Scikit-Learn RandomForestClassifier (v2.0) to ONNX format via skl2onnx.
- Tunes ONNX Runtime SessionOptions (intra_op threads, inter_op threads, graph optimizations).
- Benchmarks single-sample latency distribution (p50, p95, p99, mean) across backends.
- Verifies prediction consistency and class probability calibration against scikit-learn ground truth.
"""
import sys
import time
import json
import joblib
import psutil
import numpy as np
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.config import MODELS_DIR


def export_rf_to_onnx(output_path: Optional[Path] = None) -> Path:
    """Exports the latest trained Random Forest joblib model to ONNX."""
    import onnx
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    candidates = sorted(MODELS_DIR.glob("random_forest_*.joblib"), reverse=True)
    if not candidates:
        raise FileNotFoundError(f"No random_forest joblib models found in {MODELS_DIR}")

    rf_artifact = joblib.load(candidates[0])
    model = rf_artifact["model"]
    feature_names = rf_artifact["feature_names"]
    n_features = len(feature_names)

    initial_type = [("float_input", FloatTensorType([None, n_features]))]
    print(f"[ONNX Exporter] Converting {candidates[0].name} ({n_features} features) to ONNX ...")

    # Options for zipmap: zipmap=False outputs probabilities as 2D tensor rather than sequence of maps (much faster in C++)
    options = {id(model): {"zipmap": False}}
    onnx_model = convert_sklearn(model, initial_types=initial_type, options=options)

    if output_path is None:
        output_path = MODELS_DIR / "random_forest_v2.0.onnx"

    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    file_size_kb = output_path.stat().st_size / 1024.0
    print(f"[ONNX Exporter] Successfully exported ONNX model to: {output_path} ({file_size_kb:.1f} KB)")
    return output_path


def benchmark_sklearn_vs_onnx(num_trials: int = 500) -> Dict[str, Any]:
    """
    Benchmarks single-sample inference latency and tests consistency between
    Scikit-Learn and ONNX Runtime.
    """
    import onnxruntime as ort

    candidates = sorted(MODELS_DIR.glob("random_forest_*.joblib"), reverse=True)
    rf_artifact = joblib.load(candidates[0])
    rf_model = rf_artifact["model"]
    rf_model.n_jobs = 1
    classes = list(rf_model.classes_)
    n_features = len(rf_artifact["feature_names"])

    onnx_file = MODELS_DIR / "random_forest_v2.0.onnx"
    if not onnx_file.exists():
        onnx_file = export_rf_to_onnx(onnx_file)

    # ── 1. TUNE ONNX RUNTIME SESSION OPTIONS ──────────────────────────────────
    configurations = [
        {"name": "ORT_Sequential_1Thread", "intra": 1, "inter": 1, "opt": ort.GraphOptimizationLevel.ORT_ENABLE_ALL},
        {"name": "ORT_Parallel_2Threads", "intra": 2, "inter": 1, "opt": ort.GraphOptimizationLevel.ORT_ENABLE_ALL},
        {"name": "ORT_BasicOpt_1Thread", "intra": 1, "inter": 1, "opt": ort.GraphOptimizationLevel.ORT_ENABLE_BASIC}
    ]

    sessions = {}
    for cfg in configurations:
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = cfg["intra"]
        opts.inter_op_num_threads = cfg["inter"]
        opts.graph_optimization_level = cfg["opt"]
        sessions[cfg["name"]] = ort.InferenceSession(str(onnx_file), opts)

    input_name = sessions[configurations[0]["name"]].get_inputs()[0].name

    # Generate realistic pseudo-random feature vectors for testing
    np.random.seed(42)
    test_vectors = [np.random.randn(1, n_features).astype(np.float32) for _ in range(num_trials)]

    # ── 2. BENCHMARK SCIKIT-LEARN ─────────────────────────────────────────────
    # Warmup
    for _ in range(50):
        _ = rf_model.predict_proba(test_vectors[0])

    sk_times_ms = []
    sk_preds = []
    sk_probs = []

    for v in test_vectors:
        t0 = time.perf_counter_ns()
        p = rf_model.predict_proba(v.astype(np.float64))[0]
        t1 = time.perf_counter_ns()
        sk_times_ms.append((t1 - t0) / 1_000_000.0)
        sk_probs.append(p)
        sk_preds.append(classes[int(np.argmax(p))])

    # ── 3. BENCHMARK ONNX CONFIGURATIONS ─────────────────────────────────────
    ort_results = {}

    for cfg in configurations:
        name = cfg["name"]
        sess = sessions[name]

        # Warmup
        for _ in range(50):
            _ = sess.run(None, {input_name: test_vectors[0]})

        ort_times_ms = []
        ort_preds = []
        ort_probs = []

        for v in test_vectors:
            t0 = time.perf_counter_ns()
            out = sess.run(None, {input_name: v})
            t1 = time.perf_counter_ns()
            ort_times_ms.append((t1 - t0) / 1_000_000.0)

            pred_label = str(out[0][0])
            prob_vec = out[1][0]  # numpy array of class probabilities
            ort_preds.append(pred_label)
            ort_probs.append(prob_vec)

        # Calculate consistency with scikit-learn
        match_count = sum(1 for a, b in zip(sk_preds, ort_preds) if a == b)
        accuracy_parity = (match_count / num_trials) * 100.0

        # Mean absolute probability error across all classes
        abs_errs = [np.abs(a - b).mean() for a, b in zip(sk_probs, ort_probs)]
        mean_abs_prob_err = float(np.mean(abs_errs))

        ort_results[name] = {
            "p50_ms": round(float(np.percentile(ort_times_ms, 50)), 4),
            "p95_ms": round(float(np.percentile(ort_times_ms, 95)), 4),
            "p99_ms": round(float(np.percentile(ort_times_ms, 99)), 4),
            "mean_ms": round(float(np.mean(ort_times_ms)), 4),
            "prediction_parity_percent": round(accuracy_parity, 2),
            "mean_abs_prob_error": round(mean_abs_prob_err, 6)
        }

    sklearn_stats = {
        "p50_ms": round(float(np.percentile(sk_times_ms, 50)), 4),
        "p95_ms": round(float(np.percentile(sk_times_ms, 95)), 4),
        "p99_ms": round(float(np.percentile(sk_times_ms, 99)), 4),
        "mean_ms": round(float(np.mean(sk_times_ms)), 4)
    }

    report = {
        "trials_evaluated": num_trials,
        "scikit_learn_random_forest": sklearn_stats,
        "onnx_runtime_configurations": ort_results,
        "fastest_configuration": min(ort_results.items(), key=lambda x: x[1]["mean_ms"])[0]
    }
    return report


if __name__ == "__main__":
    print("=" * 80)
    print("ONNX EXPORT & RUNTIME BENCHMARK")
    print("=" * 80)
    out_file = export_rf_to_onnx()
    results = benchmark_sklearn_vs_onnx(num_trials=500)
    print(json.dumps(results, indent=2))
