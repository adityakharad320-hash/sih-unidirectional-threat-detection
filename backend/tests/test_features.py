import pytest
import numpy as np
from app.core.feature_extractor import StreamingFeatureExtractor
from app.core.feature_schema import FeatureVector_v1, ORDERED_FEATURE_NAMES

def test_shannon_entropy():
    # Low entropy (repeated char)
    assert StreamingFeatureExtractor.shannon_entropy("aaaaaa") == 0.0
    
    # High entropy (random hex DGA string)
    dga_entropy = StreamingFeatureExtractor.shannon_entropy("xq89zlkj4v91a0c8")
    assert dga_entropy > 3.5

def test_dga_ngram_score():
    # English word domain
    eng_score = StreamingFeatureExtractor.calculate_dga_ngram_score("weatherforecast.com")
    # Random DGA domain
    dga_score = StreamingFeatureExtractor.calculate_dga_ngram_score("xq89zlkj4v91a0c8.badc2.org")
    
    assert eng_score > dga_score

def test_beaconing_signal_features():
    # Synthetic periodic timestamps with 1.0s interval and tiny jitter
    base = 1000.0
    timestamps = [base + i * 1.0 + np.random.uniform(-0.01, 0.01) for i in range(20)]
    
    mean, std, cv, skew, fft_peak, autocorr = StreamingFeatureExtractor.calculate_beaconing_signal_features(timestamps)
    
    assert 0.95 <= mean <= 1.05
    assert cv < 0.05  # Very low jitter
    assert fft_peak > 0.1  # Spectral peak present

def test_feature_vector_schema_and_numpy():
    fv = FeatureVector_v1(
        flow_id="10.0.0.1:1234 -> 10.0.0.2:80 [TCP]",
        timestamp=1724832000.0,
        syn_ratio=0.98,
        packet_rate=1500.0
    )
    d = fv.to_dict()
    assert d["syn_ratio"] == 0.98
    assert d["packet_rate"] == 1500.0
    
    arr = fv.to_numpy()
    assert isinstance(arr, np.ndarray)
    assert len(arr) == len(ORDERED_FEATURE_NAMES)
