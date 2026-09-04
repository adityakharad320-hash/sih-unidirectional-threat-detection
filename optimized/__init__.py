"""
Optimized Unidirectional IP Threat Detection Engine (SIH26145).
High-performance, low-latency, streaming threat analysis pipeline with:
- Fast behavioral pre-screening gate
- Online incremental statistics (Welford's algorithm)
- Tiered selective feature computation
- Dual-backend ML inference (Sklearn & ONNX Runtime)
- Inlined fast linear scaling
- Selective Random Forest & Isolation Forest escalation
- Flow-level adaptive micro-window scheduling
"""
__version__ = "2.1.0-opt"
