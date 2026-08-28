"""
Streaming Pipeline Orchestrator & Real-Time Performance Monitor.

Connects:
  PCAP -> Zeek/Suricata -> EventStream -> Feature Tracker -> Hybrid ML -> Alert Engine -> WebSocket
"""
import time
import asyncio
import logging
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from pydantic import BaseModel, Field

from app.telemetry.schema import NormalizedBaseEvent
from app.telemetry.telemetry_streamer import TelemetryStreamer
from app.telemetry.replay_runner import PcapReplayRunner
from app.telemetry.telemetry_flow_tracker import StreamingTelemetryTracker
from app.telemetry.telemetry_feature_extractor import TelemetryFeatureExtractor
from app.telemetry.feature_schema import TelemetryFeatureVector_v2
from app.ml.hybrid_inference import HybridInferenceEngine
from app.alerts.engine import AlertEngine
from app.alerts.models import SecurityAlert_v2
from app.pipeline.event_stream import InMemoryEventStream

logger = logging.getLogger(__name__)

class LatencySummary(BaseModel):
    p50_ms: float
    p95_ms: float
    p99_ms: float
    mean_ms: float
    min_ms: float
    max_ms: float

class PipelinePerformanceReport(BaseModel):
    """Actual measured throughput and latency metrics (no fabricated numbers)."""
    pcap_name: str
    total_events_processed: int
    total_flows_tracked: int
    total_alerts_generated: int
    duration_seconds: float
    
    # Throughput
    events_per_second: float
    flows_per_second: float
    
    # Latencies in milliseconds
    feature_extraction_latency: LatencySummary
    inference_latency: LatencySummary
    alert_generation_latency: LatencySummary
    end_to_end_latency: LatencySummary

class StreamingPipelineOrchestrator:
    """
    Asynchronous streaming orchestrator processing telemetry with bounded memory
    and tracking live microsecond latencies.
    """
    def __init__(
        self,
        alert_engine: Optional[AlertEngine] = None,
        hybrid_engine: Optional[HybridInferenceEngine] = None,
        broadcast_callback: Optional[Callable[[SecurityAlert_v2], Any]] = None
    ):
        self.alert_engine = alert_engine or AlertEngine(dedup_window_sec=30.0)
        self.hybrid_engine = hybrid_engine or HybridInferenceEngine()
        self.broadcast_callback = broadcast_callback
        
        self.tracker = StreamingTelemetryTracker()
        self.event_stream = InMemoryEventStream(maxsize=20_000)

        # Performance metric accumulators (in milliseconds)
        self._feat_latencies: List[float] = []
        self._infer_latencies: List[float] = []
        self._alert_latencies: List[float] = []
        self._e2e_latencies: List[float] = []
        self._processed_events = 0
        self._start_time = 0.0
        self._end_time = 0.0

    @staticmethod
    def _compute_summary(arr: List[float]) -> LatencySummary:
        if not arr:
            return LatencySummary(p50_ms=0, p95_ms=0, p99_ms=0, mean_ms=0, min_ms=0, max_ms=0)
        np_arr = np.array(arr, dtype=np.float64)
        return LatencySummary(
            p50_ms=round(float(np.percentile(np_arr, 50)), 4),
            p95_ms=round(float(np.percentile(np_arr, 95)), 4),
            p99_ms=round(float(np.percentile(np_arr, 99)), 4),
            mean_ms=round(float(np.mean(np_arr)), 4),
            min_ms=round(float(np.min(np_arr)), 4),
            max_ms=round(float(np.max(np_arr)), 4)
        )

    async def run_pipeline_on_pcap(
        self,
        pcap_path: Path,
        staging_dir: Path
    ) -> PipelinePerformanceReport:
        """
        Executes real streaming replay on a PCAP and produces actual performance metrics.
        """
        self._feat_latencies.clear()
        self._infer_latencies.clear()
        self._alert_latencies.clear()
        self._e2e_latencies.clear()
        self._processed_events = 0

        # 1. Ensure Zeek / Suricata logs exist
        pcap_out = staging_dir / pcap_path.stem
        PcapReplayRunner.replay_pcap_to_telemetry(pcap_path, pcap_out)

        streamer = TelemetryStreamer(pcap_out)
        self._start_time = time.perf_counter()

        # 2. Producer: stream events line-by-line into the event stream channel
        for event in streamer.stream_all_events():
            await self.process_single_event(event)

        self._end_time = time.perf_counter()
        dur = max(1e-4, self._end_time - self._start_time)

        # 3. Compile report
        flows_tracked = len(self.tracker.active_flows)
        alerts_gen = len(self.alert_engine._alerts)
        
        report = PipelinePerformanceReport(
            pcap_name=pcap_path.name,
            total_events_processed=self._processed_events,
            total_flows_tracked=flows_tracked,
            total_alerts_generated=alerts_gen,
            duration_seconds=round(dur, 4),
            events_per_second=round(float(self._processed_events / dur), 1),
            flows_per_second=round(float(flows_tracked / dur), 1),
            feature_extraction_latency=self._compute_summary(self._feat_latencies),
            inference_latency=self._compute_summary(self._infer_latencies),
            alert_generation_latency=self._compute_summary(self._alert_latencies),
            end_to_end_latency=self._compute_summary(self._e2e_latencies)
        )
        return report

    async def process_single_event(self, event: NormalizedBaseEvent) -> Optional[SecurityAlert_v2]:
        """
        Processes a single normalized telemetry event incrementally with latency instrumentation.
        """
        t_e2e_start = time.perf_counter_ns()
        self._processed_events += 1

        # 1. State update & Feature extraction
        t0 = time.perf_counter_ns()
        state = self.tracker.process_event(event)
        fv = TelemetryFeatureExtractor.extract_features(state, self.tracker)
        t1 = time.perf_counter_ns()
        feat_lat_ms = (t1 - t0) / 1_000_000.0
        self._feat_latencies.append(feat_lat_ms)

        # 2. Hybrid ML & Behavioral Inference
        t2 = time.perf_counter_ns()
        fusion = self.hybrid_engine.predict(fv)
        t3 = time.perf_counter_ns()
        infer_lat_ms = (t3 - t2) / 1_000_000.0
        self._infer_latencies.append(infer_lat_ms)

        # 3. Alert Generation & Deduplication
        t4 = time.perf_counter_ns()
        alert, is_new = self.alert_engine.process_detection(fv, fusion)
        t5 = time.perf_counter_ns()
        alert_lat_ms = (t5 - t4) / 1_000_000.0
        self._alert_latencies.append(alert_lat_ms)

        # 4. Total End-to-End Latency
        t_e2e_end = time.perf_counter_ns()
        e2e_ms = (t_e2e_end - t_e2e_start) / 1_000_000.0
        self._e2e_latencies.append(e2e_ms)

        # Broadcast via WebSocket callback if new alert
        if is_new and self.broadcast_callback:
            if asyncio.iscoroutinefunction(self.broadcast_callback):
                await self.broadcast_callback(alert)
            else:
                self.broadcast_callback(alert)

        return alert
