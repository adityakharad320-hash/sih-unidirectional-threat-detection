"""
Unit & Integration Tests for Event Stream Abstraction & Streaming Pipeline Orchestrator.
"""
import pytest
import asyncio
from pathlib import Path
from app.pipeline.event_stream import InMemoryEventStream
from app.pipeline.orchestrator import StreamingPipelineOrchestrator
from app.telemetry.schema import NormalizedConnectionEvent
from app.config import SAMPLES_DIR, DATA_DIR

@pytest.mark.anyio
async def test_in_memory_event_stream_publish_and_subscribe():
    stream = InMemoryEventStream(maxsize=10)
    event = NormalizedConnectionEvent(
        event_id="conn_1",
        timestamp=1724832000.0,
        source_engine="zeek",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        orig_pkts=1,
        orig_bytes=54
    )
    published = await stream.publish(event)
    assert published is True

    # Check metrics
    metrics = stream.get_stream_metrics()
    assert metrics["total_published"] == 1
    assert metrics["queue_size"] == 1

    # Consume single event
    consumed_events = []
    async for e in stream.subscribe():
        consumed_events.append(e)
        break  # consume one

    assert len(consumed_events) == 1
    assert consumed_events[0].event_id == "conn_1"

@pytest.mark.anyio
async def test_event_stream_backpressure_drop():
    stream = InMemoryEventStream(maxsize=2)
    e1 = NormalizedConnectionEvent(event_id="c1", timestamp=1.0, source_engine="zeek", src_ip="1.1.1.1", dst_ip="2.2.2.2")
    e2 = NormalizedConnectionEvent(event_id="c2", timestamp=1.0, source_engine="zeek", src_ip="1.1.1.1", dst_ip="2.2.2.2")
    e3 = NormalizedConnectionEvent(event_id="c3", timestamp=1.0, source_engine="zeek", src_ip="1.1.1.1", dst_ip="2.2.2.2")

    assert await stream.publish(e1, timeout=0.1) is True
    assert await stream.publish(e2, timeout=0.1) is True
    # Third event exceeds capacity -> timeout & drop
    assert await stream.publish(e3, timeout=0.05) is False

    metrics = stream.get_stream_metrics()
    assert metrics["dropped_events"] == 1

@pytest.mark.anyio
async def test_streaming_pipeline_orchestrator_on_syn_flood(tmp_path):
    orchestrator = StreamingPipelineOrchestrator()
    syn_pcap = SAMPLES_DIR / "syn_flood.pcap"
    staging = tmp_path / "stream_staging"

    report = await orchestrator.run_pipeline_on_pcap(syn_pcap, staging)
    assert report.total_events_processed > 0
    assert report.total_flows_tracked > 0
    assert report.events_per_second > 0
    
    # Latencies must be non-negative valid floats
    assert report.feature_extraction_latency.mean_ms >= 0.0
    assert report.inference_latency.mean_ms >= 0.0
    assert report.end_to_end_latency.p95_ms >= 0.0
