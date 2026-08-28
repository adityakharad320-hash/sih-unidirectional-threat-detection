"""
Unit Tests for Pluggable Kafka Streaming Layer.
Tests topic payload serialization, partition key hashing, and fallback mechanics.
"""
import pytest
from app.pipeline.kafka_stream import (
    KafkaEventProducer, KafkaEventConsumer,
    TOPIC_TELEMETRY_EVENTS, TOPIC_SECURITY_ALERTS
)
from app.telemetry.schema import NormalizedConnectionEvent

@pytest.mark.anyio
async def test_kafka_producer_partition_hashing():
    producer = KafkaEventProducer()
    
    # Same flow should always hash to the same partition
    flow_1 = "192.168.1.100:54321->10.0.0.1:80"
    p1 = producer.compute_partition(flow_1, num_partitions=8)
    p2 = producer.compute_partition(flow_1, num_partitions=8)
    assert p1 == p2
    assert 0 <= p1 < 8

    # Different flows can hash across different partitions
    flow_2 = "172.16.4.32:65519->10.0.0.1:80"
    p3 = producer.compute_partition(flow_2, num_partitions=8)
    assert 0 <= p3 < 8

@pytest.mark.anyio
async def test_kafka_producer_publish_fallback():
    producer = KafkaEventProducer(bootstrap_servers="localhost:9092")
    await producer.connect()  # will enter fallback mode gracefully if broker offline

    event = NormalizedConnectionEvent(
        event_id="test_evt_1",
        timestamp=1724832000.0,
        source_engine="zeek",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        protocol="TCP"
    )

    success = await producer.publish(event)
    assert success is True
    assert producer._total_published == 1
    await producer.close()
