"""
Production-Grade Apache Kafka Streaming Provider.

Implements IEventStreamProducer and IEventStreamConsumer interfaces.
Provides:
  - Topic partitioning by flow_id / src_ip
  - Consumer groups with manual offset tracking
  - Graceful fallback when Kafka broker is unreachable
"""
import json
import logging
import hashlib
from typing import AsyncGenerator, Optional, List, Dict, Any

from app.pipeline.event_stream import IEventStreamProducer, IEventStreamConsumer
from app.telemetry.schema import NormalizedBaseEvent
from app.alerts.models import SecurityAlert_v2

logger = logging.getLogger(__name__)

# Topic Definitions
TOPIC_TELEMETRY_EVENTS = "sih.telemetry.events"
TOPIC_SECURITY_ALERTS  = "sih.alerts.v2"
DEFAULT_CONSUMER_GROUP = "sih-ml-inference-workers"

class KafkaEventProducer(IEventStreamProducer):
    """
    Kafka Producer that publishes NormalizedBaseEvent to sih.telemetry.events
    using flow_id partition key hashing to guarantee session affinity.
    """
    def __init__(self, bootstrap_servers: str = "localhost:9092", client_id: str = "sih-sensor-producer"):
        self.bootstrap_servers = bootstrap_servers
        self.client_id = client_id
        self._producer = None
        self._connected = False
        self._total_published = 0
        self._mock_buffer: List[Dict[str, Any]] = []

    async def connect(self):
        """Attempts connection to Kafka broker, falls back to standalone buffer if unavailable."""
        try:
            from aiokafka import AIOKafkaProducer
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                client_id=self.client_id,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None
            )
            await self._producer.start()
            self._connected = True
            logger.info(f"[KafkaProducer] Connected to Kafka bootstrap servers: {self.bootstrap_servers}")
        except Exception as e:
            self._connected = False
            logger.info(f"[KafkaProducer] Kafka broker offline ({e}). Running in decoupled fallback mode.")

    def compute_partition(self, key: str, num_partitions: int = 8) -> int:
        """Computes deterministic partition index for flow affinity."""
        hash_val = int(hashlib.md5(key.encode("utf-8")).hexdigest(), 16)
        return hash_val % num_partitions

    async def publish(self, event: NormalizedBaseEvent) -> bool:
        payload = event.model_dump()
        flow_key = f"{event.src_ip}:{event.src_port}->{event.dst_ip}:{event.dst_port}"
        
        if self._connected and self._producer:
            try:
                await self._producer.send_and_wait(
                    topic=TOPIC_TELEMETRY_EVENTS,
                    key=flow_key,
                    value=payload
                )
                self._total_published += 1
                return True
            except Exception as e:
                logger.error(f"[KafkaProducer] Publish error: {e}")
                return False
        else:
            # Fallback buffer for demo/testing
            self._mock_buffer.append({"topic": TOPIC_TELEMETRY_EVENTS, "key": flow_key, "value": payload})
            self._total_published += 1
            return True

    async def publish_batch(self, events: List[NormalizedBaseEvent]) -> int:
        count = 0
        for e in events:
            if await self.publish(e):
                count += 1
        return count

    async def close(self):
        if self._connected and self._producer:
            await self._producer.stop()
            self._connected = False

class KafkaEventConsumer(IEventStreamConsumer):
    """
    Kafka Consumer that subscribes to sih.telemetry.events using a consumer group
    with manual offset commit for at-least-once processing guarantees.
    """
    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        group_id: str = DEFAULT_CONSUMER_GROUP,
        auto_offset_reset: str = "earliest"
    ):
        self.bootstrap_servers = bootstrap_servers
        self.group_id = group_id
        self.auto_offset_reset = auto_offset_reset
        self._consumer = None
        self._connected = False
        self._mock_queue: List[NormalizedBaseEvent] = []

    async def connect(self):
        try:
            from aiokafka import AIOKafkaConsumer
            self._consumer = AIOKafkaConsumer(
                TOPIC_TELEMETRY_EVENTS,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.group_id,
                auto_offset_reset=self.auto_offset_reset,
                enable_auto_commit=False,  # Manual commit on successful inference
                value_deserializer=lambda v: json.loads(v.decode("utf-8"))
            )
            await self._consumer.start()
            self._connected = True
            logger.info(f"[KafkaConsumer] Subscribed to topic '{TOPIC_TELEMETRY_EVENTS}' in group '{self.group_id}'")
        except Exception as e:
            self._connected = False
            logger.info(f"[KafkaConsumer] Kafka broker offline ({e}). Running in decoupled fallback mode.")

    async def subscribe(self) -> AsyncGenerator[NormalizedBaseEvent, None]:
        if self._connected and self._consumer:
            from app.telemetry.schema import (
                NormalizedConnectionEvent, NormalizedDNSEvent,
                NormalizedTLSEvent, NormalizedHTTPEvent, NormalizedSecurityAlert
            )
            type_map = {
                "connection": NormalizedConnectionEvent,
                "dns": NormalizedDNSEvent,
                "tls": NormalizedTLSEvent,
                "http": NormalizedHTTPEvent,
                "alert": NormalizedSecurityAlert
            }
            try:
                async for msg in self._consumer:
                    raw_dict = msg.value
                    event_type = raw_dict.get("event_type", "connection")
                    model_cls = type_map.get(event_type, NormalizedConnectionEvent)
                    event_obj = model_cls(**raw_dict)
                    yield event_obj
                    # Commit offset on successful processing
                    await self._consumer.commit()
            except Exception as e:
                logger.error(f"[KafkaConsumer] Stream error: {e}")
        else:
            for item in list(self._mock_queue):
                yield item

    async def close(self):
        if self._connected and self._consumer:
            await self._consumer.stop()
            self._connected = False
