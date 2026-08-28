"""
Event Stream Abstraction Layer.

Decouples ingestion sensors from AI/ML consumers.
Supports in-memory bounded queues with backpressure and provides
a pluggable interface for future Apache Kafka or Redis Streams integration.
"""
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import AsyncGenerator, Optional, List, Dict, Any
from app.telemetry.schema import NormalizedBaseEvent

logger = logging.getLogger(__name__)

class IEventStreamProducer(ABC):
    """Interface for publishing normalized telemetry events to the pipeline."""
    @abstractmethod
    async def publish(self, event: NormalizedBaseEvent) -> bool:
        pass

    @abstractmethod
    async def publish_batch(self, events: List[NormalizedBaseEvent]) -> int:
        pass

class IEventStreamConsumer(ABC):
    """Interface for consuming normalized telemetry events from the pipeline."""
    @abstractmethod
    async def subscribe(self) -> AsyncGenerator[NormalizedBaseEvent, None]:
        pass

class InMemoryEventStream(IEventStreamProducer, IEventStreamConsumer):
    """
    High-performance in-memory async event channel with bounded capacity
    and backpressure handling.
    """
    def __init__(self, maxsize: int = 10_000):
        self.maxsize = maxsize
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._is_closed = False
        self._total_published = 0
        self._total_consumed = 0
        self._dropped_events = 0

    async def publish(self, event: NormalizedBaseEvent, timeout: float = 2.0) -> bool:
        """Publish a single event with backpressure timeout."""
        if self._is_closed:
            return False
        try:
            await asyncio.wait_for(self._queue.put(event), timeout=timeout)
            self._total_published += 1
            return True
        except asyncio.TimeoutError:
            self._dropped_events += 1
            logger.warning(f"[EventStream] Backpressure: Queue full ({self._queue.qsize()}/{self.maxsize}). Dropping event.")
            return False

    async def publish_batch(self, events: List[NormalizedBaseEvent], timeout: float = 5.0) -> int:
        """Publish a batch of events."""
        success = 0
        for e in events:
            if await self.publish(e, timeout=timeout):
                success += 1
        return success

    async def subscribe(self) -> AsyncGenerator[NormalizedBaseEvent, None]:
        """Async generator yielding events from the stream."""
        while not self._is_closed or not self._queue.empty():
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=0.1)
                self._total_consumed += 1
                yield event
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    def close(self):
        """Signals completion of the event stream."""
        self._is_closed = True

    def get_stream_metrics(self) -> Dict[str, Any]:
        return {
            "queue_size": self._queue.qsize(),
            "max_capacity": self.maxsize,
            "total_published": self._total_published,
            "total_consumed": self._total_consumed,
            "dropped_events": self._dropped_events,
            "is_closed": self._is_closed
        }
