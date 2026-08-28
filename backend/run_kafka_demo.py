"""
Interactive Demonstration: Pluggable Kafka Architecture.
Demonstrates:
  1. Topic schemas (sih.telemetry.events & sih.alerts.v2)
  2. Partition key affinity hashing for session tracking
  3. Consumer group offset management simulation
"""
import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.pipeline.kafka_stream import (
    KafkaEventProducer, KafkaEventConsumer,
    TOPIC_TELEMETRY_EVENTS, TOPIC_SECURITY_ALERTS, DEFAULT_CONSUMER_GROUP
)
from app.telemetry.schema import NormalizedConnectionEvent

async def run_demo():
    print("=" * 95)
    print("PLUGGABLE APACHE KAFKA ARCHITECTURE & PARTITIONING DEMONSTRATION")
    print("=" * 95)

    print(f"\n[+] TOPIC ARCHITECTURE:")
    print(f"    * Raw Telemetry Ingestion Topic: '{TOPIC_TELEMETRY_EVENTS}' (8 Partitions, Retention: 24h)")
    print(f"    * Processed Threat Alerts Topic: '{TOPIC_SECURITY_ALERTS}' (4 Partitions, Retention: 7d)")
    print(f"    * Default Consumer Group:        '{DEFAULT_CONSUMER_GROUP}'")

    producer = KafkaEventProducer()
    await producer.connect()

    sample_flows = [
        ("192.168.1.100:54321 -> 142.250.190.46:443 [TCP]", "Benign HTTPS Session"),
        ("172.16.4.32:65519 -> 10.0.0.1:80 [TCP]",          "SYN Flood Attack Stream"),
        ("192.168.1.50:51722 -> 192.168.1.1:69 [TCP]",       "Port Scan Probe"),
        ("192.168.1.75:51696 -> 8.8.8.8:53 [UDP]",           "DGA DNS Tunnel"),
        ("10.0.5.12:49152 -> 198.51.100.42:8443 [TCP]",      "C2 Cobalt Strike Heartbeat")
    ]

    print(f"\n[+] PARTITION AFFINITY & ROUTING DEMONSTRATION (8 Partitions):")
    for flow_str, description in sample_flows:
        partition = producer.compute_partition(flow_str, num_partitions=8)
        print(f"    Flow: [{flow_str:<50}] -> Partition {partition} ({description})")

    print("\n[+] CONSUMER GROUP OFFSET COMMIT SIMULATION:")
    print(f"    - Worker consumer group '{DEFAULT_CONSUMER_GROUP}' uses manual offset commit on successful alert generation.")
    print(f"    - Enables at-least-once processing guarantees and time-travel replay without altering ML code.")
    print("=" * 95)
    await producer.close()

if __name__ == "__main__":
    asyncio.run(run_demo())
