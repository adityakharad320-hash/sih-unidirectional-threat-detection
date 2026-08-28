"""
Streaming Parser for Suricata EVE JSON Logs (eve.json).

Parses alerts, flows, dns, tls, and http telemetry from Suricata.
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Dict, Any, Optional, Union
from app.telemetry.schema import (
    NormalizedBaseEvent,
    NormalizedConnectionEvent,
    NormalizedDNSEvent,
    NormalizedTLSEvent,
    NormalizedHTTPEvent,
    NormalizedSecurityAlert
)

logger = logging.getLogger(__name__)

class SuricataEveParser:
    """
    Parser for Suricata JSON EVE streams.
    """

    @staticmethod
    def _parse_timestamp(ts_val: Any) -> float:
        if isinstance(ts_val, (int, float)):
            return float(ts_val)
        if isinstance(ts_val, str):
            try:
                # ISO8601 parsing e.g. "2026-08-28T16:30:00.123456+0000"
                dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                return dt.timestamp()
            except Exception:
                pass
        return datetime.now(timezone.utc).timestamp()

    @classmethod
    def stream_eve_file(cls, eve_path: Union[str, Path]) -> Generator[NormalizedBaseEvent, None, None]:
        """
        Incrementally reads an eve.json file and yields normalized telemetry events.
        """
        p = Path(eve_path)
        if not p.exists():
            raise FileNotFoundError(f"Suricata EVE file not found: {p}")

        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for line_idx, line in enumerate(f, 1):
                l = line.strip()
                if not l:
                    continue
                try:
                    data = json.loads(l)
                    event = cls.normalize_eve_event(data, f"eve_{line_idx}")
                    if event is not None:
                        yield event
                except Exception as e:
                    logger.debug(f"Skipping malformed eve line {line_idx}: {e}")

    @classmethod
    def normalize_eve_event(cls, data: Dict[str, Any], fallback_id: str) -> Optional[NormalizedBaseEvent]:
        event_type = data.get("event_type", "").lower()
        ts = cls._parse_timestamp(data.get("timestamp"))
        flow_id_val = str(data.get("flow_id", fallback_id))
        
        src_ip = str(data.get("src_ip", "0.0.0.0"))
        dst_ip = str(data.get("dest_ip", "0.0.0.0"))
        src_port = int(data.get("src_port", 0) or 0)
        dst_port = int(data.get("dest_port", 0) or 0)
        proto = str(data.get("proto", "TCP")).upper()

        # 1. Alert Event
        if event_type == "alert":
            alert_data = data.get("alert", {})
            return NormalizedSecurityAlert(
                event_id=f"alert_{flow_id_val}_{alert_data.get('signature_id', 0)}",
                timestamp=ts,
                source_engine="suricata",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                signature_id=int(alert_data.get("signature_id", 0)),
                signature=str(alert_data.get("signature", "Unknown Signature")),
                category=str(alert_data.get("category", "Security Threat")),
                severity=int(alert_data.get("severity", 3)),
                action=str(alert_data.get("action", "allowed")),
                gid=int(alert_data.get("gid", 1)),
                rev=int(alert_data.get("rev", 1)),
                metadata=alert_data.get("metadata", {})
            )

        # 2. Flow Event
        elif event_type == "flow":
            flow_data = data.get("flow", {})
            return NormalizedConnectionEvent(
                event_id=f"flow_{flow_id_val}",
                timestamp=ts,
                source_engine="suricata",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                duration=float(flow_data.get("age", 0.0) or 0.0),
                orig_bytes=int(flow_data.get("bytes_toserver", 0) or 0),
                resp_bytes=int(flow_data.get("bytes_toclient", 0) or 0),
                orig_pkts=int(flow_data.get("pkts_toserver", 0) or 0),
                resp_pkts=int(flow_data.get("pkts_toclient", 0) or 0),
                conn_state=flow_data.get("state"),
                service=data.get("app_proto")
            )

        # 3. DNS Event
        elif event_type == "dns":
            dns_data = data.get("dns", {})
            answers_list = []
            if "grouped" in dns_data:
                for rtype, records in dns_data.get("grouped", {}).items():
                    if isinstance(records, list):
                        answers_list.extend([str(r) for r in records])
            elif "answers" in dns_data:
                raw_ans = dns_data.get("answers", [])
                if isinstance(raw_ans, list):
                    answers_list = [str(a.get("rdata", "")) for a in raw_ans if isinstance(a, dict)]

            return NormalizedDNSEvent(
                event_id=f"dns_{flow_id_val}",
                timestamp=ts,
                source_engine="suricata",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                trans_id=int(dns_data.get("id", 0) or 0),
                query_name=str(dns_data.get("rrname", "unknown")),
                query_type_name=str(dns_data.get("rrtype", "A")).upper(),
                response_code=int(dns_data.get("rcode", 0) or 0),
                answers=answers_list
            )

        # 4. TLS Event
        elif event_type == "tls":
            tls_data = data.get("tls", {})
            return NormalizedTLSEvent(
                event_id=f"tls_{flow_id_val}",
                timestamp=ts,
                source_engine="suricata",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                version=tls_data.get("version"),
                sni_server_name=tls_data.get("sni"),
                subject=tls_data.get("subject"),
                issuer=tls_data.get("issuerdn"),
                ja3=tls_data.get("ja3", {}).get("hash") if isinstance(tls_data.get("ja3"), dict) else tls_data.get("ja3"),
                ja3s=tls_data.get("ja3s", {}).get("hash") if isinstance(tls_data.get("ja3s"), dict) else tls_data.get("ja3s")
            )

        # 5. HTTP Event
        elif event_type == "http":
            http_data = data.get("http", {})
            return NormalizedHTTPEvent(
                event_id=f"http_{flow_id_val}",
                timestamp=ts,
                source_engine="suricata",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                method=str(http_data.get("http_method", "GET")).upper(),
                host=str(http_data.get("hostname", "")),
                uri=str(http_data.get("url", "/")),
                user_agent=http_data.get("http_user_agent"),
                status_code=int(http_data.get("status", 200) or 200),
                request_body_len=int(http_data.get("length", 0) or 0)
            )

        return None
