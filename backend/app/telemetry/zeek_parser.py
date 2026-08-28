"""
Streaming Parser for Zeek (Bro) Log Files.

Handles both:
1. Standard Zeek ASCII TSV format (with #separator, #fields, #types, and '-' null values).
2. Zeek JSON format (streaming NDJSON).
"""
import json
import logging
from pathlib import Path
from typing import Generator, Dict, Any, List, Optional, Union
from app.telemetry.schema import (
    NormalizedConnectionEvent,
    NormalizedDNSEvent,
    NormalizedTLSEvent,
    NormalizedHTTPEvent,
    NormalizedBaseEvent
)

logger = logging.getLogger(__name__)

class ZeekLogParser:
    """
    Robust, streaming line-by-line parser for Zeek network monitoring logs.
    """

    @classmethod
    def _parse_tsv_line(cls, line: str, fields: List[str], separator: str) -> Optional[Dict[str, Any]]:
        parts = line.rstrip("\r\n").split(separator)
        if len(parts) != len(fields):
            return None
        
        row = {}
        for f, val in zip(fields, parts):
            if val == "-" or val == "(empty)":
                row[f] = None
            else:
                row[f] = val
        return row

    @classmethod
    def stream_log_file(cls, log_path: Union[str, Path]) -> Generator[Dict[str, Any], None, None]:
        """
        Incrementally stream raw rows from a Zeek log file (TSV or JSON).
        """
        p = Path(log_path)
        if not p.exists():
            raise FileNotFoundError(f"Zeek log file not found: {p}")

        with open(p, "r", encoding="utf-8", errors="replace") as f:
            first_line = f.readline()
            if not first_line:
                return

            # Check if file is JSON (starts with '{')
            stripped = first_line.strip()
            if stripped.startswith("{"):
                try:
                    yield json.loads(stripped)
                    for line in f:
                        l = line.strip()
                        if l:
                            try:
                                yield json.loads(l)
                            except Exception as e:
                                logger.warning(f"Skipping malformed JSON line: {e}")
                    return
                except Exception:
                    pass  # Fall back to TSV parsing

            # TSV Header parsing
            separator = "\t"
            fields = []
            f.seek(0)

            for line in f:
                if line.startswith("#separator"):
                    # Zeek hex separator format e.g. #separator \x09
                    raw_sep = line.strip().split()[-1]
                    if raw_sep.startswith("\\x"):
                        try:
                            separator = bytes.fromhex(raw_sep[2:]).decode("ascii")
                        except Exception:
                            separator = "\t"
                    continue
                elif line.startswith("#fields"):
                    fields = line.strip().split()[1:]
                    continue
                elif line.startswith("#types") or line.startswith("#open") or line.startswith("#close"):
                    continue
                elif line.startswith("#"):
                    continue

                if not fields:
                    continue

                parsed = cls._parse_tsv_line(line, fields, separator)
                if parsed is not None:
                    yield parsed

    # ── Specialized Normalizers ──────────────────────────────────────────────

    @staticmethod
    def _safe_float(val: Any, default: float = 0.0) -> float:
        try:
            return float(val) if val is not None else default
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _safe_int(val: Any, default: int = 0) -> int:
        try:
            return int(float(val)) if val is not None else default
        except (ValueError, TypeError):
            return default

    @classmethod
    def normalize_conn_record(cls, row: Dict[str, Any], file_name: str = "conn.log") -> Optional[NormalizedConnectionEvent]:
        try:
            ts = cls._safe_float(row.get("ts"))
            uid = row.get("uid", f"conn_{ts}")
            src_ip = str(row.get("id.orig_h") or row.get("orig_h") or "0.0.0.0")
            dst_ip = str(row.get("id.resp_h") or row.get("resp_h") or "0.0.0.0")
            src_port = cls._safe_int(row.get("id.orig_p") or row.get("orig_p"))
            dst_port = cls._safe_int(row.get("id.resp_p") or row.get("resp_p"))
            proto = str(row.get("proto") or "TCP").upper()

            return NormalizedConnectionEvent(
                event_id=uid,
                timestamp=ts,
                source_engine="zeek",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                duration=cls._safe_float(row.get("duration")),
                orig_bytes=cls._safe_int(row.get("orig_bytes")),
                resp_bytes=cls._safe_int(row.get("resp_bytes")),
                orig_pkts=cls._safe_int(row.get("orig_pkts")),
                resp_pkts=cls._safe_int(row.get("resp_pkts")),
                conn_state=row.get("conn_state"),
                history=row.get("history"),
                service=row.get("service"),
                missed_bytes=cls._safe_int(row.get("missed_bytes"))
            )
        except Exception as e:
            logger.warning(f"Error normalizing conn record: {e}")
            return None

    @classmethod
    def normalize_dns_record(cls, row: Dict[str, Any]) -> Optional[NormalizedDNSEvent]:
        try:
            ts = cls._safe_float(row.get("ts"))
            uid = row.get("uid", f"dns_{ts}")
            src_ip = str(row.get("id.orig_h") or row.get("orig_h") or "0.0.0.0")
            dst_ip = str(row.get("id.resp_h") or row.get("resp_h") or "0.0.0.0")
            src_port = cls._safe_int(row.get("id.orig_p") or row.get("orig_p"))
            dst_port = cls._safe_int(row.get("id.resp_p") or row.get("resp_p"), default=53)
            proto = str(row.get("proto") or "UDP").upper()

            # Answers split
            answers_raw = row.get("answers")
            answers: List[str] = []
            if isinstance(answers_raw, list):
                answers = [str(a) for a in answers_raw]
            elif isinstance(answers_raw, str) and answers_raw:
                answers = [a.strip() for a in answers_raw.split(",") if a.strip()]

            qname = str(row.get("query") or "unknown")
            qtype_name = str(row.get("qtype_name") or "A").upper()

            return NormalizedDNSEvent(
                event_id=uid,
                timestamp=ts,
                source_engine="zeek",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                trans_id=cls._safe_int(row.get("trans_id")),
                query_name=qname,
                query_type=cls._safe_int(row.get("qtype")),
                query_type_name=qtype_name,
                response_code=cls._safe_int(row.get("rcode")),
                response_code_name=str(row.get("rcode_name") or "NOERROR"),
                answers=answers,
                rejected=bool(row.get("rejected", False))
            )
        except Exception as e:
            logger.warning(f"Error normalizing dns record: {e}")
            return None

    @classmethod
    def normalize_ssl_record(cls, row: Dict[str, Any]) -> Optional[NormalizedTLSEvent]:
        try:
            ts = cls._safe_float(row.get("ts"))
            uid = row.get("uid", f"ssl_{ts}")
            src_ip = str(row.get("id.orig_h") or row.get("orig_h") or "0.0.0.0")
            dst_ip = str(row.get("id.resp_h") or row.get("resp_h") or "0.0.0.0")
            src_port = cls._safe_int(row.get("id.orig_p") or row.get("orig_p"))
            dst_port = cls._safe_int(row.get("id.resp_p") or row.get("resp_p"), default=443)

            return NormalizedTLSEvent(
                event_id=uid,
                timestamp=ts,
                source_engine="zeek",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol="TCP",
                version=row.get("version"),
                cipher=row.get("cipher"),
                sni_server_name=row.get("server_name"),
                established=bool(row.get("established", False)),
                resumed=bool(row.get("resumed", False)),
                ja3=row.get("ja3"),
                ja3s=row.get("ja3s"),
                validation_status=row.get("validation_status"),
                subject=row.get("subject"),
                issuer=row.get("issuer")
            )
        except Exception as e:
            logger.warning(f"Error normalizing ssl record: {e}")
            return None

    @classmethod
    def normalize_http_record(cls, row: Dict[str, Any]) -> Optional[NormalizedHTTPEvent]:
        try:
            ts = cls._safe_float(row.get("ts"))
            uid = row.get("uid", f"http_{ts}")
            src_ip = str(row.get("id.orig_h") or row.get("orig_h") or "0.0.0.0")
            dst_ip = str(row.get("id.resp_h") or row.get("resp_h") or "0.0.0.0")
            src_port = cls._safe_int(row.get("id.orig_p") or row.get("orig_p"))
            dst_port = cls._safe_int(row.get("id.resp_p") or row.get("resp_p"), default=80)

            return NormalizedHTTPEvent(
                event_id=uid,
                timestamp=ts,
                source_engine="zeek",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol="TCP",
                method=str(row.get("method") or "GET").upper(),
                host=str(row.get("host") or ""),
                uri=str(row.get("uri") or "/"),
                user_agent=row.get("user_agent"),
                status_code=cls._safe_int(row.get("status_code"), default=200),
                status_msg=row.get("status_msg"),
                request_body_len=cls._safe_int(row.get("request_body_len")),
                response_body_len=cls._safe_int(row.get("response_body_len")),
                mime_type=row.get("resp_mime_types")
            )
        except Exception as e:
            logger.warning(f"Error normalizing http record: {e}")
            return None
