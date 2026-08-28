"""
Resilient Backend Client for Streamlit Dashboard.
Connects to FastAPI server at http://localhost:8000.
If FastAPI server is offline, transparently falls back to direct in-process engines
so the dashboard ALWAYS works seamlessly.
"""
import sys
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import os

logger = logging.getLogger("dashboard_client")

class DashboardApiClient:
    def __init__(self, base_url: Optional[str] = None):
        self.base_url = base_url or os.getenv("BACKEND_API_URL", "http://localhost:8000")
        self._direct_engine = None
        self._direct_orchestrator = None
        self._init_in_process_fallback()

    def _init_in_process_fallback(self):
        try:
            from app.main import global_alert_engine, global_orchestrator
            self._direct_engine = global_alert_engine
            self._direct_orchestrator = global_orchestrator
        except Exception as e:
            logger.warning(f"In-process engine fallback init: {e}")

    def get_system_status(self) -> Dict[str, Any]:
        try:
            import httpx
            resp = httpx.get(f"{self.base_url}/", timeout=1.0)
            if resp.status_code == 200:
                data = resp.json()
                data["backend_mode"] = "FASTAPI_REST"
                return data
        except Exception:
            pass
        return {
            "system": "SIH 2026 AI Cyber Threat Detection Engine",
            "organization": "National Technical Research Organisation (NTRO)",
            "version": "2.0.0",
            "status": "ONLINE (IN-PROCESS)",
            "mode": "PASSIVE_UNIDIRECTIONAL_INSPECTION",
            "backend_mode": "DIRECT_IN_PROCESS"
        }

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        threat_class: Optional[str] = None,
        severity: Optional[str] = None,
        exclude_benign: bool = False
    ) -> List[Dict[str, Any]]:
        try:
            import httpx
            params = {"limit": limit, "offset": offset, "exclude_benign": exclude_benign}
            if threat_class and threat_class != "ALL":
                params["threat_class"] = threat_class
            if severity and severity != "ALL":
                params["severity"] = severity
            resp = httpx.get(f"{self.base_url}/alerts", params=params, timeout=1.5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        # Fallback to direct in-process engine
        if self._direct_engine:
            from app.alerts.models import AlertSeverity
            sev_enum = AlertSeverity(severity) if severity and severity != "ALL" else None
            t_class = threat_class if threat_class and threat_class != "ALL" else None
            alerts = self._direct_engine.get_alerts(
                limit=limit,
                offset=offset,
                threat_class=t_class,
                severity=sev_enum,
                exclude_benign=exclude_benign
            )
            return [a.model_dump() for a in alerts]
        return []

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        try:
            import httpx
            resp = httpx.get(f"{self.base_url}/alerts/{alert_id}", timeout=1.5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        if self._direct_engine:
            alert = self._direct_engine.get_alert_by_id(alert_id)
            return alert.model_dump() if alert else None
        return None

    def get_statistics(self) -> Dict[str, Any]:
        try:
            import httpx
            resp = httpx.get(f"{self.base_url}/statistics", timeout=1.5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        if self._direct_engine:
            return self._direct_engine.get_statistics().model_dump()
        return {
            "total_alerts": 0,
            "total_events_processed": 0,
            "deduplication_savings_ratio": 0.0,
            "severity_breakdown": {},
            "threat_class_breakdown": {},
            "detection_method_breakdown": {},
            "active_threats_count": 0,
            "last_updated_iso": ""
        }

    def trigger_replay(self, pcap_filename: str) -> Dict[str, Any]:
        try:
            import httpx
            resp = httpx.post(f"{self.base_url}/pipeline/replay", json={"pcap_filename": pcap_filename}, timeout=2.0)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        # In-process replay fallback
        if self._direct_orchestrator:
            import asyncio
            from app.config import SAMPLES_DIR, DATA_DIR
            pcap_path = SAMPLES_DIR / pcap_filename
            staging = DATA_DIR / "dash_direct_staging"
            try:
                report = asyncio.run(self._direct_orchestrator.run_pipeline_on_pcap(pcap_path, staging))
                return {
                    "status": "COMPLETED",
                    "pcap": pcap_filename,
                    "report": report.model_dump(),
                    "message": f"Direct in-process replay for {pcap_filename} completed successfully."
                }
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        return {"status": "UNAVAILABLE", "message": "Neither FastAPI server nor in-process orchestrator ready."}
