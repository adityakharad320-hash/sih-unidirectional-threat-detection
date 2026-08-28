"""
FastAPI Server for SIH 2026 AI Cybersecurity Threat Detection Engine.

Endpoints:
  GET   /                   — Health check & system overview
  GET   /alerts             — Paginated alert queries with filtering
  GET   /alerts/{id}        — Single alert lookup
  GET   /statistics         — Aggregated threat statistics
  POST  /pipeline/replay    — Asynchronous PCAP replay through streaming pipeline
  GET   /pipeline/metrics   — Real-time streaming pipeline performance & latency metrics
  WS    /ws/alerts          — Real-time alert streaming WebSocket
"""
import asyncio
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException, Path as FPath, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.alerts.models import SecurityAlert_v2, AlertSeverity, AlertStatistics
from app.alerts.engine import AlertEngine
from app.ml.hybrid_inference import HybridInferenceEngine
from app.pipeline.orchestrator import StreamingPipelineOrchestrator, PipelinePerformanceReport
from app.config import SAMPLES_DIR, DATA_DIR

logger = logging.getLogger("api")

# Global Singleton Alert Engine & WebSocket Manager
global_alert_engine = AlertEngine(dedup_window_sec=30.0)

class ConnectionManager:
    """Manages active WebSocket client connections for real-time alert broadcasts."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast_alert(self, alert: SecurityAlert_v2):
        if not self.active_connections:
            return
        payload = alert.model_dump_json()
        async with self._lock:
            stale = []
            for ws in self.active_connections:
                try:
                    await ws.send_text(payload)
                except Exception:
                    stale.append(ws)
            for s in stale:
                if s in self.active_connections:
                    self.active_connections.remove(s)

ws_manager = ConnectionManager()

# Global Streaming Pipeline Orchestrator with WebSocket broadcast callback
global_orchestrator = StreamingPipelineOrchestrator(
    alert_engine=global_alert_engine,
    broadcast_callback=ws_manager.broadcast_alert
)

# Latest performance report store
latest_pipeline_reports: Dict[str, Any] = {}

class ReplayRequest(BaseModel):
    pcap_filename: str = Field(default="syn_flood.pcap", description="PCAP file to replay from samples directory")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SIH 2026 Threat Detection FastAPI Backend ...")
    yield
    logger.info("Shutting down FastAPI Backend.")

app = FastAPI(
    title="SIH 2026 AI Cyber Threat Detection Engine API",
    description="Passive Unidirectional Network Security Telemetry & AI Threat Detection Platform",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", tags=["System"])
async def root():
    return {
        "system": "SIH 2026 AI Cyber Threat Detection Engine",
        "organization": "National Technical Research Organisation (NTRO)",
        "version": "2.0.0",
        "status": "ONLINE",
        "mode": "PASSIVE_UNIDIRECTIONAL_INSPECTION",
        "endpoints": {
            "alerts": "/alerts",
            "statistics": "/statistics",
            "pipeline_replay": "/pipeline/replay",
            "pipeline_metrics": "/pipeline/metrics",
            "websocket_stream": "/ws/alerts",
            "docs": "/docs"
        }
    }

@app.get("/alerts", response_model=List[SecurityAlert_v2], tags=["Alerts"])
async def get_alerts(
    limit: int = Query(default=50, ge=1, le=500, description="Max alerts to return"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    threat_class: Optional[str] = Query(default=None, description="Filter by threat class e.g. DDOS, PORT_SCAN"),
    severity: Optional[AlertSeverity] = Query(default=None, description="Filter by severity level"),
    exclude_benign: bool = Query(default=False, description="Exclude normal benign sessions from results")
):
    """Retrieve security alerts with optional class, severity, and pagination filters."""
    alerts = global_alert_engine.get_alerts(
        limit=limit,
        offset=offset,
        threat_class=threat_class,
        severity=severity,
        exclude_benign=exclude_benign
    )
    return alerts

@app.get("/alerts/{alert_id}", response_model=SecurityAlert_v2, tags=["Alerts"])
async def get_alert_by_id(
    alert_id: str = FPath(..., description="Unique alert ID e.g. ALT-20260828-ABCD1234")
):
    """Retrieve full details and supporting evidence for a specific alert."""
    alert = global_alert_engine.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found.")
    return alert

@app.get("/statistics", response_model=AlertStatistics, tags=["Statistics"])
async def get_statistics():
    """Retrieve aggregated threat statistics, severity breakdowns, and deduplication metrics."""
    return global_alert_engine.get_statistics()

@app.post("/pipeline/replay", tags=["Pipeline"])
async def trigger_pcap_replay(req: ReplayRequest, background_tasks: BackgroundTasks):
    """Triggers streaming replay of a PCAP file through the AI pipeline."""
    pcap_path = SAMPLES_DIR / req.pcap_filename
    if not pcap_path.exists():
        raise HTTPException(status_code=404, detail=f"PCAP sample '{req.pcap_filename}' not found.")

    async def _run_replay():
        report = await global_orchestrator.run_pipeline_on_pcap(
            pcap_path=pcap_path,
            staging_dir=DATA_DIR / "api_pipeline_staging"
        )
        latest_pipeline_reports[req.pcap_filename] = report.model_dump()

    background_tasks.add_task(_run_replay)
    return {
        "status": "PROCESSING_STARTED",
        "pcap": req.pcap_filename,
        "message": f"PCAP '{req.pcap_filename}' streaming replay launched in background. Alerts will stream to /ws/alerts."
    }

@app.get("/pipeline/metrics", tags=["Pipeline"])
async def get_pipeline_metrics():
    """Retrieve real-time streaming pipeline throughput and latency statistics."""
    stream_metrics = global_orchestrator.event_stream.get_stream_metrics()
    return {
        "event_stream": stream_metrics,
        "latest_reports": latest_pipeline_reports
    }

@app.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time live alert streaming to SOC dashboards."""
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as e:
        logger.debug(f"WebSocket exception: {e}")
        await ws_manager.disconnect(websocket)
