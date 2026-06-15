"""
FastAPI application — AegisLab Platform API.

Endpoints
---------
POST /agents/                Create/register an agent definition
GET  /agents/                List registered agents
POST /tasks/                 Submit a new agent task
GET  /tasks/{task_id}        Get task status and trace
POST /tasks/{task_id}/tools  Execute a tool call within a task
GET  /health                 Liveness probe
GET  /metrics/backpressure   Per-agent rate limit / circuit breaker status
GET  /metrics/egress         Egress kill-switch status
POST /admin/reload-policies  Hot-reload policy YAML files
POST /admin/quarantine/{id}  Release an agent from quarantine
GET  /stream/traces          SSE stream of decision trace events
GET  /dashboard              Serve the security dashboard HTML
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncGenerator

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from pydantic import BaseModel
from starlette.middleware.trustedhost import TrustedHostMiddleware

from aegislab.config import get_settings
from aegislab.core.agent import AgentDefinition, AgentScope, get_registry
from aegislab.core.orchestrator import get_orchestrator
from aegislab.defenses.backpressure import get_backpressure
from aegislab.logging.tracer import get_tracer, subscribe_traces, unsubscribe_traces
from aegislab.policy.engine import get_policy_engine
from aegislab.proxy.egress import get_kill_switch

logger = logging.getLogger(__name__)

DASHBOARD_PATH = Path(__file__).parent.parent.parent / "dashboard" / "index.html"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    cfg = get_settings()
    logging.basicConfig(level=cfg.log_level)
    logger.info("AegisLab starting up")
    yield
    logger.info("AegisLab shutting down")


app = FastAPI(
    title="AegisLab",
    description="Secure AI Agent Platform with Deterministic Boundaries",
    version="0.1.0",
    lifespan=lifespan,
    # Suppress the default /docs and /redoc in production to reduce attack surface.
    # Remove these lines during development if you need Swagger UI.
    # docs_url=None,
    # redoc_url=None,
)

# ── Hermes Security Hardening: Bad-Host / Host-Header Injection Fix ───────────
#
# Starlette's request.base_url and request.url are constructed from the Host
# header, which an attacker fully controls.  Without this middleware:
#   • Password-reset emails contain attacker-controlled links (Host poisoning)
#   • Cache-poisoning via malformed Host values
#   • SSRF through server-generated URLs that embed the Host header
#
# TrustedHostMiddleware rejects any request whose Host header is not in the
# allowed list, returning 400 before your route code ever runs.
#
# In production replace "*" with your actual FQDN(s):
#   allowed_hosts=["aegislab.yourdomain.com", "api.yourdomain.com"]
#
# References:
#   • OWASP: Host Header Injection (A01:2021)
#   • Portswigger: "Host header attacks" — https://portswigger.net/web-security/host-header
#   • Starlette issue #1501 — ProxyHeadersMiddleware must sit OUTSIDE
#     TrustedHostMiddleware in the stack; wrong ordering lets X-Forwarded-Host
#     bypass the check.
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.aegislab.internal", "*"],
    # ↑ Tighten "*" to your real domains before deploying to production.
)

# ── Security response headers middleware ──────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):  # type: ignore[type-arg]
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Remove server identification header to reduce information leakage
    response.headers.pop("server", None)
    return response

# CORS — restrict origins in production; "*" is only safe for local dev.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response schemas ────────────────────────────────────────────────

class RegisterAgentRequest(BaseModel):
    agent_id: str
    description: str = ""
    allowed_tools: list[str] = []
    scope: AgentScope = AgentScope.READ
    max_task_duration_seconds: int = 300
    risk_budget: float = 5.0
    require_human_approval_for: list[str] = []
    system_prompt: str = ""


class SubmitTaskRequest(BaseModel):
    agent_id: str
    payload: dict[str, Any] = {}


class ToolCallRequest(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = {}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "aegislab"}


@app.post("/agents/", status_code=status.HTTP_201_CREATED)
async def register_agent(req: RegisterAgentRequest) -> dict[str, Any]:
    defn = AgentDefinition(**req.model_dump())
    get_registry().register(defn)
    return {"agent_id": defn.agent_id, "registered": True}


@app.get("/agents/")
async def list_agents() -> list[dict[str, Any]]:
    return [d.model_dump() for d in get_registry().list_definitions()]


@app.post("/tasks/", status_code=status.HTTP_202_ACCEPTED)
async def submit_task(req: SubmitTaskRequest) -> dict[str, Any]:
    try:
        task = await get_orchestrator().submit_task(req.agent_id, req.payload)
        return {
            "task_id": task.task_id,
            "agent_id": task.agent_id,
            "status": task.status,
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=429, detail=str(exc))


@app.get("/tasks/{task_id}")
async def get_task(task_id: str) -> dict[str, Any]:
    task = get_registry().get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task.model_dump()


@app.post("/tasks/{task_id}/tools")
async def execute_tool(task_id: str, req: ToolCallRequest) -> dict[str, Any]:
    task = get_registry().get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    try:
        call = await get_orchestrator().execute_tool_call(
            task, req.tool_name, req.arguments
        )
        return call.model_dump()
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@app.get("/metrics/backpressure")
async def backpressure_status() -> list[dict[str, Any]]:
    return get_backpressure().status()


@app.get("/metrics/egress")
async def egress_status() -> list[dict[str, Any]]:
    return get_kill_switch().status()


@app.post("/admin/reload-policies")
async def reload_policies() -> dict[str, str]:
    get_policy_engine().reload()
    return {"result": "policies reloaded"}


@app.post("/admin/quarantine/{agent_id}/release")
async def release_quarantine(agent_id: str) -> dict[str, str]:
    await get_backpressure().release_quarantine(agent_id)
    return {"result": f"agent '{agent_id}' released from quarantine"}


@app.get("/stream/traces")
async def stream_traces(request: Request) -> StreamingResponse:
    """Server-Sent Events stream of decision trace events."""
    q = subscribe_traces()

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15.0)
                    data = json.dumps(event.to_log_dict(), default=str)
                    yield f"data: {data}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            unsubscribe_traces(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard() -> FileResponse:
    if not DASHBOARD_PATH.exists():
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return FileResponse(str(DASHBOARD_PATH))


def cli() -> None:
    import uvicorn
    cfg = get_settings()
    uvicorn.run("aegislab.api.main:app", host=cfg.api_host, port=cfg.api_port, reload=True)
