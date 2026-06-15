"""
Decision trace writer.

Writes structured TraceEvents to:
  1. A JSONL file on disk (configurable via AEGISLAB_TRACE_LOG_FILE)
  2. An in-process asyncio.Queue for real-time dashboard streaming

All I/O is async and non-blocking.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from pathlib import Path
from typing import Any

import aiofiles

from aegislab.config import get_settings
from aegislab.logging.schema import EventType, TraceEvent

logger = logging.getLogger(__name__)

# Dashboard subscribers (SSE stream)
_subscribers: list[asyncio.Queue[TraceEvent]] = []


def subscribe_traces() -> asyncio.Queue[TraceEvent]:
    q: asyncio.Queue[TraceEvent] = asyncio.Queue(maxsize=500)
    _subscribers.append(q)
    return q


def unsubscribe_traces(q: asyncio.Queue[TraceEvent]) -> None:
    try:
        _subscribers.remove(q)
    except ValueError:
        pass


def _broadcast(event: TraceEvent) -> None:
    for q in list(_subscribers):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass


class DecisionTracer:
    """Writes agent decision traces to JSONL and broadcasts to subscribers."""

    def __init__(self) -> None:
        cfg = get_settings()
        self._log_path = cfg.trace_log_file
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = asyncio.Lock()

    async def _write(self, event: TraceEvent) -> None:
        line = json.dumps(event.to_log_dict(), default=str) + "\n"
        async with self._write_lock:
            async with aiofiles.open(self._log_path, "a") as fh:
                await fh.write(line)
        _broadcast(event)

    def _make_event(
        self,
        event_type: EventType,
        agent_id: str,
        task_id: str,
        **kwargs: Any,
    ) -> TraceEvent:
        return TraceEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            agent_id=agent_id,
            task_id=task_id,
            **kwargs,
        )

    async def record_task_start(self, task: Any) -> None:
        event = self._make_event(
            EventType.TASK_START,
            agent_id=task.agent_id,
            task_id=task.task_id,
            message=f"Task started for agent '{task.agent_id}'",
        )
        await self._write(event)

    async def record_task_end(self, task: Any) -> None:
        event = self._make_event(
            EventType.TASK_END,
            agent_id=task.agent_id,
            task_id=task.task_id,
            message=f"Task ended with status '{task.status}'",
            extra={
                "status": task.status,
                "risk_score_total": task.risk_score_total,
                "duration_seconds": task.duration_seconds(),
                "tool_call_count": len(task.tool_calls),
            },
        )
        await self._write(event)

    async def record_tool_call(self, task: Any, call: Any) -> None:
        event = self._make_event(
            EventType.TOOL_CALL,
            agent_id=task.agent_id,
            task_id=task.task_id,
            tool_name=call.tool_name,
            tool_arguments=call.arguments,
            tool_result=call.result,
            tool_error=call.error,
            policy_verdict=call.policy_decision,
            risk_score=call.risk_score,
            message=(
                f"Tool '{call.tool_name}' → {call.policy_decision}"
                + (f": {call.error}" if call.error else "")
            ),
        )
        await self._write(event)

    async def record_injection_flag(
        self,
        agent_id: str,
        task_id: str,
        score: float,
        patterns: list[str],
        blocked: bool,
    ) -> None:
        event = self._make_event(
            EventType.INJECTION_FLAG,
            agent_id=agent_id,
            task_id=task_id,
            injection_score=score,
            injection_patterns=patterns,
            message=(
                f"Prompt injection {'BLOCKED' if blocked else 'FLAGGED'} "
                f"(score={score:.2f})"
            ),
        )
        await self._write(event)

    async def record_egress(
        self,
        agent_id: str,
        task_id: str,
        url: str,
        method: str,
        allowed: bool,
        status: int | None = None,
        reason: str = "",
    ) -> None:
        event = self._make_event(
            EventType.EGRESS_EVENT,
            agent_id=agent_id,
            task_id=task_id,
            egress_url=url,
            egress_method=method,
            egress_allowed=allowed,
            egress_status=status,
            message=(
                f"Egress {method} {url} → {'ALLOWED' if allowed else 'BLOCKED'}"
                + (f": {reason}" if reason else "")
            ),
        )
        await self._write(event)

    async def record_approval_request(
        self,
        agent_id: str,
        task_id: str,
        tool_name: str,
        reason: str,
    ) -> None:
        event = self._make_event(
            EventType.APPROVAL_REQUEST,
            agent_id=agent_id,
            task_id=task_id,
            tool_name=tool_name,
            message=f"Human approval required for tool '{tool_name}': {reason}",
        )
        await self._write(event)


_tracer: DecisionTracer | None = None


def get_tracer() -> DecisionTracer:
    global _tracer
    if _tracer is None:
        _tracer = DecisionTracer()
    return _tracer
