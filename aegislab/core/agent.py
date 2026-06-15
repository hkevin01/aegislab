"""
Agent data models and lifecycle management.

An Agent is a named, versioned definition. A Task is a single invocation of
an agent — it gets its own identity token, sandbox, and decision trace.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AgentScope(str, Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    QUARANTINED = "quarantined"
    AWAITING_APPROVAL = "awaiting_approval"


class AgentDefinition(BaseModel):
    """Static description of an agent type loaded from policy YAML."""

    agent_id: str
    description: str = ""
    allowed_tools: list[str] = Field(default_factory=list)
    scope: AgentScope = AgentScope.READ
    max_task_duration_seconds: int = 300
    risk_budget: float = Field(default=1.0, ge=0.0, le=10.0)
    require_human_approval_for: list[str] = Field(default_factory=list)
    system_prompt: str = ""


class ToolCall(BaseModel):
    """A single tool invocation recorded in a task trace."""

    call_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: Any = None
    error: str | None = None
    policy_decision: str = "allow"   # allow | deny | escalated
    risk_score: float = 0.0
    duration_ms: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))


class Task(BaseModel):
    """A single running invocation of an agent."""

    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    status: AgentStatus = AgentStatus.PENDING
    token: str = ""                # short-lived identity JWT
    container_id: str | None = None
    input_payload: dict[str, Any] = Field(default_factory=dict)
    output_payload: dict[str, Any] = Field(default_factory=dict)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    risk_score_total: float = 0.0
    injection_flags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None

    def record_tool_call(self, call: ToolCall) -> None:
        self.tool_calls.append(call)
        self.risk_score_total += call.risk_score

    def duration_seconds(self) -> float | None:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class AgentRegistry:
    """In-memory registry of agent definitions and active tasks."""

    def __init__(self) -> None:
        self._definitions: dict[str, AgentDefinition] = {}
        self._tasks: dict[str, Task] = {}
        self._lock = asyncio.Lock()

    def register(self, definition: AgentDefinition) -> None:
        self._definitions[definition.agent_id] = definition

    def get_definition(self, agent_id: str) -> AgentDefinition | None:
        return self._definitions.get(agent_id)

    def list_definitions(self) -> list[AgentDefinition]:
        return list(self._definitions.values())

    async def create_task(self, agent_id: str, input_payload: dict[str, Any]) -> Task:
        async with self._lock:
            defn = self._definitions.get(agent_id)
            if defn is None:
                raise ValueError(f"Unknown agent: {agent_id!r}")
            task = Task(agent_id=agent_id, input_payload=input_payload)
            self._tasks[task.task_id] = task
            return task

    async def update_task(self, task: Task) -> None:
        async with self._lock:
            self._tasks[task.task_id] = task

    def get_task(self, task_id: str) -> Task | None:
        return self._tasks.get(task_id)

    def list_tasks(self, status: AgentStatus | None = None) -> list[Task]:
        tasks = list(self._tasks.values())
        if status is not None:
            tasks = [t for t in tasks if t.status == status]
        return tasks

    def active_count(self) -> int:
        return sum(1 for t in self._tasks.values() if t.status == AgentStatus.RUNNING)


_registry: AgentRegistry | None = None


def get_registry() -> AgentRegistry:
    global _registry
    if _registry is None:
        _registry = AgentRegistry()
    return _registry
