"""
Structured decision trace schema.

Every significant event in an agent task lifecycle is recorded as a
TraceEvent and serialized to JSONL. The schema is designed so that:

  - You can reconstruct the full decision tree for any task
  - Anomaly detection can query fields like risk_score, tool, verdict
  - Compliance auditors can answer: who, what, when, where, why

Event types
-----------
TASK_START        : task created, identity issued
TASK_END          : task completed/failed/quarantined
TOOL_CALL         : a tool was invoked (or denied)
INJECTION_FLAG    : prompt injection classifier raised an alert
POLICY_DECISION   : policy engine verdict
EGRESS_EVENT      : outbound network request (allowed or blocked)
APPROVAL_REQUEST  : human-in-the-loop escalation triggered
CIRCUIT_BREAKER   : circuit breaker state change
KILL_SWITCH       : kill switch activated or released
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    TASK_START = "TASK_START"
    TASK_END = "TASK_END"
    TOOL_CALL = "TOOL_CALL"
    INJECTION_FLAG = "INJECTION_FLAG"
    POLICY_DECISION = "POLICY_DECISION"
    EGRESS_EVENT = "EGRESS_EVENT"
    APPROVAL_REQUEST = "APPROVAL_REQUEST"
    CIRCUIT_BREAKER = "CIRCUIT_BREAKER"
    KILL_SWITCH = "KILL_SWITCH"


class TraceEvent(BaseModel):
    """
    A single auditable event in the AegisLab trace stream.
    Serializes to JSON for JSONL storage and downstream analysis.
    """

    event_id: str
    event_type: EventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    agent_id: str
    task_id: str

    # Tool call fields
    tool_name: str | None = None
    tool_arguments: dict[str, Any] | None = None
    tool_result: Any = None
    tool_error: str | None = None

    # Policy / risk
    policy_verdict: str | None = None   # allow | deny | escalate
    risk_score: float | None = None
    policy_reason: str | None = None

    # Injection
    injection_score: float | None = None
    injection_patterns: list[str] | None = None

    # Egress
    egress_url: str | None = None
    egress_method: str | None = None
    egress_allowed: bool | None = None
    egress_status: int | None = None

    # General
    message: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)

    def to_log_dict(self) -> dict[str, Any]:
        """Return a flat dict suitable for JSONL serialization."""
        data = self.model_dump(exclude_none=True)
        data["timestamp"] = self.timestamp.isoformat()
        data["event_type"] = self.event_type.value
        return data
