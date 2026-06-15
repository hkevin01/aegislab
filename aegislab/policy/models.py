"""
Policy data models.

Policies are loaded from YAML files and validated here.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class RateLimit(BaseModel):
    requests_per_minute: int = 60
    burst: int = 10


class ToolPolicy(BaseModel):
    """
    Per-tool allow/deny policy.

    Evaluation order:
      1. Explicit deny rules (first match → DENY)
      2. Explicit allow rules (first match → ALLOW)
      3. default_action fallback
    """

    tool: str
    description: str = ""
    default_action: str = "deny"        # allow | deny
    allow: dict[str, Any] = Field(default_factory=dict)
    deny: dict[str, Any] = Field(default_factory=dict)
    rate_limit: RateLimit = Field(default_factory=RateLimit)
    require_human_approval: list[dict[str, Any]] = Field(default_factory=list)
    risk_weight: float = Field(default=1.0, ge=0.0, le=10.0)


class AgentPolicy(BaseModel):
    """
    Per-agent security profile.
    """

    agent_id: str
    description: str = ""
    allowed_tools: list[str] = Field(default_factory=list)
    scope: str = "read"
    max_task_duration_seconds: int = 300
    risk_budget: float = Field(default=5.0, ge=0.0, le=100.0)
    require_human_approval_for: list[str] = Field(default_factory=list)
    rate_limit: RateLimit = Field(default_factory=RateLimit)
    system_prompt: str = ""
