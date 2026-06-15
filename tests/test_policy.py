"""Tests for the policy engine."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from aegislab.core.identity import AgentIdentity
from aegislab.policy.engine import PolicyEngine, PolicyDecision
from aegislab.policy.models import ToolPolicy, RateLimit


def make_identity(agent_id: str, allowed_tools: list[str]) -> AgentIdentity:
    return AgentIdentity({
        "agent_id": agent_id,
        "task_id": "test-task-123",
        "allowed_tools": allowed_tools,
        "scope": "read",
        "iat": 0,
        "exp": 9999999999,
    })


@pytest.fixture
def engine():
    """Policy engine with no policies loaded (empty state)."""
    eng = PolicyEngine.__new__(PolicyEngine)
    eng._tool_policies = {}
    return eng


@pytest.mark.asyncio
async def test_tool_not_in_allowed_list_denied(engine):
    identity = make_identity("analyst", ["http_request"])
    result = await engine.evaluate(identity, "shell_exec", {})
    assert result.verdict == PolicyDecision.DENY
    assert "allowed_tools" in result.reason


@pytest.mark.asyncio
async def test_no_policy_global_default_deny(engine):
    """With default_policy=deny, a tool with no policy should be denied."""
    identity = make_identity("analyst", ["some_tool"])
    with patch("aegislab.policy.engine.get_settings") as mock_cfg:
        mock_cfg.return_value.default_policy = "deny"
        result = await engine.evaluate(identity, "some_tool", {})
    assert result.verdict == PolicyDecision.DENY


@pytest.mark.asyncio
async def test_no_policy_global_default_allow(engine):
    identity = make_identity("analyst", ["some_tool"])
    with patch("aegislab.policy.engine.get_settings") as mock_cfg:
        mock_cfg.return_value.default_policy = "allow"
        result = await engine.evaluate(identity, "some_tool", {})
    assert result.verdict == PolicyDecision.ALLOW


@pytest.mark.asyncio
async def test_explicit_deny_rule_applied(engine):
    policy = ToolPolicy(
        tool="http_request",
        default_action="allow",
        deny={"domains": ["evil.com"]},
    )
    engine._tool_policies["http_request"] = policy
    identity = make_identity("analyst", ["http_request"])
    result = await engine.evaluate(identity, "http_request", {"url": "http://evil.com/data"})
    assert result.verdict == PolicyDecision.DENY


@pytest.mark.asyncio
async def test_explicit_allow_rule_applied(engine):
    policy = ToolPolicy(
        tool="http_request",
        default_action="deny",
        allow={"domains": ["safe.internal"]},
    )
    engine._tool_policies["http_request"] = policy
    identity = make_identity("analyst", ["http_request"])
    result = await engine.evaluate(identity, "http_request", {"url": "http://safe.internal/api"})
    assert result.verdict == PolicyDecision.ALLOW


@pytest.mark.asyncio
async def test_human_approval_escalation(engine):
    policy = ToolPolicy(
        tool="database_query",
        default_action="deny",
        require_human_approval=[{"operation": "INSERT"}],
    )
    engine._tool_policies["database_query"] = policy
    identity = make_identity("analyst", ["database_query"])
    result = await engine.evaluate(identity, "database_query", {"operation": "INSERT"})
    assert result.verdict == PolicyDecision.ESCALATE


@pytest.mark.asyncio
async def test_wildcard_tool_allow(engine):
    """Agent with '*' in allowed_tools can call any tool."""
    identity = make_identity("admin", ["*"])
    result = await engine.evaluate(identity, "any_tool", {})
    # No policy → falls through to global default
    with patch("aegislab.policy.engine.get_settings") as mock_cfg:
        mock_cfg.return_value.default_policy = "allow"
        result = await engine.evaluate(identity, "any_tool", {})
    assert result.verdict == PolicyDecision.ALLOW
