"""
Policy engine — evaluates tool calls against loaded policies.

Decision flow for every tool call:
  1. Check identity token: is the tool in the agent's allowed_tools list?
  2. Load the tool's ToolPolicy (if any).
  3. Evaluate explicit deny rules → DENY if matched.
  4. Check require_human_approval conditions → ESCALATE if matched.
  5. Evaluate explicit allow rules → ALLOW if matched.
  6. Fall back to the policy's default_action (default: deny).
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass
from typing import Any

from aegislab.core.identity import AgentIdentity
from aegislab.policy.loader import load_tool_policies
from aegislab.policy.models import ToolPolicy

logger = logging.getLogger(__name__)


class PolicyDecision:
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


@dataclass
class EvaluationResult:
    verdict: str          # PolicyDecision constant
    reason: str
    risk_score: float
    tool: str
    agent_id: str


def _matches_conditions(conditions: dict[str, Any], arguments: dict[str, Any]) -> bool:
    """
    Check whether *arguments* satisfy *conditions*.

    Supported condition keys:
      - methods    : list of HTTP method strings
      - domains    : list of glob patterns matched against arguments["url"]
      - Any other key is matched as a literal equality check against arguments.
    """
    if not conditions:
        return False

    for key, value in conditions.items():
        if key == "methods":
            method = str(arguments.get("method", "")).upper()
            if method not in [str(m).upper() for m in value]:
                return False
        elif key == "domains":
            url = str(arguments.get("url", ""))
            # Extract hostname from URL for matching
            import urllib.parse
            host = urllib.parse.urlparse(url).hostname or url
            matched = any(fnmatch.fnmatch(host, str(pattern)) for pattern in value)
            if not matched:
                return False
        else:
            if arguments.get(key) != value:
                return False

    return True


class PolicyEngine:
    """
    Thread-safe policy evaluation engine.
    Policies are loaded eagerly at construction time and can be reloaded.
    """

    def __init__(self) -> None:
        self._tool_policies: dict[str, ToolPolicy] = {}
        self.reload()

    def reload(self) -> None:
        """Reload all policies from disk."""
        self._tool_policies = load_tool_policies()
        logger.info("Policy engine loaded %d tool policies", len(self._tool_policies))

    async def evaluate(
        self,
        identity: AgentIdentity,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> EvaluationResult:
        """
        Evaluate a tool call request and return an EvaluationResult.
        This method is async to allow future integration with remote policy servers.
        """
        agent_id = identity.agent_id

        # Step 1 — identity-level check
        if not identity.can_use_tool(tool_name):
            return EvaluationResult(
                verdict=PolicyDecision.DENY,
                reason=f"Tool '{tool_name}' not in agent's allowed_tools list",
                risk_score=5.0,
                tool=tool_name,
                agent_id=agent_id,
            )

        policy = self._tool_policies.get(tool_name)

        # No policy found — fall back to global default
        if policy is None:
            from aegislab.config import get_settings
            default = get_settings().default_policy
            verdict = PolicyDecision.ALLOW if default == "allow" else PolicyDecision.DENY
            return EvaluationResult(
                verdict=verdict,
                reason=f"No policy for '{tool_name}'; using global default ({default})",
                risk_score=0.5 if verdict == PolicyDecision.ALLOW else 2.0,
                tool=tool_name,
                agent_id=agent_id,
            )

        risk_score = policy.risk_weight

        # Step 2 — explicit deny rules
        if _matches_conditions(policy.deny, arguments):
            return EvaluationResult(
                verdict=PolicyDecision.DENY,
                reason=f"Matched deny rule for tool '{tool_name}'",
                risk_score=risk_score * 2,
                tool=tool_name,
                agent_id=agent_id,
            )

        # Step 3 — human approval conditions
        for condition in policy.require_human_approval:
            if _matches_conditions(condition, arguments):
                return EvaluationResult(
                    verdict=PolicyDecision.ESCALATE,
                    reason=(
                        f"Tool '{tool_name}' with these arguments requires human approval"
                    ),
                    risk_score=risk_score * 1.5,
                    tool=tool_name,
                    agent_id=agent_id,
                )

        # Step 4 — explicit allow rules
        if _matches_conditions(policy.allow, arguments):
            return EvaluationResult(
                verdict=PolicyDecision.ALLOW,
                reason=f"Matched allow rule for tool '{tool_name}'",
                risk_score=risk_score,
                tool=tool_name,
                agent_id=agent_id,
            )

        # Step 5 — default action
        verdict = (
            PolicyDecision.ALLOW
            if policy.default_action == "allow"
            else PolicyDecision.DENY
        )
        return EvaluationResult(
            verdict=verdict,
            reason=f"Default action ({policy.default_action}) for tool '{tool_name}'",
            risk_score=risk_score,
            tool=tool_name,
            agent_id=agent_id,
        )


_engine: PolicyEngine | None = None


def get_policy_engine() -> PolicyEngine:
    global _engine
    if _engine is None:
        _engine = PolicyEngine()
    return _engine
