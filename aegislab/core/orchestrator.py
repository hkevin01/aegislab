"""
Orchestrator — ties together identity, sandbox, policy, defenses, and logging
for a complete agent task execution.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any

from aegislab.core.agent import (
    AgentDefinition,
    AgentStatus,
    Task,
    ToolCall,
    get_registry,
)
from aegislab.core.identity import get_identity_service
from aegislab.core.sandbox import SandboxConfig, get_sandbox
from aegislab.defenses.backpressure import get_backpressure
from aegislab.defenses.guardrails import get_guardrails
from aegislab.defenses.injection import get_injection_classifier
from aegislab.defenses.threat_detector import Severity, get_ata_detector
from aegislab.logging.tracer import get_tracer
from aegislab.policy.engine import PolicyDecision, get_policy_engine

logger = logging.getLogger(__name__)


class Orchestrator:
    """Coordinates the full lifecycle of an agent task."""

    def __init__(self) -> None:
        self._registry = get_registry()
        self._identity = get_identity_service()
        self._policy = get_policy_engine()
        self._bp = get_backpressure()
        self._classifier = get_injection_classifier()
        self._ata = get_ata_detector()
        self._guardrails = get_guardrails()
        self._tracer = get_tracer()

    async def submit_task(
        self, agent_id: str, input_payload: dict[str, Any]
    ) -> Task:
        """
        Validate input, issue identity, create task record, and queue execution.
        Returns the Task immediately (status=PENDING).
        """
        defn = self._registry.get_definition(agent_id)
        if defn is None:
            raise ValueError(f"Unknown agent: {agent_id!r}")

        # Check backpressure — will raise if agent is rate-limited or quarantined
        await self._bp.check_agent(agent_id)

        # Forge guardrails: validate input schema and content
        gr = self._guardrails.validate_input(input_payload)
        if not gr.passed:
            critical = [v for v in gr.violations if v.severity == "critical"]
            raise PermissionError(
                f"Input blocked by Forge guardrails: "
                + "; ".join(v.message[:100] for v in critical)
            )

        # Scan input for prompt injection
        user_input = str(input_payload.get("prompt", ""))
        inj_result = await self._classifier.classify(user_input)
        if inj_result.blocked:
            raise PermissionError(
                f"Input blocked by injection classifier (score={inj_result.score:.2f}): "
                f"{inj_result.reason}"
            )

        # ATA behavioral fingerprint scan on all input fields
        ata_result = self._ata.scan_text(str(input_payload))
        if ata_result.blocked:
            findings_summary = "; ".join(
                f"[{f.rule_id}] {f.description[:80]}" for f in ata_result.findings
            )
            raise PermissionError(
                f"Input blocked by ATA detector (severity={ata_result.highest_severity}): "
                f"{findings_summary}"
            )

        task = await self._registry.create_task(agent_id, input_payload)
        if inj_result.flagged:
            task.injection_flags.append(
                f"suspicion_score={inj_result.score:.2f}: {inj_result.reason}"
            )

        # Issue short-lived identity token
        token = self._identity.issue(
            agent_id=agent_id,
            allowed_tools=defn.allowed_tools,
            scope=defn.scope.value,
            task_id=task.task_id,
        )
        task.token = token

        await self._registry.update_task(task)

        # Fire and forget execution
        asyncio.create_task(self._execute(task, defn))
        return task

    async def execute_tool_call(
        self,
        task: Task,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ToolCall:
        """
        Execute a single tool call on behalf of a running task.
        Enforces policy, records the call, and applies backpressure on failure.
        """
        identity = self._identity.verify(task.token)

        # ATA scan on tool arguments before policy evaluation
        ata_result = self._ata.scan_tool_call(tool_name, arguments)
        if ata_result.blocked:
            findings_summary = "; ".join(
                f"[{f.rule_id}]" for f in ata_result.findings
            )
            call = ToolCall(
                tool_name=tool_name,
                arguments=arguments,
                policy_decision="deny",
                risk_score=10.0,
                error=f"ATA detector blocked call ({findings_summary})",
            )
            task.record_tool_call(call)
            await self._registry.update_task(task)
            await self._tracer.record_tool_call(task, call)
            await self._bp.record_violation(task.agent_id)
            raise PermissionError(
                f"Tool call '{tool_name}' blocked by ATA detector: {findings_summary}"
            )

        # Policy check
        decision = await self._policy.evaluate(identity, tool_name, arguments)
        call = ToolCall(
            tool_name=tool_name,
            arguments=arguments,
            policy_decision=decision.verdict,
            risk_score=decision.risk_score,
        )

        if decision.verdict == PolicyDecision.DENY:
            call.error = f"Policy denied: {decision.reason}"
            task.record_tool_call(call)
            await self._registry.update_task(task)
            await self._tracer.record_tool_call(task, call)
            await self._bp.record_violation(task.agent_id)
            raise PermissionError(f"Tool call denied by policy: {decision.reason}")

        if decision.verdict == PolicyDecision.ESCALATE:
            call.policy_decision = "escalated"
            task.status = AgentStatus.AWAITING_APPROVAL
            task.record_tool_call(call)
            await self._registry.update_task(task)
            await self._tracer.record_tool_call(task, call)
            raise PermissionError(
                f"Tool call requires human approval: {decision.reason}"
            )

        # Execute (stubbed — real impl would dispatch to tool registry)
        t0 = time.monotonic()
        call.result = {"status": "executed", "tool": tool_name, "args": arguments}
        call.duration_ms = (time.monotonic() - t0) * 1000

        task.record_tool_call(call)
        await self._registry.update_task(task)
        await self._tracer.record_tool_call(task, call)
        return call

    async def _execute(self, task: Task, defn: AgentDefinition) -> None:
        """Internal task execution — runs in a background asyncio task."""
        task.status = AgentStatus.RUNNING
        task.started_at = datetime.now(tz=timezone.utc)
        await self._registry.update_task(task)
        await self._tracer.record_task_start(task)

        try:
            sandbox = get_sandbox()
            cfg = SandboxConfig(
                agent_token=task.token,
                timeout_seconds=defn.max_task_duration_seconds,
            )
            # In a real deployment: inject the actual agent code/command.
            # For demo purposes we run a no-op.
            result = await sandbox.run(
                command=["python", "-c", "print('agent task complete')"],
                config=cfg,
            )
            task.output_payload = {"stdout": result.stdout, "exit_code": result.exit_code}
            task.status = (
                AgentStatus.COMPLETED if result.exit_code == 0 else AgentStatus.FAILED
            )
        except Exception as exc:
            logger.exception("Task %s failed: %s", task.task_id, exc)
            task.status = AgentStatus.FAILED
            task.error = str(exc)
            await self._bp.record_violation(task.agent_id)
        finally:
            task.completed_at = datetime.now(tz=timezone.utc)
            await self._registry.update_task(task)
            await self._tracer.record_task_end(task)


_orchestrator: Orchestrator | None = None


def get_orchestrator() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
    return _orchestrator
