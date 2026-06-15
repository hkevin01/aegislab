"""
Structural backpressure — rate limits, circuit breakers, and kill-switches.

Prevents runaway or cascading failures in multi-agent workflows.

State is stored in Redis (sliding window counters + circuit breaker state).
Falls back to an in-process dict when Redis is unavailable (dev mode).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Failing — reject all requests
    HALF_OPEN = "half_open" # Testing recovery


@dataclass
class AgentBudget:
    """Per-agent counters tracked in memory."""
    request_count: int = 0
    violation_count: int = 0
    circuit_state: CircuitState = CircuitState.CLOSED
    circuit_opened_at: float = 0.0
    window_start: float = field(default_factory=time.monotonic)
    requests_in_window: int = 0


class BackpressureError(Exception):
    """Raised when a request should be rejected due to backpressure."""


class BackpressureEngine:
    """
    Rate limits and circuit breakers per agent.

    Configuration (hardcoded defaults, can be overridden per-agent via policy):
      - max_requests_per_minute : 60
      - max_violations_before_open : 5
      - circuit_open_duration_seconds : 30
      - quarantine_violation_threshold : 20
    """

    MAX_RPM = 60
    WINDOW_SECONDS = 60
    MAX_VIOLATIONS = 5
    CIRCUIT_OPEN_SECONDS = 30
    QUARANTINE_THRESHOLD = 20

    def __init__(self) -> None:
        self._budgets: dict[str, AgentBudget] = defaultdict(AgentBudget)
        self._quarantined: set[str] = set()
        self._lock = asyncio.Lock()

    async def check_agent(self, agent_id: str) -> None:
        """
        Assert that agent_id is allowed to proceed.
        Raises BackpressureError if rate-limited, circuit-open, or quarantined.
        """
        async with self._lock:
            if agent_id in self._quarantined:
                raise BackpressureError(
                    f"Agent '{agent_id}' is quarantined due to excessive violations"
                )

            budget = self._budgets[agent_id]
            now = time.monotonic()

            # Reset sliding window
            if now - budget.window_start >= self.WINDOW_SECONDS:
                budget.window_start = now
                budget.requests_in_window = 0

            # Rate limit
            if budget.requests_in_window >= self.MAX_RPM:
                raise BackpressureError(
                    f"Agent '{agent_id}' rate limit exceeded "
                    f"({self.MAX_RPM} req/min)"
                )

            # Circuit breaker
            if budget.circuit_state == CircuitState.OPEN:
                elapsed = now - budget.circuit_opened_at
                if elapsed >= self.CIRCUIT_OPEN_SECONDS:
                    budget.circuit_state = CircuitState.HALF_OPEN
                    logger.info("Circuit breaker HALF_OPEN for agent %s", agent_id)
                else:
                    raise BackpressureError(
                        f"Circuit breaker OPEN for agent '{agent_id}' "
                        f"(opens in {self.CIRCUIT_OPEN_SECONDS - elapsed:.0f}s)"
                    )

            budget.requests_in_window += 1
            budget.request_count += 1

    async def record_violation(self, agent_id: str) -> None:
        """Record a policy violation for agent_id; may open the circuit."""
        async with self._lock:
            budget = self._budgets[agent_id]
            budget.violation_count += 1

            if budget.violation_count >= self.QUARANTINE_THRESHOLD:
                self._quarantined.add(agent_id)
                logger.warning(
                    "Agent %s QUARANTINED after %d violations",
                    agent_id,
                    budget.violation_count,
                )
                return

            if (
                budget.circuit_state == CircuitState.CLOSED
                and budget.violation_count >= self.MAX_VIOLATIONS
            ):
                budget.circuit_state = CircuitState.OPEN
                budget.circuit_opened_at = time.monotonic()
                logger.warning(
                    "Circuit breaker OPENED for agent %s after %d violations",
                    agent_id,
                    budget.violation_count,
                )

            elif budget.circuit_state == CircuitState.HALF_OPEN:
                # Failure during probe → reopen
                budget.circuit_state = CircuitState.OPEN
                budget.circuit_opened_at = time.monotonic()
                logger.warning("Circuit breaker RE-OPENED for agent %s", agent_id)

    async def record_success(self, agent_id: str) -> None:
        """Record a successful call; may close a half-open circuit."""
        async with self._lock:
            budget = self._budgets[agent_id]
            if budget.circuit_state == CircuitState.HALF_OPEN:
                budget.circuit_state = CircuitState.CLOSED
                budget.violation_count = 0
                logger.info("Circuit breaker CLOSED for agent %s", agent_id)

    async def release_quarantine(self, agent_id: str) -> None:
        """Manually release a quarantined agent (operator action)."""
        async with self._lock:
            self._quarantined.discard(agent_id)
            budget = self._budgets[agent_id]
            budget.circuit_state = CircuitState.CLOSED
            budget.violation_count = 0
            logger.info("Agent %s released from quarantine", agent_id)

    def status(self) -> list[dict[str, Any]]:
        """Return a snapshot of all agent budgets for the dashboard."""
        out = []
        for agent_id, budget in self._budgets.items():
            out.append({
                "agent_id": agent_id,
                "request_count": budget.request_count,
                "violation_count": budget.violation_count,
                "circuit_state": budget.circuit_state.value,
                "quarantined": agent_id in self._quarantined,
                "requests_in_current_window": budget.requests_in_window,
            })
        return out


_backpressure: BackpressureEngine | None = None


def get_backpressure() -> BackpressureEngine:
    global _backpressure
    if _backpressure is None:
        _backpressure = BackpressureEngine()
    return _backpressure
