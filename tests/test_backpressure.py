"""Tests for the backpressure engine."""

from __future__ import annotations

import pytest
from aegislab.defenses.backpressure import BackpressureEngine, BackpressureError, CircuitState


@pytest.fixture
def bp():
    return BackpressureEngine()


@pytest.mark.asyncio
async def test_normal_request_passes(bp):
    await bp.check_agent("agent-a")   # should not raise


@pytest.mark.asyncio
async def test_rate_limit_exceeded(bp):
    bp.MAX_RPM = 3   # lower limit for test speed
    for _ in range(3):
        await bp.check_agent("agent-b")
    with pytest.raises(BackpressureError, match="rate limit"):
        await bp.check_agent("agent-b")


@pytest.mark.asyncio
async def test_circuit_opens_after_violations(bp):
    bp.MAX_VIOLATIONS = 3
    for _ in range(3):
        await bp.record_violation("agent-c")
    state = bp._budgets["agent-c"].circuit_state
    assert state == CircuitState.OPEN


@pytest.mark.asyncio
async def test_open_circuit_blocks_requests(bp):
    bp.MAX_VIOLATIONS = 1
    await bp.record_violation("agent-d")
    with pytest.raises(BackpressureError, match="Circuit breaker"):
        await bp.check_agent("agent-d")


@pytest.mark.asyncio
async def test_quarantine_after_many_violations(bp):
    bp.QUARANTINE_THRESHOLD = 3
    for _ in range(3):
        await bp.record_violation("agent-e")
    assert "agent-e" in bp._quarantined
    with pytest.raises(BackpressureError, match="quarantined"):
        await bp.check_agent("agent-e")


@pytest.mark.asyncio
async def test_quarantine_release(bp):
    bp.QUARANTINE_THRESHOLD = 1
    await bp.record_violation("agent-f")
    await bp.release_quarantine("agent-f")
    assert "agent-f" not in bp._quarantined
    await bp.check_agent("agent-f")   # should not raise


@pytest.mark.asyncio
async def test_success_closes_half_open_circuit(bp):
    from aegislab.defenses.backpressure import CircuitState
    bp._budgets["agent-g"].circuit_state = CircuitState.HALF_OPEN
    await bp.record_success("agent-g")
    assert bp._budgets["agent-g"].circuit_state == CircuitState.CLOSED
