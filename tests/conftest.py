"""Shared pytest fixtures."""

from __future__ import annotations

import pytest
from aegislab.core.agent import AgentRegistry
from aegislab.defenses.backpressure import BackpressureEngine
from aegislab.policy.engine import PolicyEngine


@pytest.fixture(autouse=True)
def reset_singletons(monkeypatch):
    """
    Reset module-level singletons before each test to ensure isolation.
    """
    import aegislab.core.agent as agent_mod
    import aegislab.defenses.backpressure as bp_mod
    import aegislab.policy.engine as engine_mod
    import aegislab.defenses.injection as inj_mod
    import aegislab.defenses.threat_detector as ata_mod
    import aegislab.defenses.guardrails as gr_mod
    import aegislab.logging.tracer as tracer_mod

    monkeypatch.setattr(agent_mod, "_registry", None)
    monkeypatch.setattr(bp_mod, "_backpressure", None)
    monkeypatch.setattr(engine_mod, "_engine", None)
    monkeypatch.setattr(inj_mod, "_classifier", None)
    monkeypatch.setattr(ata_mod, "_detector", None)
    monkeypatch.setattr(gr_mod, "_guardrails", None)
    monkeypatch.setattr(tracer_mod, "_tracer", None)
