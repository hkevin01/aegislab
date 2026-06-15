"""
Policy loader — reads YAML files from the policy directory and returns
validated ToolPolicy / AgentPolicy objects.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from aegislab.config import get_settings
from aegislab.policy.models import AgentPolicy, ToolPolicy

logger = logging.getLogger(__name__)


def _load_yaml(path: Path) -> dict:
    with path.open() as fh:
        return yaml.safe_load(fh) or {}


def load_tool_policies(policy_dir: Path | None = None) -> dict[str, ToolPolicy]:
    """Load all YAML files from policies/tools/ and return a name→policy map."""
    base = policy_dir or get_settings().policy_dir
    tools_dir = base / "tools"
    policies: dict[str, ToolPolicy] = {}

    if not tools_dir.exists():
        logger.warning("Tool policy directory not found: %s", tools_dir)
        return policies

    for yaml_file in sorted(tools_dir.glob("*.yaml")):
        try:
            data = _load_yaml(yaml_file)
            policy = ToolPolicy(**data)
            policies[policy.tool] = policy
            logger.debug("Loaded tool policy: %s", policy.tool)
        except Exception as exc:
            logger.error("Failed to load tool policy %s: %s", yaml_file, exc)

    return policies


def load_agent_policies(policy_dir: Path | None = None) -> dict[str, AgentPolicy]:
    """Load all YAML files from policies/agents/ and return an id→policy map."""
    base = policy_dir or get_settings().policy_dir
    agents_dir = base / "agents"
    policies: dict[str, AgentPolicy] = {}

    if not agents_dir.exists():
        logger.warning("Agent policy directory not found: %s", agents_dir)
        return policies

    for yaml_file in sorted(agents_dir.glob("*.yaml")):
        try:
            data = _load_yaml(yaml_file)
            policy = AgentPolicy(**data)
            policies[policy.agent_id] = policy
            logger.debug("Loaded agent policy: %s", policy.agent_id)
        except Exception as exc:
            logger.error("Failed to load agent policy %s: %s", yaml_file, exc)

    return policies
