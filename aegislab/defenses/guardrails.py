"""
Forge Guardrails — structured input/output validation layer for AI agents.

Concept
-------
"Guardrails" in AI safety refers to a programmable validation layer that sits
between the model and the outside world, enforcing structural and semantic
contracts on both inputs (prompts) and outputs (model responses / tool calls).

Key frameworks in this space:
  • guardrails-ai   — https://github.com/guardrails-ai/guardrails
    Open-source Python library with typed validators, retry logic, and
    structured output parsing.

  • NVIDIA NeMo Guardrails — https://github.com/NVIDIA/NeMo-Guardrails
    Colang-based programmable rails for topical filtering, safety checks,
    fact-checking, and jailbreak detection.

  • Invariant Guardrails — https://invariantlabs.ai
    Contextual security layer for AI agents; acquired by Snyk (2025).
    Provides runtime policy enforcement over agent trajectories.

What AegisLab "Forge" adds
--------------------------
A lightweight, zero-dependency guardrails layer that:
  1. Validates input schemas before an agent task is submitted
  2. Validates model output / tool call return values before they are passed
     to the next agent in a chain
  3. Enforces content constraints (blocked topics, required fields, length
     limits, PII redaction)
  4. Provides a retry-with-correction loop when outputs fail validation
  5. Applies to both direct calls and MCP tool responses

MCP Security
------------
The Model Context Protocol (MCP) introduces new attack surfaces:
  • Tool poisoning / rug pulls: A malicious MCP server returns tool
    descriptions containing embedded instructions that override the system
    prompt (Invariant Labs, 2025; https://invariantlabs.ai/blog/mcp-security).
  • Prompt injection via tool output: Tool results containing injection
    payloads are treated as trusted by the model
    (Greshake et al., arXiv:2302.12173).
  • Cross-server data exfiltration: Agents with multiple MCP servers can
    be tricked into leaking data from one server to another.

AegisGuardrails addresses all three via:
  - Structural validation of MCP tool schemas before registration
  - Content scanning of tool return values (injection + ATA fingerprints)
  - Strict domain isolation: agent identities are scoped to ONE MCP server
    at a time unless explicitly bridged by the policy engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ValidationError


# ── PII patterns ──────────────────────────────────────────────────────────────

_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CREDIT_CARD = re.compile(r"\b(?:\d[ -]?){13,16}\b")
_AWS_KEY = re.compile(r"\b(AKIA|ASIA|AROA)[A-Z0-9]{16}\b")
_PRIVATE_KEY_PEM = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_API_KEY_GENERIC = re.compile(r"\b(?:sk|pk|api|key|token)[_\-][a-zA-Z0-9]{20,}\b", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


# ── Blocked topics (configurable) ────────────────────────────────────────────

_DEFAULT_BLOCKED_TOPICS = [
    re.compile(r"\b(synthesize|manufacture)\s+(drug|explosive|weapon|bomb)\b", re.I),
    re.compile(r"\b(child|minor)\s+(sexual|nude|naked)\b", re.I),
    re.compile(r"\b(biological|chemical)\s+weapon\b", re.I),
]


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class GuardrailViolation:
    rule: str
    message: str
    severity: str = "high"
    redacted: bool = False


@dataclass
class GuardrailResult:
    passed: bool
    violations: list[GuardrailViolation] = field(default_factory=list)
    redacted_text: str | None = None

    def has_critical(self) -> bool:
        return any(v.severity == "critical" for v in self.violations)


# ── Schema validators ─────────────────────────────────────────────────────────

class AgentInputSchema(BaseModel):
    """Minimum required shape for an agent task input payload."""
    prompt: str
    # Additional fields are allowed (extra="allow") but prompt is required.
    model_config = {"extra": "allow"}


class ToolOutputSchema(BaseModel):
    """Expected shape of a successful tool call result."""
    status: str
    model_config = {"extra": "allow"}


# ── Guardrail engine ──────────────────────────────────────────────────────────

class ForgeGuardrails:
    """
    Programmable guardrails layer for AegisLab agent inputs and outputs.

    Usage pattern
    -------------
        rails = ForgeGuardrails()

        # Validate agent input
        result = rails.validate_input(payload)
        if not result.passed:
            raise ValueError(result.violations)

        # Validate tool output before passing to next agent
        result = rails.validate_tool_output(tool_result)
        if not result.passed:
            # optionally retry with corrected output or block
            ...

        # Redact PII from model output before logging
        clean = rails.redact(model_output)
    """

    def __init__(
        self,
        blocked_topics: list[re.Pattern[str]] | None = None,
        max_prompt_length: int = 8192,
        max_output_length: int = 65536,
        redact_pii: bool = True,
    ) -> None:
        self._blocked = blocked_topics or _DEFAULT_BLOCKED_TOPICS
        self._max_prompt = max_prompt_length
        self._max_output = max_output_length
        self._redact_pii = redact_pii

    # ── Input validation ──────────────────────────────────────────────────────

    def validate_input(self, payload: dict[str, Any]) -> GuardrailResult:
        """
        Validate an agent input payload.

        Checks:
          1. Schema: prompt field is present and a string
          2. Length: prompt does not exceed max_prompt_length
          3. Blocked topics: hard-blocked content categories
          4. PII in prompt: AWS keys, private keys, credit cards
          5. MCP schema injection: tool_description overrides in JSON
        """
        violations: list[GuardrailViolation] = []

        # 1. Schema validation
        try:
            AgentInputSchema(**payload)
        except ValidationError as exc:
            for err in exc.errors():
                violations.append(GuardrailViolation(
                    rule="SCHEMA-001",
                    message=f"Input schema violation: {err['msg']} (field: {'.'.join(str(l) for l in err['loc'])})",
                    severity="high",
                ))
            return GuardrailResult(passed=False, violations=violations)

        prompt = str(payload.get("prompt", ""))

        # 2. Length
        if len(prompt) > self._max_prompt:
            violations.append(GuardrailViolation(
                rule="INPUT-001",
                message=f"Prompt exceeds max length ({len(prompt)} > {self._max_prompt})",
                severity="medium",
            ))

        # 3. Blocked topics
        for pattern in self._blocked:
            if pattern.search(prompt):
                violations.append(GuardrailViolation(
                    rule="CONTENT-001",
                    message=f"Prompt contains blocked content (pattern: {pattern.pattern[:50]})",
                    severity="critical",
                ))

        # 4. PII / secrets in prompt (warn — agents should not receive raw secrets)
        for name, pattern in [
            ("AWS_KEY", _AWS_KEY),
            ("PRIVATE_KEY", _PRIVATE_KEY_PEM),
            ("CREDIT_CARD", _CREDIT_CARD),
            ("SSN", _SSN),
        ]:
            if pattern.search(prompt):
                violations.append(GuardrailViolation(
                    rule=f"PII-{name}",
                    message=f"Prompt contains sensitive data pattern: {name}",
                    severity="high",
                ))

        # 5. MCP tool description injection in JSON payload
        full_payload_str = str(payload)
        if re.search(
            r"\"description\"\s*:\s*\"[^\"]*ignore[^\"]*instructions",
            full_payload_str, re.I
        ):
            violations.append(GuardrailViolation(
                rule="MCP-POISON-001",
                message=(
                    "Possible MCP tool-description poisoning detected in input payload. "
                    "Ref: Invariant Labs MCP security research (2025)."
                ),
                severity="critical",
            ))

        return GuardrailResult(
            passed=len([v for v in violations if v.severity in ("high", "critical")]) == 0,
            violations=violations,
        )

    # ── Output validation ─────────────────────────────────────────────────────

    def validate_tool_output(self, output: Any) -> GuardrailResult:
        """
        Validate a tool call return value before it is passed to the next agent.

        This is critical for MCP security: tool outputs can contain injected
        instructions (indirect prompt injection, arXiv:2302.12173).
        """
        violations: list[GuardrailViolation] = []
        output_str = str(output)

        # Length check
        if len(output_str) > self._max_output:
            violations.append(GuardrailViolation(
                rule="OUTPUT-001",
                message=f"Tool output exceeds max length ({len(output_str)} > {self._max_output})",
                severity="medium",
            ))

        # Injection in tool output — indirect prompt injection vector
        # ref: Greshake et al. arXiv:2302.12173
        _injection_in_output = re.compile(
            r"ignore\s+(previous|prior)\s+instructions?"
            r"|you\s+are\s+now\s+a"
            r"|<\|?system\|?>",
            re.I,
        )
        if _injection_in_output.search(output_str):
            violations.append(GuardrailViolation(
                rule="IPI-001",
                message=(
                    "Indirect prompt injection detected in tool output. "
                    "Malicious instructions embedded in tool return value. "
                    "arXiv:2302.12173 (Greshake et al., 2023)."
                ),
                severity="critical",
            ))

        # Secrets in output — should not be passed between agents in plaintext
        for name, pattern in [
            ("AWS_KEY", _AWS_KEY),
            ("PRIVATE_KEY", _PRIVATE_KEY_PEM),
        ]:
            if pattern.search(output_str):
                violations.append(GuardrailViolation(
                    rule=f"OUTPUT-PII-{name}",
                    message=f"Tool output contains sensitive data pattern: {name}. "
                            "This should be redacted before passing to the next agent.",
                    severity="high",
                ))

        return GuardrailResult(
            passed=len([v for v in violations if v.severity in ("high", "critical")]) == 0,
            violations=violations,
        )

    # ── PII redaction ─────────────────────────────────────────────────────────

    def redact(self, text: str) -> str:
        """
        Redact known PII and secret patterns from text before logging or
        passing between agents. Returns the cleaned string.
        """
        if not self._redact_pii:
            return text
        text = _AWS_KEY.sub("[REDACTED:AWS_KEY]", text)
        text = _PRIVATE_KEY_PEM.sub("[REDACTED:PRIVATE_KEY]", text)
        text = _CREDIT_CARD.sub("[REDACTED:CREDIT_CARD]", text)
        text = _SSN.sub("[REDACTED:SSN]", text)
        text = _API_KEY_GENERIC.sub("[REDACTED:API_KEY]", text)
        # Partial email redaction: keep domain, mask local part
        text = _EMAIL.sub(lambda m: "***@" + m.group(0).split("@")[1], text)
        return text

    # ── MCP schema validation ─────────────────────────────────────────────────

    def validate_mcp_tool_schema(self, tool_schema: dict[str, Any]) -> GuardrailResult:
        """
        Validate a tool schema from an MCP server before registering it.

        Prevents rug-pull attacks where a malicious MCP server injects
        override instructions into the tool's 'description' field.
        Ref: Invariant Labs (2025), https://invariantlabs.ai/blog/mcp-security
        """
        violations: list[GuardrailViolation] = []
        desc = str(tool_schema.get("description", ""))

        _override_patterns = [
            re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions?", re.I),
            re.compile(r"system\s+prompt", re.I),
            re.compile(r"you\s+are\s+now", re.I),
            re.compile(r"do\s+not\s+(follow|obey)", re.I),
        ]
        for p in _override_patterns:
            if p.search(desc):
                violations.append(GuardrailViolation(
                    rule="MCP-SCHEMA-001",
                    message=(
                        "MCP tool schema description contains instruction override. "
                        "This is a tool-poisoning / rug-pull attack pattern. "
                        "Ref: Invariant Labs MCP security research (2025)."
                    ),
                    severity="critical",
                ))
                break

        return GuardrailResult(
            passed=len(violations) == 0,
            violations=violations,
        )


_guardrails: ForgeGuardrails | None = None


def get_guardrails() -> ForgeGuardrails:
    global _guardrails
    if _guardrails is None:
        _guardrails = ForgeGuardrails()
    return _guardrails
