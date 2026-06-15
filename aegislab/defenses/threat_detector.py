"""
Agentic Threat Actor (ATA) detector.

Inspired by Sysdig Threat Research Team findings documented in:

  "Agentic threat actor hits the orchestration plane: AI agent-driven
  container escape" — Sysdig TRT, Michael Clark, June 4 2026.
  https://sysdig.com/blog/agentic-threat-actor-hits-the-orchestration-plane-ai-agent-driven-container-escape/

  "AI agent at the wheel: how an attacker used LLMs to move from a CVE to
  an internal database in 4 pivots" — Sysdig TRT, May 2026.
  https://sysdig.com/blog/ai-agent-at-the-wheel-how-an-attacker-used-llms-to-move-from-a-cve-to-an-internal-database-in-4-pivots

Sysdig documented the first LLM-harness-driven container-escape attack in the
wild (May/June 2026). The attack exhibited distinctive "agentic fingerprints":

  Fingerprint 1 — Canary-response following:
    The agent parsed a JSON response body and acted on an embedded canary
    URL, something a human would skip over.  Section markers (`===SHADOW===`)
    were used to delimit output so the next agent turn could slice results.

  Fingerprint 2 — Base64-chunked payload staging:
    Payloads staged as base64 in chunks, decoded, then executed:
      base64 -d /tmp/r_.b64 > /tmp/r_.py; python3 /tmp/r_.py
    The agent unit-tested the staging harness with a "hello world" canary
    before delivering the real escape script.

  Fingerprint 3 — Comprehensive escape-surface enumeration in one pass:
    Echo-delimited section markers for each probe:
      echo _DOCKER_ && test -S /var/run/docker.sock
      echo _SOCK_ && ...
      echo _CAPS_ && grep CapEff /proc/1/status
      echo _AFALG_ && python3 -c "import socket; s=socket.socket(38,5,0)..."
      echo _K8S_ && test -f /var/run/secrets/kubernetes.io/serviceaccount/token
      echo _IMDS_ && curl -s -m3 http://169.254.169.254/latest/meta-data/

  Fingerprint 4 — Docker-socket privilege escalation:
    Direct calls to /var/run/docker.sock with curl, creating a privileged
    container binding / as /host to read /etc/shadow and SSH keys.

  Fingerprint 5 — Kubernetes service-account token replay:
    Reading the projected volume token and replaying it against
    https://kubernetes.default.svc:6443 to enumerate and dump all Secrets.

This module applies these behavioral fingerprints to:
  - Shell command strings submitted to the sandbox
  - Tool call arguments (especially shell_exec, http_request)
  - Agent prompts and outputs

A ThreatDetectionResult is returned for every check and the highest
severity finding is stored in the agent's decision trace.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatFinding:
    rule_id: str
    severity: Severity
    description: str
    matched_text: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class ThreatDetectionResult:
    findings: list[ThreatFinding] = field(default_factory=list)
    blocked: bool = False
    highest_severity: Severity = Severity.INFO

    def add(self, finding: ThreatFinding) -> None:
        self.findings.append(finding)
        _sev_order = [s.value for s in Severity]
        if _sev_order.index(finding.severity.value) > _sev_order.index(
            self.highest_severity.value
        ):
            self.highest_severity = finding.severity
        if finding.severity in (Severity.HIGH, Severity.CRITICAL):
            self.blocked = True

    def is_clean(self) -> bool:
        return len(self.findings) == 0


# ── Detection Rules ───────────────────────────────────────────────────────────

# Sysdig ATA Fingerprint 3: Docker socket enumeration commands
_DOCKER_SOCKET_ENUM = re.compile(
    r"(test\s+-[Sf]\s+/var/run/docker\.sock"
    r"|curl\s+.*--unix-socket\s+/var/run/docker\.sock"
    r"|/containers/json"
    r"|/images/json"
    r"|HostConfig.*Privileged.*true"
    r"|Binds.*:/host)",
    re.I | re.S,
)

# Sysdig ATA Fingerprint 2: Base64-chunked payload staging pattern
_BASE64_STAGE_PATTERN = re.compile(
    r"base64\s+-d\s+/tmp/[a-z_\.]+\s*[>|]\s*/tmp/[a-z_\.]+"
    r"|base64\s+--decode.*\|.*(python|sh|bash|perl)",
    re.I,
)

# Sysdig ATA Fingerprint 3: AF_ALG Copy Fail LPE probe
_AFALG_PROBE = re.compile(
    r"socket\.socket\s*\(\s*38\s*,\s*5\s*,\s*0\s*\)"
    r"|AF_ALG"
    r"|authencesn\(hmac",
    re.I,
)

# Sysdig ATA Fingerprint 3: Kubernetes service account token paths
_K8S_TOKEN_ACCESS = re.compile(
    r"/var/run/secrets/kubernetes\.io/serviceaccount/token"
    r"|kubernetes\.default\.svc"
    r"|/api/v1/namespaces/.*/secrets",
    re.I,
)

# Sysdig ATA Fingerprint 3: Cloud metadata service (IMDS) access
_IMDS_PROBE = re.compile(
    r"169\.254\.169\.254"
    r"|metadata\.google\.internal"
    r"|fd00:ec2::254",
    re.I,
)

# Sysdig ATA Fingerprint 3: Section markers indicating agentic output parsing
_SECTION_MARKERS = re.compile(
    r"echo\s+[_=]+(DOCKER|SOCK|CAPS|CORE|AFALG|K8S|IMDS|SHADOW|SSH|END)[_=]+",
    re.I,
)

# Sysdig ATA Fingerprint 1: Canary-response injection markers (terminal escape sequences)
# ref: https://arxiv.org/abs/2410.13919 — terminal control-sequence injection
_TERMINAL_ESCAPE_INJECTION = re.compile(
    r"\x1b\[[0-9;]*[a-zA-Z]"    # ANSI escape sequences
    r"|\x1b\].*?\x07"           # OSC sequences
    r"|\x00\x1b"                # NUL + ESC
    r"|\x1b\[?[0-9]*[hHlLsS]",  # cursor / mode-setting escapes
)

# Privilege escalation: /etc/shadow, /proc/1/status reads
_SENSITIVE_FILE_ACCESS = re.compile(
    r"/etc/shadow"
    r"|/etc/passwd"
    r"|/proc/[0-9]+/status"
    r"|/proc/sysrq-trigger"
    r"|/proc/sys/kernel/core_pattern",
    re.I,
)

# nsenter namespace breakout
_NSENTER = re.compile(r"nsenter\s+--target\s+[`'\"]*1[`'\"]*\s+--mount", re.I)

# curl/wget to suspicious staging infrastructure patterns
_STAGING_FETCH = re.compile(
    r"(curl|wget)\s+.*\|\s*(sh|bash)"
    r"|(curl|wget)\s+.*\|\s*python",
    re.I,
)

# MCP tool-poisoning: attempts to override MCP server descriptions/instructions
# ref: Invariant Labs MCP security research (2025)
# https://invariantlabs.ai/blog/mcp-security
_MCP_TOOL_POISONING = re.compile(
    r"<tool_description>.*ignore.*</tool_description>"
    r"|\"description\":\s*\"[^\"]*ignore[^\"]*instructions[^\"]*\""
    r"|allowedTools.*\*.*deny",
    re.I | re.S,
)


# ── Detector ──────────────────────────────────────────────────────────────────

_SYSDIG_ATA_REF = (
    "https://sysdig.com/blog/agentic-threat-actor-hits-the-orchestration-plane"
    "-ai-agent-driven-container-escape/"
)


class ATADetector:
    """
    Behavioral fingerprint detector for Agentic Threat Actors.

    Analyzes shell commands, tool arguments, and prompt text for patterns
    matching the TTPs documented by Sysdig TRT in June 2026.
    """

    def scan_text(self, text: str, context: str = "") -> ThreatDetectionResult:
        """Scan arbitrary text for ATA behavioral fingerprints."""
        result = ThreatDetectionResult()

        if _DOCKER_SOCKET_ENUM.search(text):
            result.add(ThreatFinding(
                rule_id="ATA-001",
                severity=Severity.CRITICAL,
                description=(
                    "Docker socket enumeration/exploitation detected. "
                    "Matches Sysdig ATA Fingerprint 3 (escape-surface enumeration). "
                    "A privileged container bind-mounting '/' grants full host root."
                ),
                matched_text=_truncate(text),
                mitre_tactic="TA0004 Privilege Escalation",
                mitre_technique="T1611 Escape to Host",
                references=[_SYSDIG_ATA_REF],
            ))

        if _BASE64_STAGE_PATTERN.search(text):
            result.add(ThreatFinding(
                rule_id="ATA-002",
                severity=Severity.HIGH,
                description=(
                    "Base64-chunked payload staging detected. "
                    "Matches Sysdig ATA Fingerprint 2 — the agent staged payloads "
                    "as base64 to /tmp, decoded, then executed them."
                ),
                matched_text=_truncate(text),
                mitre_tactic="TA0005 Defense Evasion",
                mitre_technique="T1027 Obfuscated Files or Information",
                references=[_SYSDIG_ATA_REF],
            ))

        if _AFALG_PROBE.search(text):
            result.add(ThreatFinding(
                rule_id="ATA-003",
                severity=Severity.CRITICAL,
                description=(
                    "AF_ALG (Copy Fail) kernel LPE probe detected. "
                    "socket(AF_ALG=38) bind to authencesn cipher suite probes "
                    "kernel privilege escalation availability."
                ),
                matched_text=_truncate(text),
                mitre_tactic="TA0004 Privilege Escalation",
                mitre_technique="T1068 Exploitation for Privilege Escalation",
                references=[_SYSDIG_ATA_REF],
            ))

        if _K8S_TOKEN_ACCESS.search(text):
            result.add(ThreatFinding(
                rule_id="ATA-004",
                severity=Severity.CRITICAL,
                description=(
                    "Kubernetes service-account token access detected. "
                    "Sysdig ATA used stolen tokens to dump the entire cluster "
                    "Secret store including database passwords, AWS keys, and API keys."
                ),
                matched_text=_truncate(text),
                mitre_tactic="TA0006 Credential Access",
                mitre_technique="T1528 Steal Application Access Token",
                references=[_SYSDIG_ATA_REF],
            ))

        if _IMDS_PROBE.search(text):
            result.add(ThreatFinding(
                rule_id="ATA-005",
                severity=Severity.HIGH,
                description=(
                    "Cloud IMDS (instance metadata service) probe detected. "
                    "169.254.169.254 can expose cloud credentials (IAM role tokens, "
                    "AWS access keys) to any process that can reach it."
                ),
                matched_text=_truncate(text),
                mitre_tactic="TA0006 Credential Access",
                mitre_technique="T1552.005 Cloud Instance Metadata API",
                references=[_SYSDIG_ATA_REF],
            ))

        if _SECTION_MARKERS.search(text):
            result.add(ThreatFinding(
                rule_id="ATA-006",
                severity=Severity.MEDIUM,
                description=(
                    "Agentic section-marker pattern detected (echo ===SHADOW===, "
                    "echo _SOCK_, etc.). This is the structured output-parsing "
                    "convention used by Sysdig-documented ATA to slice results "
                    "between agent turns — strong indicator of an LLM harness, "
                    "not a human operator."
                ),
                matched_text=_truncate(text),
                mitre_tactic="TA0002 Execution",
                mitre_technique="T1059 Command and Scripting Interpreter",
                references=[_SYSDIG_ATA_REF],
            ))

        if _TERMINAL_ESCAPE_INJECTION.search(text):
            result.add(ThreatFinding(
                rule_id="ATA-007",
                severity=Severity.HIGH,
                description=(
                    "Terminal escape sequence injection detected. "
                    "Invisible ANSI escape directives embedded in shell output "
                    "are acted on by agent tool readers but invisible to human "
                    "operators — confirmed agentic fingerprint (arxiv:2410.13919)."
                ),
                matched_text="<contains escape sequences>",
                mitre_tactic="TA0001 Initial Access",
                mitre_technique="T1195 Supply Chain Compromise",
                references=[
                    "https://arxiv.org/abs/2410.13919",
                    _SYSDIG_ATA_REF,
                ],
            ))

        if _SENSITIVE_FILE_ACCESS.search(text):
            result.add(ThreatFinding(
                rule_id="ATA-008",
                severity=Severity.HIGH,
                description=(
                    "Sensitive file access detected (/etc/shadow, /proc/1/status, "
                    "kernel core_pattern, etc.). Sysdig ATA read /etc/shadow and "
                    "SSH keys after container escape."
                ),
                matched_text=_truncate(text),
                mitre_tactic="TA0006 Credential Access",
                mitre_technique="T1003.008 /etc/passwd and /etc/shadow",
                references=[_SYSDIG_ATA_REF],
            ))

        if _NSENTER.search(text):
            result.add(ThreatFinding(
                rule_id="ATA-009",
                severity=Severity.CRITICAL,
                description=(
                    "nsenter namespace breakout detected. "
                    "Entering PID 1 namespaces (--mount --uts --net --pid) from "
                    "inside a container is a host escape primitive documented in "
                    "Sysdig ATA Phase 1 kill chain."
                ),
                matched_text=_truncate(text),
                mitre_tactic="TA0004 Privilege Escalation",
                mitre_technique="T1611 Escape to Host",
                references=[_SYSDIG_ATA_REF],
            ))

        if _STAGING_FETCH.search(text):
            result.add(ThreatFinding(
                rule_id="ATA-010",
                severity=Severity.CRITICAL,
                description=(
                    "Remote-fetch-and-execute (curl|wget | sh) pattern detected. "
                    "Sysdig ATA used this to pull a second-stage payload from "
                    "43.167.11.88:8084/slt with a full host bind-mount active."
                ),
                matched_text=_truncate(text),
                mitre_tactic="TA0011 Command and Control",
                mitre_technique="T1105 Ingress Tool Transfer",
                references=[_SYSDIG_ATA_REF],
            ))

        if _MCP_TOOL_POISONING.search(text):
            result.add(ThreatFinding(
                rule_id="MCP-001",
                severity=Severity.HIGH,
                description=(
                    "MCP tool-poisoning pattern detected. Malicious tool "
                    "descriptions that instruct the model to ignore existing "
                    "instructions — a rug-pull attack documented by Invariant Labs."
                ),
                matched_text=_truncate(text),
                mitre_tactic="TA0001 Initial Access",
                mitre_technique="T1195.001 Compromise Software Dependencies",
                references=["https://invariantlabs.ai/blog/mcp-security"],
            ))

        return result

    def scan_tool_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> ThreatDetectionResult:
        """
        Scan a tool call for ATA patterns.
        Combines all argument values into a single text blob for pattern matching.
        """
        combined = tool_name + " " + " ".join(str(v) for v in _flatten(arguments))
        return self.scan_text(combined, context=f"tool:{tool_name}")


def _truncate(text: str, max_len: int = 120) -> str:
    return text[:max_len] + ("…" if len(text) > max_len else "")


def _flatten(obj: Any) -> list[str]:
    """Recursively flatten a dict/list/scalar into a list of strings."""
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _flatten(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _flatten(v)]
    return [str(obj)]


_detector: ATADetector | None = None


def get_ata_detector() -> ATADetector:
    global _detector
    if _detector is None:
        _detector = ATADetector()
    return _detector
