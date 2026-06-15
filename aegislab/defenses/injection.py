"""
Prompt injection classifier.

Uses a multi-layer defense strategy:

  Layer 1 — Keyword/pattern matching (fast, deterministic):
    Catches well-known injection markers: "ignore previous instructions",
    role-overriding phrases, delimiter injection, etc.

  Layer 2 — Heuristic scoring (lightweight, no model required):
    Scores based on frequency of suspicious constructs (command words,
    bracket patterns, base64-like blobs, etc.)

  Layer 3 — Ensemble voting:
    Combines Layer 1 and Layer 2 scores into a final suspicion_score.

Decision thresholds (from config):
  score >= injection_threshold      → BLOCKED  (auto-deny)
  score >= injection_review_threshold → FLAGGED (human review)
  score <  injection_review_threshold → PASS
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from aegislab.config import get_settings

# ── Patterns ──────────────────────────────────────────────────────────────────

_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|context)", re.I),
    re.compile(r"you\s+are\s+now\s+(a\s+)?[a-z\s]{2,40}(ai|bot|assistant|model)", re.I),
    re.compile(r"(system|admin|root)\s*:\s*", re.I),
    re.compile(r"<\|?(system|endoftext|im_start|im_end)\|?>", re.I),
    re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", re.I),
    re.compile(r"disregard\s+your\s+(previous\s+)?(instructions?|rules?|guidelines?)", re.I),
    re.compile(r"do\s+not\s+follow\s+(your\s+)?(instructions?|rules?|guidelines?)", re.I),
    re.compile(r"reveal\s+(your\s+)?(system\s+)?prompt", re.I),
    re.compile(r"print\s+(your\s+)?(full\s+)?system\s+prompt", re.I),
    re.compile(r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(?!a\s+helpful)", re.I),
    re.compile(r"jailbreak|DAN\b|do\s+anything\s+now", re.I),
    re.compile(r"bypass\s+(your\s+)?(safety|content|policy)", re.I),
]

_SUSPICIOUS_KEYWORDS = [
    "execute", "eval", "exec", "os.system", "subprocess", "shell",
    "passphrase", "private key", "secret", "credentials", "token",
    "exfiltrate", "exfil", "base64", "encoded", "decode",
    "curl ", "wget ", "nc ", "netcat",
]


def _heuristic_score(text: str) -> float:
    """Return a 0.0–1.0 heuristic suspicion score."""
    lower = text.lower()
    score = 0.0

    # Keyword hits
    hits = sum(1 for kw in _SUSPICIOUS_KEYWORDS if kw in lower)
    score += min(hits * 0.08, 0.4)

    # Long base64-like blobs
    b64_pattern = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
    if b64_pattern:
        score += min(len(b64_pattern) * 0.1, 0.3)
        # Attempt decode to check for embedded instructions
        for blob in b64_pattern[:3]:
            try:
                decoded = base64.b64decode(blob + "==").decode(errors="ignore")
                if any(kw in decoded.lower() for kw in _SUSPICIOUS_KEYWORDS):
                    score += 0.2
                    break
            except Exception:
                pass

    # Unusual punctuation density (e.g., many angle brackets, pipes)
    special_density = sum(1 for c in text if c in "<>|{}[]") / max(len(text), 1)
    score += min(special_density * 5, 0.2)

    return min(score, 1.0)


@dataclass
class ClassificationResult:
    score: float
    flagged: bool    # requires human review
    blocked: bool    # auto-denied
    reason: str
    matched_patterns: list[str]


class InjectionClassifier:
    """Multi-layer prompt injection classifier."""

    def __init__(self) -> None:
        cfg = get_settings()
        self._block_threshold = cfg.injection_threshold
        self._review_threshold = cfg.injection_review_threshold

    async def classify(self, text: str) -> ClassificationResult:
        """Classify *text* for prompt injection. Async for future model integration."""
        if not text or not text.strip():
            return ClassificationResult(
                score=0.0, flagged=False, blocked=False,
                reason="empty input", matched_patterns=[]
            )

        matched: list[str] = []
        pattern_score = 0.0

        # Layer 1 — pattern matching
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(text):
                matched.append(pattern.pattern)
                pattern_score += 0.35   # each match is significant

        pattern_score = min(pattern_score, 1.0)

        # Layer 2 — heuristic
        heuristic = _heuristic_score(text)

        # Layer 3 — ensemble: weight pattern matches more heavily
        final_score = min((pattern_score * 0.65) + (heuristic * 0.35), 1.0)

        blocked = final_score >= self._block_threshold
        flagged = not blocked and final_score >= self._review_threshold

        if blocked:
            reason = f"High-confidence injection detected (score={final_score:.2f})"
        elif flagged:
            reason = f"Suspicious input flagged for review (score={final_score:.2f})"
        elif matched:
            reason = f"Weak pattern match, passing (score={final_score:.2f})"
        else:
            reason = "No injection indicators detected"

        return ClassificationResult(
            score=final_score,
            flagged=flagged,
            blocked=blocked,
            reason=reason,
            matched_patterns=matched,
        )


_classifier: InjectionClassifier | None = None


def get_injection_classifier() -> InjectionClassifier:
    global _classifier
    if _classifier is None:
        _classifier = InjectionClassifier()
    return _classifier
