"""
Short-lived, cryptographically signed agent identity tokens.

Every agent invocation receives an RS256 JWT that encodes:
  - agent_id     : stable identifier for the agent type
  - task_id      : unique identifier for this specific invocation
  - allowed_tools: list of tool names the agent may call
  - scope        : coarse permission level (read | write | admin)
  - iat / exp    : issued-at / expiry (default TTL from config)

No shared API keys — secrets are injected at container spawn time
and destroyed when the container is torn down.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jose import jwt, JWTError

from aegislab.config import get_settings


class IdentityError(Exception):
    """Raised when token issuance or verification fails."""


class AgentIdentity:
    """Represents the verified identity of a running agent task."""

    def __init__(self, claims: dict[str, Any]) -> None:
        self._claims = claims

    @property
    def agent_id(self) -> str:
        return str(self._claims["agent_id"])

    @property
    def task_id(self) -> str:
        return str(self._claims["task_id"])

    @property
    def allowed_tools(self) -> list[str]:
        return list(self._claims.get("allowed_tools", []))

    @property
    def scope(self) -> str:
        return str(self._claims.get("scope", "read"))

    @property
    def expires_at(self) -> datetime:
        return datetime.fromtimestamp(int(self._claims["exp"]), tz=timezone.utc)

    @property
    def issued_at(self) -> datetime:
        return datetime.fromtimestamp(int(self._claims["iat"]), tz=timezone.utc)

    @property
    def is_expired(self) -> bool:
        return datetime.now(tz=timezone.utc) >= self.expires_at

    def can_use_tool(self, tool_name: str) -> bool:
        """Return True if this identity is permitted to call *tool_name*."""
        allowed = self.allowed_tools
        if "*" in allowed:
            return True
        return tool_name in allowed

    def to_dict(self) -> dict[str, Any]:
        return dict(self._claims)

    def __repr__(self) -> str:
        return (
            f"AgentIdentity(agent_id={self.agent_id!r}, task_id={self.task_id!r}, "
            f"scope={self.scope!r}, tools={self.allowed_tools})"
        )


class IdentityService:
    """Issues and verifies short-lived agent identity tokens."""

    def __init__(self) -> None:
        cfg = get_settings()
        self._algorithm = cfg.jwt_algorithm
        self._issuer = cfg.jwt_issuer
        self._ttl = cfg.token_ttl_seconds
        self._private_key = self._load_key(cfg.jwt_private_key_path)
        self._public_key = self._load_key(cfg.jwt_public_key_path)

    @staticmethod
    def _load_key(path: Path) -> str:
        if not path.exists():
            raise IdentityError(
                f"Key file not found: {path}. Run 'make keys' to generate a key pair."
            )
        return path.read_text()

    def issue(
        self,
        agent_id: str,
        allowed_tools: list[str],
        scope: str = "read",
        ttl_override: int | None = None,
        task_id: str | None = None,
    ) -> str:
        """
        Issue a signed JWT for an agent invocation.

        Returns the raw token string. The caller should treat this as a
        secret — pass it into the container environment and discard it
        after the task completes.
        """
        now = int(datetime.now(tz=timezone.utc).timestamp())
        ttl = ttl_override if ttl_override is not None else self._ttl
        claims: dict[str, Any] = {
            "iss": self._issuer,
            "iat": now,
            "exp": now + ttl,
            "agent_id": agent_id,
            "task_id": task_id or str(uuid.uuid4()),
            "allowed_tools": allowed_tools,
            "scope": scope,
        }
        return jwt.encode(claims, self._private_key, algorithm=self._algorithm)

    def verify(self, token: str) -> AgentIdentity:
        """
        Verify and decode a token.

        Raises IdentityError on any failure (expired, bad signature, etc.).
        """
        try:
            claims = jwt.decode(
                token,
                self._public_key,
                algorithms=[self._algorithm],
                issuer=self._issuer,
            )
        except JWTError as exc:
            raise IdentityError(f"Token verification failed: {exc}") from exc
        return AgentIdentity(claims)


# Module-level singleton — initialised lazily so tests can monkeypatch config.
_identity_service: IdentityService | None = None


def get_identity_service() -> IdentityService:
    global _identity_service
    if _identity_service is None:
        _identity_service = IdentityService()
    return _identity_service
