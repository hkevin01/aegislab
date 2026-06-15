"""Tests for identity service (mocked key pair)."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
from pathlib import Path

from aegislab.core.identity import AgentIdentity, IdentityService, IdentityError


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_service_with_test_keys() -> IdentityService:
    """Create an IdentityService with a fresh in-memory RSA key pair."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    svc = IdentityService.__new__(IdentityService)
    svc._algorithm = "RS256"
    svc._issuer = "aegislab"
    svc._ttl = 900
    svc._private_key = private_pem
    svc._public_key = public_pem
    return svc


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_issue_and_verify_token():
    svc = make_service_with_test_keys()
    token = svc.issue(
        agent_id="data-analyst",
        allowed_tools=["http_request", "filesystem_read"],
        scope="read",
        task_id="task-001",
    )
    identity = svc.verify(token)
    assert identity.agent_id == "data-analyst"
    assert identity.task_id == "task-001"
    assert "http_request" in identity.allowed_tools
    assert identity.scope == "read"
    assert not identity.is_expired


def test_can_use_tool_allowed():
    svc = make_service_with_test_keys()
    token = svc.issue("analyst", ["http_request", "filesystem_read"], "read")
    identity = svc.verify(token)
    assert identity.can_use_tool("http_request")
    assert identity.can_use_tool("filesystem_read")
    assert not identity.can_use_tool("shell_exec")


def test_wildcard_tool_permission():
    svc = make_service_with_test_keys()
    token = svc.issue("admin", ["*"], "admin")
    identity = svc.verify(token)
    assert identity.can_use_tool("anything")
    assert identity.can_use_tool("shell_exec")


def test_tampered_token_rejected():
    svc = make_service_with_test_keys()
    token = svc.issue("analyst", ["http_request"], "read")
    # Corrupt the signature portion
    parts = token.split(".")
    tampered = parts[0] + "." + parts[1] + ".invalidsignature"
    with pytest.raises(IdentityError):
        svc.verify(tampered)


def test_token_has_correct_expiry():
    svc = make_service_with_test_keys()
    svc._ttl = 60
    token = svc.issue("analyst", [], "read")
    identity = svc.verify(token)
    ttl_remaining = (identity.expires_at - datetime.now(tz=timezone.utc)).total_seconds()
    assert 50 < ttl_remaining <= 60
