"""Platform-wide configuration via environment variables."""

from __future__ import annotations

from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGISLAB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Identity / JWT
    jwt_private_key_path: Path = Path("keys/private.pem")
    jwt_public_key_path: Path = Path("keys/public.pem")
    token_ttl_seconds: int = 900
    jwt_algorithm: str = "RS256"
    jwt_issuer: str = "aegislab"

    # Policy
    policy_dir: Path = Path("policies/")
    default_policy: str = "deny"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Egress proxy
    egress_proxy_port: int = 8888
    egress_proxy_host: str = "127.0.0.1"
    egress_allow_domains: str = ""

    # Injection defenses
    injection_threshold: float = 0.7
    injection_review_threshold: float = 0.4

    # Human approval
    human_approval_webhook: str = ""
    human_approval_timeout_seconds: int = 300

    # Sandbox
    sandbox_driver: str = "subprocess"
    container_image: str = "python:3.11-slim"
    container_memory_limit: str = "256m"
    container_cpu_quota: int = 50000

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    log_level: str = "INFO"

    # Observability
    trace_log_file: Path = Path("logs/traces.jsonl")
    metrics_port: int = 9090

    @property
    def egress_allow_domain_list(self) -> list[str]:
        return [d.strip() for d in self.egress_allow_domains.split(",") if d.strip()]


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
