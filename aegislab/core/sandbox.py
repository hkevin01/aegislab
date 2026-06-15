"""
Sandbox management — ephemeral, isolated execution environments.

Supports two drivers:
  - "subprocess"  : lightweight in-process sandbox for development/testing
  - "docker"      : ephemeral Docker containers with resource limits,
                    seccomp, read-only root FS, and no-new-privileges

The sandbox injects the agent identity token as AEGISLAB_AGENT_TOKEN and
routes outbound traffic through the egress proxy by setting HTTP_PROXY /
HTTPS_PROXY environment variables.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import uuid
from dataclasses import dataclass, field
from typing import Any

from aegislab.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    container_id: str | None = None


@dataclass
class SandboxConfig:
    agent_token: str
    image: str = ""
    memory_limit: str = "256m"
    cpu_quota: int = 50000
    extra_env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 300
    network_mode: str = "bridge"


class SandboxError(Exception):
    """Raised when a sandbox cannot be created or managed."""


class SubprocessSandbox:
    """
    Minimal sandbox using a subprocess — suitable for local development only.
    Does NOT provide true isolation; use the Docker driver in production.
    """

    async def run(
        self,
        command: list[str],
        config: SandboxConfig,
        working_dir: str | None = None,
    ) -> SandboxResult:
        cfg = get_settings()
        env = {
            "AEGISLAB_AGENT_TOKEN": config.agent_token,
            "HTTP_PROXY": f"http://{cfg.egress_proxy_host}:{cfg.egress_proxy_port}",
            "HTTPS_PROXY": f"http://{cfg.egress_proxy_host}:{cfg.egress_proxy_port}",
            **config.extra_env,
        }
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                env=env,
                cwd=working_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=config.timeout_seconds
            )
            return SandboxResult(
                exit_code=proc.returncode or 0,
                stdout=stdout_bytes.decode(errors="replace"),
                stderr=stderr_bytes.decode(errors="replace"),
            )
        except asyncio.TimeoutError as exc:
            raise SandboxError(
                f"Subprocess timed out after {config.timeout_seconds}s"
            ) from exc


class DockerSandbox:
    """
    Docker-based ephemeral sandbox.

    Each task gets a fresh container with:
      - read-only root filesystem
      - no-new-privileges security opt
      - resource limits (memory, CPU)
      - agent token injected as environment variable
      - egress proxy routing
    """

    def __init__(self) -> None:
        try:
            import docker  # type: ignore[import]
            self._client = docker.from_env()
        except Exception as exc:
            raise SandboxError(f"Cannot connect to Docker: {exc}") from exc

    async def run(
        self,
        command: list[str],
        config: SandboxConfig,
        working_dir: str | None = None,
    ) -> SandboxResult:
        cfg = get_settings()
        container_name = f"aegislab-task-{uuid.uuid4().hex[:8]}"
        env = {
            "AEGISLAB_AGENT_TOKEN": config.agent_token,
            "HTTP_PROXY": f"http://{cfg.egress_proxy_host}:{cfg.egress_proxy_port}",
            "HTTPS_PROXY": f"http://{cfg.egress_proxy_host}:{cfg.egress_proxy_port}",
            **config.extra_env,
        }
        loop = asyncio.get_running_loop()

        def _create_and_run() -> SandboxResult:
            import docker  # type: ignore[import]

            container = self._client.containers.run(
                config.image or cfg.container_image,
                command=" ".join(command),
                name=container_name,
                environment=env,
                mem_limit=config.memory_limit,
                cpu_quota=config.cpu_quota,
                security_opt=["no-new-privileges:true"],
                read_only=True,
                tmpfs={"/tmp": "size=64m,noexec"},
                network_mode=config.network_mode,
                detach=False,
                remove=True,
                stdout=True,
                stderr=True,
            )
            # When detach=False, containers.run returns log bytes
            output = container if isinstance(container, bytes) else b""
            return SandboxResult(
                exit_code=0,
                stdout=output.decode(errors="replace"),
                stderr="",
                container_id=container_name,
            )

        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _create_and_run),
                timeout=config.timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            logger.warning("Container %s timed out, attempting removal", container_name)
            try:
                container_obj = self._client.containers.get(container_name)
                container_obj.remove(force=True)
            except Exception:
                pass
            raise SandboxError(
                f"Container timed out after {config.timeout_seconds}s"
            ) from exc


def get_sandbox() -> SubprocessSandbox | DockerSandbox:
    """Return the appropriate sandbox driver based on configuration."""
    driver = get_settings().sandbox_driver
    if driver == "docker":
        return DockerSandbox()
    return SubprocessSandbox()
