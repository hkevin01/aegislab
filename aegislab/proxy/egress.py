"""
Egress proxy enforcement layer.

In production, all agent outbound traffic is routed through a mitmproxy
instance (see docker-compose.yml). This module provides:

  1. EgressGuard — an httpx-compatible transport wrapper that enforces the
     domain allow-list and logs every outbound request. Use this in agent
     code that runs inside the sandbox.

  2. EgressEvent — structured record written to the decision trace.

  3. KillSwitch — monitors the egress event stream and can hard-block an
     agent's outbound traffic when anomalous patterns are detected.
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import time
import urllib.parse
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

import httpx

from aegislab.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class EgressEvent:
    agent_id: str
    task_id: str
    url: str
    method: str
    allowed: bool
    blocked_reason: str = ""
    response_status: int | None = None
    duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


class DomainDeniedError(Exception):
    """Raised when an outbound request is denied by the egress guard."""


class EgressGuard(httpx.AsyncBaseTransport):
    """
    httpx transport that enforces an egress domain allow-list and emits
    EgressEvent records.

    Usage:
        async with httpx.AsyncClient(transport=EgressGuard(agent_id, task_id)) as client:
            resp = await client.get("https://allowed-domain.com/data")
    """

    def __init__(
        self,
        agent_id: str,
        task_id: str,
        kill_switch: "KillSwitch | None" = None,
    ) -> None:
        self._agent_id = agent_id
        self._task_id = task_id
        self._kill_switch = kill_switch
        self._allow_patterns = get_settings().egress_allow_domain_list
        self._inner = httpx.AsyncHTTPTransport()

    def _is_domain_allowed(self, url: str) -> tuple[bool, str]:
        if not self._allow_patterns:
            # No allow-list configured → allow all (development mode)
            return True, ""
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        for pattern in self._allow_patterns:
            if fnmatch.fnmatch(host, pattern):
                return True, ""
        return False, f"Domain '{host}' not in egress allow-list"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        method = request.method

        # Kill switch check
        if self._kill_switch and self._kill_switch.is_blocked(self._agent_id):
            event = EgressEvent(
                agent_id=self._agent_id,
                task_id=self._task_id,
                url=url,
                method=method,
                allowed=False,
                blocked_reason="Kill switch active for agent",
            )
            logger.warning("EGRESS KILL-SWITCH: %s %s", method, url)
            _emit_event(event)
            raise DomainDeniedError(event.blocked_reason)

        allowed, reason = self._is_domain_allowed(url)
        if not allowed:
            event = EgressEvent(
                agent_id=self._agent_id,
                task_id=self._task_id,
                url=url,
                method=method,
                allowed=False,
                blocked_reason=reason,
            )
            logger.warning("EGRESS BLOCKED: %s %s — %s", method, url, reason)
            _emit_event(event)
            raise DomainDeniedError(reason)

        t0 = time.monotonic()
        response = await self._inner.handle_async_request(request)
        duration_ms = (time.monotonic() - t0) * 1000

        event = EgressEvent(
            agent_id=self._agent_id,
            task_id=self._task_id,
            url=url,
            method=method,
            allowed=True,
            response_status=response.status_code,
            duration_ms=duration_ms,
        )
        _emit_event(event)

        if self._kill_switch:
            self._kill_switch.record_request(self._agent_id, url)

        return response


# ── Event bus (in-process pub/sub for dashboard) ──────────────────────────────

_event_listeners: list[asyncio.Queue[EgressEvent]] = []


def subscribe_egress_events() -> asyncio.Queue[EgressEvent]:
    """Subscribe to egress events. Returns a queue that receives new events."""
    q: asyncio.Queue[EgressEvent] = asyncio.Queue(maxsize=1000)
    _event_listeners.append(q)
    return q


def unsubscribe_egress_events(q: asyncio.Queue[EgressEvent]) -> None:
    try:
        _event_listeners.remove(q)
    except ValueError:
        pass


def _emit_event(event: EgressEvent) -> None:
    for q in list(_event_listeners):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass  # Drop if listener is not keeping up


# ── Kill Switch ───────────────────────────────────────────────────────────────

class KillSwitch:
    """
    Monitors outbound request patterns and activates a kill switch when
    anomalous behaviour is detected.

    Current heuristics:
      - More than N unique external hostnames in a sliding 60-second window
        → "mass exfiltration" probe → block agent.
    """

    UNIQUE_HOST_THRESHOLD = 20
    WINDOW_SECONDS = 60

    def __init__(self) -> None:
        self._blocked: set[str] = set()
        # agent_id → deque of (timestamp, hostname)
        self._request_log: dict[str, deque[tuple[float, str]]] = defaultdict(
            lambda: deque(maxlen=500)
        )

    def is_blocked(self, agent_id: str) -> bool:
        return agent_id in self._blocked

    def block(self, agent_id: str, reason: str = "") -> None:
        self._blocked.add(agent_id)
        logger.critical("KILL SWITCH ACTIVATED for agent %s: %s", agent_id, reason)

    def release(self, agent_id: str) -> None:
        self._blocked.discard(agent_id)
        logger.info("Kill switch released for agent %s", agent_id)

    def record_request(self, agent_id: str, url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or url
        now = time.time()
        log = self._request_log[agent_id]
        log.append((now, host))

        # Prune old entries
        cutoff = now - self.WINDOW_SECONDS
        while log and log[0][0] < cutoff:
            log.popleft()

        unique_hosts = len({h for _, h in log})
        if unique_hosts >= self.UNIQUE_HOST_THRESHOLD:
            self.block(
                agent_id,
                f"Contacted {unique_hosts} unique external hosts in {self.WINDOW_SECONDS}s "
                "(possible mass exfiltration)",
            )

    def status(self) -> list[dict[str, Any]]:
        return [
            {
                "agent_id": agent_id,
                "blocked": agent_id in self._blocked,
                "recent_hosts": len({h for _, h in log}),
            }
            for agent_id, log in self._request_log.items()
        ]


_kill_switch: KillSwitch | None = None


def get_kill_switch() -> KillSwitch:
    global _kill_switch
    if _kill_switch is None:
        _kill_switch = KillSwitch()
    return _kill_switch
