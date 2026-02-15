from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import final
from . import Stream

async def start_local_redirector(
    handle_tcp_stream: Callable[[Stream], Awaitable[None]],
    handle_udp_stream: Callable[[Stream], Awaitable[None]],
) -> LocalRedirector: ...
@final
class LocalRedirector:
    # Redirector flow selection helper (legacy intercept-spec syntax).
    # This does not configure network blocking policy JSON.
    @staticmethod
    def describe_spec(spec: str) -> None: ...
    # Redirector-only flow selection control.
    # Network blocking policy is loaded via MITMPROXY_NETWORK_POLICY_PATH.
    def set_intercept(self, spec: str) -> None: ...
    def close(self) -> None: ...
    async def wait_closed(self) -> None: ...
    @staticmethod
    def unavailable_reason() -> str | None: ...

__all__ = [
    "start_local_redirector",
    "LocalRedirector",
]
