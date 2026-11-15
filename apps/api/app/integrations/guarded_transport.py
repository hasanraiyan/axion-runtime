"""
Guarded ``httpx2`` transport (SRS-07 FR-40).

The official MCP SDK takes an ``httpx2.AsyncClient``; giving it a client built on this
transport means **every** request it makes, including each redirect hop it chooses to
follow, is validated by the ``OutboundUrlGuard`` and sent to the pinned IP. The original
hostname is preserved for the ``Host`` header and TLS SNI/verification, so certificate
checks still apply while DNS can no longer change between validation and connection.
"""
from __future__ import annotations

from typing import Iterable, Optional

import httpx2

from app.core.outbound import OutboundUrlGuard


class GuardedAsyncTransport(httpx2.AsyncBaseTransport):
    def __init__(
        self,
        guard: OutboundUrlGuard,
        *,
        allowed_hosts: Optional[Iterable[str]] = None,
        inner: Optional[httpx2.AsyncBaseTransport] = None,
        pin_ips: bool = True,
    ) -> None:
        self._guard = guard
        self._allowed_hosts = list(allowed_hosts) if allowed_hosts is not None else None
        self._inner = inner if inner is not None else httpx2.AsyncHTTPTransport()
        self._pin = pin_ips

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        target = await self._guard.check(str(request.url), allowed_hosts=self._allowed_hosts)

        if self._pin and target.pinned_ips:
            headers = request.headers.copy()
            headers["Host"] = request.url.netloc.decode("ascii")
            extensions = dict(request.extensions)
            if target.scheme == "https":
                extensions["sni_hostname"] = target.host
            request = httpx2.Request(
                method=request.method,
                url=request.url.copy_with(host=target.pinned_ips[0]),
                headers=headers,
                stream=request.stream,
                extensions=extensions,
            )
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()
