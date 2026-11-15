"""
Real-socket test server: runs an ASGI app under uvicorn on a loopback port inside the current event loop.

Needed where an in-process ``ASGITransport`` cannot carry the traffic, namely long-lived SSE streams (the legacy MCP
transport and the standalone ``list_changed`` stream). Clients must use a guard that allows loopback and plain http.
"""
import asyncio
import contextlib
import socket
from typing import Any, AsyncIterator

import uvicorn


@contextlib.asynccontextmanager
async def serve(app: Any) -> AsyncIterator[str]:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="on"))
    server.capture_signals = contextlib.nullcontext  # type: ignore[method-assign]  # signals belong to the test runner
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(200):
            if server.started:
                break
            if task.done():
                task.result()
            await asyncio.sleep(0.025)
        else:
            raise RuntimeError("test server did not start")
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=10)
        sock.close()
