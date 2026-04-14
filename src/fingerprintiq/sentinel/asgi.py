"""Bare ASGI middleware for Sentinel — works with any ASGI framework.

Use the FastAPI-specific middleware from `fingerprintiq.sentinel.fastapi` when
possible; this variant exists for Litestar, raw Starlette, and custom ASGI apps.
"""

from __future__ import annotations

from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

from fingerprintiq._http import DEFAULT_ENDPOINT, DEFAULT_TIMEOUT
from fingerprintiq.sentinel._core import Sentinel


class SentinelASGIMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        api_key: str,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.app = app
        self._client = Sentinel(api_key=api_key, endpoint=endpoint, timeout=timeout)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers_raw: list[tuple[bytes, bytes]] = scope.get("headers") or []
        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in headers_raw}

        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        host = headers.get("host", "localhost")
        scheme = scope.get("scheme", "http")
        url = f"{scheme}://{host}{path}"

        try:
            result: Any = await self._client.ainspect_raw(
                method=method, url=url, headers=headers
            )
        except Exception:
            result = None

        state = scope.setdefault("state", {})
        state["sentinel"] = result

        await self.app(scope, receive, send)
