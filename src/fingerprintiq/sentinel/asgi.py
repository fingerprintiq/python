"""Bare ASGI middleware for Sentinel — works with any ASGI framework.

Use the FastAPI-specific middleware from `fingerprintiq.sentinel.fastapi` when
possible; this variant exists for Litestar, raw Starlette, and custom ASGI apps.
"""

from __future__ import annotations

import asyncio

from starlette.types import ASGIApp, Receive, Scope, Send

from fingerprintiq._http import DEFAULT_ENDPOINT
from fingerprintiq.sentinel._core import (
    DEFAULT_SENTINEL_TIMEOUT,
    Sentinel,
    SentinelMode,
    SentinelResult,
)


class SentinelASGIMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        api_key: str,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = DEFAULT_SENTINEL_TIMEOUT,
        mode: SentinelMode = "background",
    ) -> None:
        if mode not in ("blocking", "background"):
            raise ValueError("mode must be 'blocking' or 'background'")
        self.app = app
        self._client = Sentinel(api_key=api_key, endpoint=endpoint, timeout=timeout)
        self._mode = mode
        self._background_tasks: set[asyncio.Task[SentinelResult | None]] = set()

    async def _inspect(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
    ) -> SentinelResult | None:
        try:
            return await self._client.ainspect_raw(method=method, url=url, headers=headers)
        except Exception:
            return None

    def _inspect_in_background(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
    ) -> None:
        task = asyncio.create_task(self._inspect(method=method, url=url, headers=headers))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

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

        if self._mode == "background":
            result = None
            self._inspect_in_background(method=method, url=url, headers=headers)
        else:
            result = await self._inspect(method=method, url=url, headers=headers)

        state = scope.setdefault("state", {})
        state["sentinel"] = result

        await self.app(scope, receive, send)
