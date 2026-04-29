"""FastAPI / Starlette middleware for Sentinel."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from fingerprintiq._http import DEFAULT_ENDPOINT
from fingerprintiq.sentinel._core import DEFAULT_SENTINEL_TIMEOUT, Sentinel, SentinelMode


class SentinelMiddleware(BaseHTTPMiddleware):
    """Attach a `SentinelResult` to `request.state.sentinel` for each request.

    If the upstream API fails for any reason, `request.state.sentinel` is set to
    `None` so the request continues unblocked. This middleware never raises.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        api_key: str,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = DEFAULT_SENTINEL_TIMEOUT,
        mode: SentinelMode = "background",
    ) -> None:
        super().__init__(app)
        if mode not in ("blocking", "background"):
            raise ValueError("mode must be 'blocking' or 'background'")
        self._client = Sentinel(api_key=api_key, endpoint=endpoint, timeout=timeout)
        self._mode = mode
        self._background_tasks: set[asyncio.Task[object]] = set()

    async def _inspect(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
    ) -> object | None:
        try:
            return await self._client.ainspect_raw(
                method=method,
                url=url,
                headers=headers,
            )
        except Exception:
            return None

    def _inspect_in_background(self, request: Request) -> None:
        task = asyncio.create_task(
            self._inspect(
                method=request.method,
                url=str(request.url),
                headers={k: v for k, v in request.headers.items()},
            )
        )
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if self._mode == "background":
            request.state.sentinel = None
            self._inspect_in_background(request)
            return await call_next(request)

        request.state.sentinel = await self._inspect(
            method=request.method,
            url=str(request.url),
            headers={k: v for k, v in request.headers.items()},
        )
        return await call_next(request)
