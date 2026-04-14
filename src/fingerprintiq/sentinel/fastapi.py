"""FastAPI / Starlette middleware for Sentinel."""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from fingerprintiq._http import DEFAULT_ENDPOINT, DEFAULT_TIMEOUT
from fingerprintiq.sentinel._core import Sentinel


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
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        super().__init__(app)
        self._client = Sentinel(api_key=api_key, endpoint=endpoint, timeout=timeout)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        try:
            headers = {k: v for k, v in request.headers.items()}
            result = await self._client.ainspect_raw(
                method=request.method,
                url=str(request.url),
                headers=headers,
            )
            request.state.sentinel = result
        except Exception:
            request.state.sentinel = None
        return await call_next(request)
