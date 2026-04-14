"""Framework-agnostic Sentinel client."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any
from urllib.parse import urlparse

import httpx

from fingerprintiq._http import (
    DEFAULT_ENDPOINT,
    DEFAULT_TIMEOUT,
    build_async_client,
    build_sync_client,
    raise_for_status,
    wrap_httpx_error,
)

SENTINEL_PATH = "/v1/sentinel/inspect"


@dataclass
class SentinelResult:
    """Classification result for an API caller.

    Mirrors the JS `SentinelResult` type at `packages/server/src/types.ts`.
    """

    caller_type: str
    confidence: float
    reasons: list[str] = field(default_factory=list)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> SentinelResult:
        reasons_raw = data.get("reasons") or []
        reasons = [str(r) for r in reasons_raw] if isinstance(reasons_raw, list) else []
        return cls(
            caller_type=str(data.get("callerType", "unknown")),
            confidence=float(data.get("confidence", 0.0)),
            reasons=reasons,
            metadata=dict(data.get("metadata") or {}),
            raw=dict(data),
        )


class Sentinel:
    """Synchronous + asynchronous Sentinel client.

    Most users will install the FastAPI middleware instead of instantiating this
    directly. See `fingerprintiq.sentinel.fastapi.SentinelMiddleware`.
    """

    def __init__(
        self,
        *,
        api_key: str,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        self._api_key = api_key
        self._endpoint = endpoint
        self._timeout = timeout
        self._sync_client: httpx.Client | None = None
        self._async_client: httpx.AsyncClient | None = None

    def _get_sync(self) -> httpx.Client:
        if self._sync_client is None:
            self._sync_client = build_sync_client(
                self._api_key, endpoint=self._endpoint, timeout=self._timeout
            )
        return self._sync_client

    def _get_async(self) -> httpx.AsyncClient:
        if self._async_client is None:
            self._async_client = build_async_client(
                self._api_key, endpoint=self._endpoint, timeout=self._timeout
            )
        return self._async_client

    def _build_body(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
    ) -> dict[str, Any]:
        parsed = urlparse(url)
        user_agent = ""
        for key, value in headers.items():
            if key.lower() == "user-agent":
                user_agent = value
                break
        return {
            "userAgent": user_agent,
            "headers": {k.lower(): v for k, v in headers.items()},
            "method": method.upper(),
            "path": parsed.path or "/",
        }

    def inspect_raw(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
    ) -> SentinelResult:
        client = self._get_sync()
        body = self._build_body(method=method, url=url, headers=headers)
        try:
            response = client.post(SENTINEL_PATH, json=body)
        except httpx.HTTPError as exc:
            raise wrap_httpx_error(exc) from exc
        raise_for_status(response)
        return SentinelResult.from_api(response.json())

    async def ainspect_raw(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
    ) -> SentinelResult:
        client = self._get_async()
        try:
            response = await client.post(
                SENTINEL_PATH, json=self._build_body(method=method, url=url, headers=headers)
            )
        except httpx.HTTPError as exc:
            raise wrap_httpx_error(exc) from exc
        raise_for_status(response)
        return SentinelResult.from_api(response.json())

    def close(self) -> None:
        if self._sync_client is not None:
            self._sync_client.close()
            self._sync_client = None

    async def aclose(self) -> None:
        if self._async_client is not None:
            await self._async_client.aclose()
            self._async_client = None

    def __enter__(self) -> Sentinel:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
