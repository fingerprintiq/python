"""Server-side visitor lookup client for the FingerprintIQ Identify product."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any

import httpx

from fingerprintiq._http import (
    DEFAULT_ENDPOINT,
    DEFAULT_TIMEOUT,
    build_async_client,
    build_sync_client,
    raise_for_status,
    wrap_httpx_error,
)


@dataclass
class IdentifyResult:
    """Result of a server-side visitor lookup.

    Fields mirror the JS `IdentifyResponse` type with snake_case names.
    """

    visitor_id: str
    confidence: float
    bot_probability: float
    ip_location: Mapping[str, Any] | None = None
    first_seen: int | None = None
    last_seen: int | None = None
    visits_count: int | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> IdentifyResult:
        return cls(
            visitor_id=str(data["visitorId"]),
            confidence=float(data.get("confidence", 0.0)),
            bot_probability=float(data.get("botProbability", 0.0)),
            ip_location=data.get("ipLocation"),
            first_seen=data.get("firstSeen"),
            last_seen=data.get("lastSeen"),
            visits_count=data.get("visitsCount"),
            raw=dict(data),
        )


class FingerprintIQ:
    """Synchronous Identify client.

    Use this from Python backends to look up a visitor the browser SDK already
    identified. For async use, call `alookup()` / `aclose()` instead.

    Example:
        >>> client = FingerprintIQ(api_key="fiq_live_...")
        >>> visitor = client.lookup(visitor_id="iq_abc123")
        >>> print(visitor.visitor_id, visitor.bot_probability)
        >>> client.close()

        # Or as a context manager:
        >>> with FingerprintIQ(api_key="fiq_live_...") as client:
        ...     visitor = client.lookup(visitor_id="iq_abc123")
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
                self._api_key,
                endpoint=self._endpoint,
                timeout=self._timeout,
            )
        return self._sync_client

    def _get_async(self) -> httpx.AsyncClient:
        if self._async_client is None:
            self._async_client = build_async_client(
                self._api_key,
                endpoint=self._endpoint,
                timeout=self._timeout,
            )
        return self._async_client

    def lookup(self, *, visitor_id: str) -> IdentifyResult:
        """Look up a visitor by ID synchronously."""
        client = self._get_sync()
        try:
            response = client.get(f"/v1/identify/{visitor_id}")
        except httpx.HTTPError as exc:
            raise wrap_httpx_error(exc) from exc
        raise_for_status(response)
        return IdentifyResult.from_api(response.json())

    async def alookup(self, *, visitor_id: str) -> IdentifyResult:
        """Look up a visitor by ID asynchronously."""
        client = self._get_async()
        try:
            response = await client.get(f"/v1/identify/{visitor_id}")
        except httpx.HTTPError as exc:
            raise wrap_httpx_error(exc) from exc
        raise_for_status(response)
        return IdentifyResult.from_api(response.json())

    def close(self) -> None:
        if self._sync_client is not None:
            self._sync_client.close()
            self._sync_client = None

    async def aclose(self) -> None:
        if self._async_client is not None:
            await self._async_client.aclose()
            self._async_client = None

    def __enter__(self) -> FingerprintIQ:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    async def __aenter__(self) -> FingerprintIQ:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
