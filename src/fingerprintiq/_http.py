"""Shared HTTP client configuration for FingerprintIQ SDK components."""

from __future__ import annotations

import httpx

from fingerprintiq._errors import APIError, RateLimitError, TimeoutError
from fingerprintiq._version import __version__

DEFAULT_TIMEOUT = 10.0
DEFAULT_ENDPOINT = "https://fingerprintiq.com"
USER_AGENT = f"fingerprintiq-python/{__version__}"


def build_sync_client(
    api_key: str,
    *,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: float = DEFAULT_TIMEOUT,
) -> httpx.Client:
    return httpx.Client(
        base_url=endpoint,
        timeout=timeout,
        headers={
            "X-API-Key": api_key,
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        },
    )


def build_async_client(
    api_key: str,
    *,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: float = DEFAULT_TIMEOUT,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=endpoint,
        timeout=timeout,
        headers={
            "X-API-Key": api_key,
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        },
    )


def raise_for_status(response: httpx.Response) -> None:
    """Translate non-2xx responses into the SDK error hierarchy."""
    if 200 <= response.status_code < 300:
        return

    body = response.text
    if response.status_code == 429:
        retry_after_header = response.headers.get("retry-after")
        retry_after: int | None = None
        if retry_after_header is not None:
            try:
                retry_after = int(retry_after_header)
            except ValueError:
                retry_after = None
        raise RateLimitError(
            f"rate limited: {body[:200]}",
            retry_after=retry_after,
        )
    raise APIError(
        f"API error ({response.status_code}): {body[:200]}",
        status_code=response.status_code,
        body=body,
    )


def wrap_httpx_error(exc: Exception) -> Exception:
    """Map httpx network exceptions to SDK errors."""
    if isinstance(exc, httpx.TimeoutException):
        return TimeoutError(str(exc))
    return exc


__all__ = [
    "DEFAULT_ENDPOINT",
    "DEFAULT_TIMEOUT",
    "USER_AGENT",
    "build_async_client",
    "build_sync_client",
    "raise_for_status",
    "wrap_httpx_error",
]
