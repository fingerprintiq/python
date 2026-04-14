"""Error hierarchy for the FingerprintIQ SDK."""

from __future__ import annotations


class FingerprintIQError(Exception):
    """Base class for all FingerprintIQ SDK errors."""


class APIError(FingerprintIQError):
    """Non-2xx response from the FingerprintIQ API."""

    def __init__(self, message: str, *, status_code: int, body: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class RateLimitError(APIError):
    """HTTP 429 from the FingerprintIQ API."""

    def __init__(self, message: str, *, retry_after: int | None = None) -> None:
        super().__init__(message, status_code=429)
        self.retry_after = retry_after


class TimeoutError(FingerprintIQError):
    """Network timeout reaching the FingerprintIQ API."""
