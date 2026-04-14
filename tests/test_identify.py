from __future__ import annotations

import pytest
import respx
from httpx import Response

from fingerprintiq import FingerprintIQ
from fingerprintiq._errors import APIError, RateLimitError

VISITOR_RESPONSE = {
    "visitorId": "iq_abc123",
    "confidence": 0.97,
    "botProbability": 0.02,
    "ipLocation": {"country": "US", "city": "San Francisco"},
    "firstSeen": 1_710_000_000_000,
    "lastSeen": 1_713_000_000_000,
    "visitsCount": 4,
}


@respx.mock
def test_lookup_returns_parsed_result():
    route = respx.get("https://fingerprintiq.com/v1/identify/iq_abc123").mock(
        return_value=Response(200, json=VISITOR_RESPONSE),
    )

    client = FingerprintIQ(api_key="fiq_live_test")
    try:
        result = client.lookup(visitor_id="iq_abc123")
    finally:
        client.close()

    assert route.called
    assert result.visitor_id == "iq_abc123"
    assert result.confidence == 0.97
    assert result.bot_probability == 0.02
    assert result.visits_count == 4
    assert result.ip_location == {"country": "US", "city": "San Francisco"}


@respx.mock
def test_lookup_raises_api_error_on_404():
    respx.get("https://fingerprintiq.com/v1/identify/missing").mock(
        return_value=Response(404, text="not found"),
    )

    client = FingerprintIQ(api_key="fiq_live_test")
    try:
        with pytest.raises(APIError) as exc_info:
            client.lookup(visitor_id="missing")
    finally:
        client.close()

    assert exc_info.value.status_code == 404


@respx.mock
def test_lookup_raises_rate_limit_with_retry_after():
    respx.get("https://fingerprintiq.com/v1/identify/x").mock(
        return_value=Response(429, headers={"retry-after": "45"}, text="slow down"),
    )

    client = FingerprintIQ(api_key="fiq_live_test")
    try:
        with pytest.raises(RateLimitError) as exc_info:
            client.lookup(visitor_id="x")
    finally:
        client.close()

    assert exc_info.value.retry_after == 45


@respx.mock
def test_client_works_as_context_manager():
    respx.get("https://fingerprintiq.com/v1/identify/iq_abc123").mock(
        return_value=Response(200, json=VISITOR_RESPONSE),
    )

    with FingerprintIQ(api_key="fiq_live_test") as client:
        result = client.lookup(visitor_id="iq_abc123")

    assert result.visitor_id == "iq_abc123"


@pytest.mark.asyncio
@respx.mock
async def test_async_lookup():
    respx.get("https://fingerprintiq.com/v1/identify/iq_abc123").mock(
        return_value=Response(200, json=VISITOR_RESPONSE),
    )

    client = FingerprintIQ(api_key="fiq_live_test")
    try:
        result = await client.alookup(visitor_id="iq_abc123")
    finally:
        await client.aclose()

    assert result.visitor_id == "iq_abc123"


def test_api_key_required():
    with pytest.raises(ValueError, match="api_key is required"):
        FingerprintIQ(api_key="")
