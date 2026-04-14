from __future__ import annotations

import pytest
import respx
from httpx import Response

from fingerprintiq.sentinel import Sentinel, SentinelResult

API_RESPONSE = {
    "callerType": "ai-agent",
    "confidence": 0.93,
    "reasons": ["user-agent-match", "ja4-signature"],
    "metadata": {"agent": "ClaudeBot"},
}


@respx.mock
def test_inspect_parses_result():
    respx.post("https://fingerprintiq.com/v1/sentinel/inspect").mock(
        return_value=Response(200, json=API_RESPONSE),
    )

    sentinel = Sentinel(api_key="fiq_live_test")
    try:
        result = sentinel.inspect_raw(
            method="GET",
            url="https://my.api/data",
            headers={"user-agent": "ClaudeBot"},
        )
    finally:
        sentinel.close()

    assert isinstance(result, SentinelResult)
    assert result.caller_type == "ai-agent"
    assert result.confidence == 0.93
    assert "user-agent-match" in result.reasons


@pytest.mark.asyncio
@respx.mock
async def test_ainspect_parses_result():
    respx.post("https://fingerprintiq.com/v1/sentinel/inspect").mock(
        return_value=Response(200, json=API_RESPONSE),
    )

    sentinel = Sentinel(api_key="fiq_live_test")
    try:
        result = await sentinel.ainspect_raw(
            method="GET",
            url="https://my.api/data",
            headers={"user-agent": "ClaudeBot"},
        )
    finally:
        await sentinel.aclose()

    assert result.caller_type == "ai-agent"
