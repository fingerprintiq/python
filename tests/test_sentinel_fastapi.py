from __future__ import annotations

import asyncio
import time

import respx
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from httpx import Response

from fingerprintiq.sentinel import Sentinel, SentinelResult
from fingerprintiq.sentinel.fastapi import SentinelMiddleware

API_RESPONSE = {
    "callerType": "browser",
    "confidence": 0.88,
    "reasons": ["ua-chrome"],
    "metadata": {},
}


def _make_app(**middleware_kwargs) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SentinelMiddleware, api_key="fiq_live_test", **middleware_kwargs)

    @app.get("/probe")
    def probe(request: Request) -> dict:
        result = getattr(request.state, "sentinel", None)
        if result is None:
            return {"caller": None}
        return {"caller": result.caller_type, "confidence": result.confidence}

    return app


@respx.mock
def test_middleware_populates_request_state():
    respx.post("https://fingerprintiq.com/v1/sentinel/inspect").mock(
        return_value=Response(200, json=API_RESPONSE),
    )

    client = TestClient(_make_app(mode="blocking"))
    response = client.get("/probe", headers={"user-agent": "Mozilla/5.0"})
    assert response.status_code == 200
    assert response.json() == {"caller": "browser", "confidence": 0.88}


@respx.mock
def test_middleware_sets_none_on_api_failure():
    respx.post("https://fingerprintiq.com/v1/sentinel/inspect").mock(
        return_value=Response(500, text="boom"),
    )

    client = TestClient(_make_app(mode="blocking"))
    response = client.get("/probe", headers={"user-agent": "Mozilla/5.0"})
    assert response.status_code == 200
    assert response.json() == {"caller": None}


def test_default_mode_does_not_wait_for_inspection(monkeypatch):
    calls: list[str] = []

    async def slow_inspect(
        self: Sentinel,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
    ) -> SentinelResult:
        calls.append("started")
        await asyncio.sleep(0.2)
        calls.append("finished")
        return SentinelResult(caller_type="browser", confidence=0.88)

    monkeypatch.setattr(Sentinel, "ainspect_raw", slow_inspect)

    with TestClient(_make_app()) as client:
        started_at = time.perf_counter()
        response = client.get("/probe", headers={"user-agent": "Mozilla/5.0"})
        elapsed = time.perf_counter() - started_at

        assert response.status_code == 200
        assert response.json() == {"caller": None}
        assert elapsed < 0.1

        time.sleep(0.25)
        assert calls == ["started", "finished"]
