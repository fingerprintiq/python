from __future__ import annotations

import respx
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from httpx import Response

from fingerprintiq.sentinel.fastapi import SentinelMiddleware

API_RESPONSE = {
    "callerType": "browser",
    "confidence": 0.88,
    "reasons": ["ua-chrome"],
    "metadata": {},
}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(SentinelMiddleware, api_key="fiq_live_test")

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

    client = TestClient(_make_app())
    response = client.get("/probe", headers={"user-agent": "Mozilla/5.0"})
    assert response.status_code == 200
    assert response.json() == {"caller": "browser", "confidence": 0.88}


@respx.mock
def test_middleware_sets_none_on_api_failure():
    respx.post("https://fingerprintiq.com/v1/sentinel/inspect").mock(
        return_value=Response(500, text="boom"),
    )

    client = TestClient(_make_app())
    response = client.get("/probe", headers={"user-agent": "Mozilla/5.0"})
    assert response.status_code == 200
    assert response.json() == {"caller": None}
