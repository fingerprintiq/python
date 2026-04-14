from __future__ import annotations

from unittest.mock import patch

import respx
from httpx import Response

from fingerprintiq.pulse import Pulse


@respx.mock
def test_pulse_respects_do_not_track():
    identify_route = respx.post("https://fingerprintiq.com/v1/pulse/identify").mock(
        return_value=Response(200, json={"machineId": "m_123"}),
    )
    event_route = respx.post("https://fingerprintiq.com/v1/pulse/event").mock(
        return_value=Response(200, json={}),
    )

    with patch.dict("os.environ", {"DO_NOT_TRACK": "1"}, clear=False):
        pulse = Pulse(api_key="fiq_live_test", tool="cli", version="1.0.0")
        pulse.track("deploy")
        pulse.shutdown()

    assert not identify_route.called
    assert not event_route.called


@respx.mock
def test_pulse_respects_fingerprintiq_optout():
    event_route = respx.post("https://fingerprintiq.com/v1/pulse/event").mock(
        return_value=Response(200, json={}),
    )

    with patch.dict("os.environ", {"FINGERPRINTIQ_OPTOUT": "true"}, clear=False):
        pulse = Pulse(api_key="fiq_live_test", tool="cli", version="1.0.0")
        pulse.track("build")
        pulse.shutdown()

    assert not event_route.called


@respx.mock
def test_pulse_can_opt_back_in_explicitly():
    respx.post("https://fingerprintiq.com/v1/pulse/identify").mock(
        return_value=Response(200, json={"machineId": "m_123"}),
    )
    event_route = respx.post("https://fingerprintiq.com/v1/pulse/event").mock(
        return_value=Response(200, json={}),
    )

    with patch.dict("os.environ", {"DO_NOT_TRACK": "1"}, clear=False):
        pulse = Pulse(
            api_key="fiq_live_test",
            tool="cli",
            version="1.0.0",
            respect_opt_out=False,
        )
        pulse.track("deploy")
        pulse.flush()
        pulse.shutdown()

    assert event_route.called
