from __future__ import annotations

import respx
from httpx import Response

from fingerprintiq.pulse._fingerprint import MachineFingerprint
from fingerprintiq.pulse._transport import PulseTransport

FAKE_FP = MachineFingerprint(
    fingerprint_hash="hash",
    os="linux",
    arch="x64",
    cpu_model="Fake CPU",
    core_count=4,
    memory_gb=8.0,
    runtime="python",
    runtime_version="3.12.0",
    shell="bash",
    is_ci=False,
    is_container=False,
    ci_provider=None,
    container_type=None,
    locale="en-US",
    timezone="UTC",
    os_version="Linux 6.0",
    terminal_emulator=None,
    package_manager=None,
    python_version_major=3,
    is_tty=False,
    terminal_columns=None,
    wsl_distro=None,
)


@respx.mock
def test_identify_then_flush_events():
    identify_route = respx.post("https://fingerprintiq.com/v1/pulse/identify").mock(
        return_value=Response(200, json={"machineId": "m_123"}),
    )
    event_route = respx.post("https://fingerprintiq.com/v1/pulse/event").mock(
        return_value=Response(200, json={}),
    )

    transport = PulseTransport(
        api_key="fiq_live_test",
        tool="test-cli",
        version="1.0.0",
        flush_interval=3600,
    )
    transport.identify(FAKE_FP)
    transport.enqueue({"command": "deploy", "timestamp": 1234})
    transport.enqueue({"command": "build", "timestamp": 1235})
    transport.flush()
    transport.shutdown()

    assert identify_route.called
    assert event_route.called
    assert event_route.call_count == 1


@respx.mock
def test_auto_flush_when_buffer_exceeds_max_batch():
    respx.post("https://fingerprintiq.com/v1/pulse/identify").mock(
        return_value=Response(200, json={"machineId": "m_123"}),
    )
    event_route = respx.post("https://fingerprintiq.com/v1/pulse/event").mock(
        return_value=Response(200, json={}),
    )

    transport = PulseTransport(
        api_key="fiq_live_test",
        tool="test-cli",
        version="1.0.0",
        max_batch_size=2,
        flush_interval=3600,
    )
    transport.identify(FAKE_FP)
    transport.enqueue({"command": "a", "timestamp": 1})
    transport.enqueue({"command": "b", "timestamp": 2})
    transport.enqueue({"command": "c", "timestamp": 3})
    transport.shutdown()

    assert event_route.call_count == 2


@respx.mock
def test_network_errors_are_silent():
    respx.post("https://fingerprintiq.com/v1/pulse/identify").mock(
        return_value=Response(500, text="boom"),
    )
    respx.post("https://fingerprintiq.com/v1/pulse/event").mock(
        return_value=Response(500, text="boom"),
    )

    transport = PulseTransport(
        api_key="fiq_live_test",
        tool="test-cli",
        version="1.0.0",
        flush_interval=3600,
    )
    transport.identify(FAKE_FP)
    transport.enqueue({"command": "deploy", "timestamp": 1})
    transport.flush()
    transport.shutdown()
