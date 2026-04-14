"""Pulse event transport — background-thread batched flush."""

from __future__ import annotations

import atexit
import threading
from typing import Any

import httpx

from fingerprintiq._http import DEFAULT_ENDPOINT, USER_AGENT
from fingerprintiq.pulse._fingerprint import MachineFingerprint

IDENTIFY_PATH = "/v1/pulse/identify"
EVENT_PATH = "/v1/pulse/event"

DEFAULT_FLUSH_INTERVAL = 30.0
DEFAULT_MAX_BATCH_SIZE = 25


class PulseTransport:
    def __init__(
        self,
        *,
        api_key: str,
        tool: str,
        version: str,
        endpoint: str = DEFAULT_ENDPOINT,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL,
        max_batch_size: int = DEFAULT_MAX_BATCH_SIZE,
    ) -> None:
        self._api_key = api_key
        self._tool = tool
        self._version = version
        self._endpoint = endpoint
        self._flush_interval = flush_interval
        self._max_batch_size = max_batch_size

        self._buffer: list[dict[str, Any]] = []
        self._machine_id: str | None = None
        self._lock = threading.Lock()
        self._shutdown_event = threading.Event()
        self._client = httpx.Client(
            base_url=endpoint,
            timeout=10.0,
            headers={
                "X-API-Key": api_key,
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
            },
        )
        self._thread: threading.Thread | None = None
        self._start_flush_thread()
        atexit.register(self.shutdown)

    def _start_flush_thread(self) -> None:
        def loop() -> None:
            while not self._shutdown_event.wait(self._flush_interval):
                try:
                    self.flush()
                except Exception:
                    pass

        self._thread = threading.Thread(target=loop, daemon=True, name="fingerprintiq-pulse-flush")
        self._thread.start()

    def identify(self, fingerprint: MachineFingerprint) -> None:
        try:
            response = self._client.post(IDENTIFY_PATH, json=fingerprint.to_dict())
            if 200 <= response.status_code < 300:
                data = response.json()
                self._machine_id = data.get("machineId")
        except Exception:
            pass

    def enqueue(self, event: dict[str, Any]) -> None:
        should_flush = False
        with self._lock:
            self._buffer.append(event)
            if len(self._buffer) >= self._max_batch_size:
                should_flush = True
        if should_flush:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            if not self._buffer:
                return
            batch = self._buffer[: self._max_batch_size]
            self._buffer = self._buffer[self._max_batch_size :]

        payload = {
            "machineId": self._machine_id,
            "tool": self._tool,
            "toolVersion": self._version,
            "events": batch,
        }
        try:
            self._client.post(EVENT_PATH, json=payload)
        except Exception:
            pass

    def shutdown(self) -> None:
        if self._shutdown_event.is_set():
            return
        self._shutdown_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        try:
            self.flush()
        finally:
            self._client.close()
