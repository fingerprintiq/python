"""Pulse — CLI usage analytics and machine fingerprinting."""

from __future__ import annotations

import os
import time
from collections.abc import Mapping
from typing import Any

from fingerprintiq._http import DEFAULT_ENDPOINT
from fingerprintiq.pulse._fingerprint import (
    MachineFingerprint,
    collect_machine_fingerprint,
)
from fingerprintiq.pulse._transport import (
    DEFAULT_FLUSH_INTERVAL,
    DEFAULT_MAX_BATCH_SIZE,
    PulseTransport,
)

_OPT_OUT_VALUES = frozenset({"1", "true", "yes"})
_OPT_OUT_ENV_VARS = ("DO_NOT_TRACK", "FINGERPRINTIQ_OPTOUT")


def _is_opted_out() -> bool:
    for name in _OPT_OUT_ENV_VARS:
        value = os.environ.get(name, "").strip().lower()
        if value in _OPT_OUT_VALUES:
            return True
    return False


class Pulse:
    """Track CLI usage and machine fingerprint events.

    Instantiate once at startup with the tool name and version, then call
    `pulse.track(command)` for each invocation you want to record. Events are
    batched and flushed on a background daemon thread; the process never blocks
    on analytics.

    Honors `DO_NOT_TRACK=1` and `FINGERPRINTIQ_OPTOUT=1` (and `=true`) by
    default — set `respect_opt_out=False` to disable this check.
    """

    def __init__(
        self,
        *,
        api_key: str,
        tool: str,
        version: str,
        endpoint: str = DEFAULT_ENDPOINT,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL,
        max_batch_size: int = DEFAULT_MAX_BATCH_SIZE,
        respect_opt_out: bool = True,
    ) -> None:
        self._api_key = api_key
        self._tool = tool
        self._version = version
        self._endpoint = endpoint
        self._flush_interval = flush_interval
        self._max_batch_size = max_batch_size
        self._disabled = respect_opt_out and _is_opted_out()
        self._transport: PulseTransport | None = None
        self._initialized = False

    def _init(self) -> None:
        if self._initialized or self._disabled:
            return
        self._transport = PulseTransport(
            api_key=self._api_key,
            tool=self._tool,
            version=self._version,
            endpoint=self._endpoint,
            flush_interval=self._flush_interval,
            max_batch_size=self._max_batch_size,
        )
        fp = collect_machine_fingerprint()
        self._transport.identify(fp)
        self._initialized = True

    def track(
        self,
        command: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        if self._disabled:
            return
        self._init()
        if self._transport is None:
            return
        event: dict[str, Any] = {
            "command": command,
            "timestamp": int(time.time() * 1000),
        }
        if metadata:
            duration = metadata.get("duration_ms")
            if isinstance(duration, (int, float)):
                event["durationMs"] = duration
            success = metadata.get("success")
            if isinstance(success, bool):
                event["success"] = success
            event["metadata"] = dict(metadata)
        self._transport.enqueue(event)

    def flush(self) -> None:
        if self._disabled or self._transport is None:
            return
        self._transport.flush()

    def shutdown(self) -> None:
        if self._disabled or self._transport is None:
            return
        self._transport.shutdown()


__all__ = [
    "MachineFingerprint",
    "Pulse",
    "collect_machine_fingerprint",
]
