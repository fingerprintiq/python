from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from fingerprintiq.pulse._fingerprint import collect_machine_fingerprint

pytestmark = pytest.mark.parity


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_python_and_js_produce_identical_fingerprint_hash():
    harness = Path(__file__).parent / "helpers" / "node_harness.cjs"
    pulse_dist = (
        Path(__file__).resolve().parents[2] / "pulse" / "dist" / "index.js"
    )
    if not pulse_dist.exists():
        pytest.skip(
            "packages/pulse not built — run `pnpm -C packages/pulse build` first"
        )

    result = subprocess.run(
        ["node", str(harness)],
        capture_output=True,
        text=True,
        check=True,
    )
    js_data = json.loads(result.stdout)
    js_hash = js_data["fingerprintHash"]

    py_fp = collect_machine_fingerprint()
    py_hash = py_fp.fingerprint_hash

    assert py_hash == js_hash, (
        f"Fingerprint hash mismatch:\n"
        f"  JS:     {js_hash}\n"
        f"  Python: {py_hash}\n"
        f"Check normalization in packages/python/src/fingerprintiq/pulse/_fingerprint.py"
    )
