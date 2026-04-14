from __future__ import annotations

import hashlib
from unittest.mock import patch

from fingerprintiq.pulse._fingerprint import (
    MachineFingerprint,
    _format_memory_gb,
    _round_half_away_from_zero,
    collect_machine_fingerprint,
    normalize_arch,
    normalize_platform,
)


def test_normalize_platform_matches_node_values():
    assert normalize_platform("Darwin") == "darwin"
    assert normalize_platform("Linux") == "linux"
    assert normalize_platform("Windows") == "win32"


def test_normalize_arch_matches_node_values():
    assert normalize_arch("x86_64") == "x64"
    assert normalize_arch("amd64") == "x64"
    assert normalize_arch("aarch64") == "arm64"
    assert normalize_arch("arm64") == "arm64"


def test_memory_rounding_matches_js_math_round():
    assert _round_half_away_from_zero(16.05, 1) == 16.1
    assert _round_half_away_from_zero(15.95, 1) == 16.0
    assert _round_half_away_from_zero(0.0, 1) == 0.0


def test_memory_gb_formatting_matches_js_string():
    # Whole numbers render without decimal to match JS String(16) === "16"
    assert _format_memory_gb(16.0) == "16"
    assert _format_memory_gb(16) == "16"
    assert _format_memory_gb(16.5) == "16.5"
    assert _format_memory_gb(0) == "0"


def test_collect_fingerprint_returns_deterministic_hash_with_mocks():
    with (
        patch("fingerprintiq.pulse._fingerprint.socket.gethostname", return_value="host1"),
        patch(
            "fingerprintiq.pulse._fingerprint._get_mac_address",
            return_value="aa:bb:cc:dd:ee:ff",
        ),
        patch("fingerprintiq.pulse._fingerprint._get_cpu_model", return_value="Apple M2"),
        patch("fingerprintiq.pulse._fingerprint._get_core_count", return_value=8),
        patch("fingerprintiq.pulse._fingerprint._get_memory_bytes", return_value=16 * 1024**3),
        patch("fingerprintiq.pulse._fingerprint.platform.system", return_value="Darwin"),
        patch("fingerprintiq.pulse._fingerprint.platform.machine", return_value="arm64"),
        patch("fingerprintiq.pulse._fingerprint._get_os_version", return_value="macOS 14"),
        patch(
            "fingerprintiq.pulse._fingerprint._get_terminal_emulator",
            return_value="Apple_Terminal",
        ),
    ):
        fp = collect_machine_fingerprint()

    hostname_hash = hashlib.sha256(b"host1").hexdigest()
    mac_hash = hashlib.sha256(b"aa:bb:cc:dd:ee:ff").hexdigest()
    parts = [
        hostname_hash,
        mac_hash,
        "Apple M2",
        "8",
        "16",  # 16 GB → "16" not "16.0" to match JS String(16)
        "darwin",
        "arm64",
        "macOS 14",
        "Apple_Terminal",
    ]
    expected = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

    assert isinstance(fp, MachineFingerprint)
    assert fp.fingerprint_hash == expected
    assert fp.os == "darwin"
    assert fp.arch == "arm64"
    assert fp.runtime == "python"


def test_collect_fingerprint_with_no_mac_no_memory():
    with (
        patch("fingerprintiq.pulse._fingerprint.socket.gethostname", return_value="host2"),
        patch("fingerprintiq.pulse._fingerprint._get_mac_address", return_value=None),
        patch("fingerprintiq.pulse._fingerprint._get_cpu_model", return_value=None),
        patch("fingerprintiq.pulse._fingerprint._get_core_count", return_value=None),
        patch("fingerprintiq.pulse._fingerprint._get_memory_bytes", return_value=0),
        patch("fingerprintiq.pulse._fingerprint.platform.system", return_value="Linux"),
        patch("fingerprintiq.pulse._fingerprint.platform.machine", return_value="x86_64"),
        patch("fingerprintiq.pulse._fingerprint._get_os_version", return_value=None),
        patch("fingerprintiq.pulse._fingerprint._get_terminal_emulator", return_value=None),
    ):
        fp = collect_machine_fingerprint()

    hostname_hash = hashlib.sha256(b"host2").hexdigest()
    parts = [
        hostname_hash,
        "no-mac",
        "unknown-cpu",
        "0",
        "0",   # 0 bytes → "0" not "0.0"
        "linux",
        "x64",
        "unknown-osver",
        "unknown-term",
    ]
    expected = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    assert fp.fingerprint_hash == expected
