"""Machine fingerprint collection for the Pulse product.

Hash composition MUST match `packages/pulse/src/fingerprint.ts` byte-for-byte
so the same machine produces the same fingerprint_hash regardless of which SDK
is used.
"""

from __future__ import annotations

import hashlib
import locale as locale_mod
import os
import platform
import socket
import sys
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from decimal import ROUND_HALF_UP, Decimal


@dataclass
class MachineFingerprint:
    """Serializable machine fingerprint. Mirrors the JS MachineFingerprint type."""

    fingerprint_hash: str
    os: str
    arch: str
    cpu_model: str | None
    core_count: int | None
    memory_gb: float | None
    runtime: str
    runtime_version: str
    shell: str | None
    is_ci: bool
    is_container: bool
    ci_provider: str | None
    container_type: str | None
    locale: str | None
    timezone: str | None
    os_version: str | None
    terminal_emulator: str | None
    package_manager: str | None
    python_version_major: int | None
    is_tty: bool
    terminal_columns: int | None
    wsl_distro: str | None
    process_versions: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


# ─── normalization helpers ────────────────────────────────────────────────────


def normalize_platform(system: str) -> str:
    """Normalize Python's platform.system() to Node.js os.platform() values."""
    s = system.lower()
    if s == "darwin":
        return "darwin"
    if s == "linux":
        return "linux"
    if s in ("windows", "win32"):
        return "win32"
    return s


def normalize_arch(machine: str) -> str:
    """Normalize Python's platform.machine() to Node.js os.arch() values."""
    m = machine.lower()
    if m in ("x86_64", "amd64"):
        return "x64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    if m in ("i386", "i686"):
        return "ia32"
    return m


def _round_half_away_from_zero(value: float, digits: int) -> float:
    """Emulate JavaScript's Math.round on (value * 10**digits) / 10**digits."""
    if value == 0:
        return 0.0
    quant = Decimal(10) ** -digits
    return float(Decimal(str(value)).quantize(quant, rounding=ROUND_HALF_UP))


def _format_memory_gb(gb: float) -> str:
    """Format memory GB to match JS String(number) behavior.

    JS: String(16) === "16", String(16.5) === "16.5", String(0) === "0".
    Python's default str() gives "16.0" for a float — we need to drop
    the decimal for whole numbers to match the JS composite hash.
    """
    if gb == int(gb):
        return str(int(gb))
    return str(gb)


# ─── data sources ─────────────────────────────────────────────────────────────


def _iface_order_from_getifaddrs() -> list[str] | None:
    """Walk ``getifaddrs(3)`` and return interface names in the order Node sees them.

    Node's ``os.networkInterfaces()`` (via libuv's ``uv_interface_addresses``)
    only exposes interfaces that have at least one ``AF_INET``/``AF_INET6``
    address, and groups them by the order in which their first IP-family entry
    appears in the raw ``getifaddrs`` linked list. Matching that ordering is
    the only way Python can deterministically pick the same MAC as Node on
    hosts with multiple physical interfaces.

    Returns ``None`` when ``libc.getifaddrs`` isn't reachable (e.g. Windows),
    so the caller can fall back to psutil's native enumeration order.
    """
    import ctypes
    import ctypes.util

    libc_name = ctypes.util.find_library("c")
    if libc_name is None:
        return None
    try:
        libc = ctypes.CDLL(libc_name, use_errno=True)
    except OSError:
        return None
    if not hasattr(libc, "getifaddrs"):
        return None

    class _Sockaddr(ctypes.Structure):
        _fields_ = [
            ("sa_family_or_len", ctypes.c_uint8),
            ("sa_family", ctypes.c_uint8),
            ("sa_data", ctypes.c_char * 14),
        ]

    class _Ifaddrs(ctypes.Structure):
        pass

    _Ifaddrs._fields_ = [
        ("ifa_next", ctypes.POINTER(_Ifaddrs)),
        ("ifa_name", ctypes.c_char_p),
        ("ifa_flags", ctypes.c_uint),
        ("ifa_addr", ctypes.POINTER(_Sockaddr)),
        ("ifa_netmask", ctypes.POINTER(_Sockaddr)),
        ("ifa_dstaddr", ctypes.POINTER(_Sockaddr)),
        ("ifa_data", ctypes.c_void_p),
    ]

    libc.getifaddrs.restype = ctypes.c_int
    libc.getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(_Ifaddrs))]
    libc.freeifaddrs.argtypes = [ctypes.POINTER(_Ifaddrs)]

    head = ctypes.POINTER(_Ifaddrs)()
    if libc.getifaddrs(ctypes.byref(head)) != 0:
        return None

    try:
        order: list[str] = []
        seen: set[str] = set()
        node = head
        # macOS uses BSD sockaddr layout (sa_len, sa_family); Linux uses the
        # POSIX layout where sa_family is a 16-bit field at offset 0. On Linux,
        # reading byte 1 still yields the high byte of a little-endian AF value
        # (which is 0 for every family we care about: AF_INET=2, AF_INET6=10),
        # so the "family byte" lives at offset 0 on Linux and offset 1 on
        # Darwin. Detect which layout we're on by platform.
        import sys as _sys

        is_linux = _sys.platform.startswith("linux")
        while node:
            entry = node.contents
            name_bytes = entry.ifa_name
            if name_bytes is not None and entry.ifa_addr:
                sa = entry.ifa_addr[0]
                family = sa.sa_family_or_len if is_linux else sa.sa_family
                # AF_INET = 2 is the same on macOS and Linux; AF_INET6 is 30
                # on Darwin and 10 on Linux.
                is_inet = family == 2
                is_inet6 = family == (10 if is_linux else 30)
                if is_inet or is_inet6:
                    name_str = name_bytes.decode("utf-8", errors="replace")
                    if name_str not in seen:
                        seen.add(name_str)
                        order.append(name_str)
            node = entry.ifa_next
        return order
    finally:
        libc.freeifaddrs(head)


def _get_mac_address() -> str | None:
    """Return the primary MAC address, matching Node's ``os.networkInterfaces()`` lookup.

    Walks all interfaces in the order Node's libuv sees them — that is, the
    order each interface's first ``AF_INET``/``AF_INET6`` entry appears in the
    raw ``getifaddrs(3)`` linked list on Unix. For each non-loopback interface
    we consult psutil's MAC lookup (``net_if_addrs``) and return the first
    MAC that isn't ``"00:00:00:00:00:00"``.

    Mirrors ``packages/pulse/src/fingerprint.ts:11-24`` so Node and Python
    CLIs on the same host collapse into one machine row in Pulse.
    """
    try:
        import psutil  # type: ignore[import-untyped]
    except ImportError:
        return None

    addrs = psutil.net_if_addrs()
    # Raw getifaddrs walk (Unix) gives us the iface order Node uses. On
    # platforms where getifaddrs isn't available (Windows) we fall back to
    # psutil's native enumeration order.
    iface_order = _iface_order_from_getifaddrs()
    if iface_order is None:
        iface_order = list(addrs.keys())

    for name in iface_order:
        if name in ("lo", "lo0") or name.startswith("lo"):
            continue
        addr_list = addrs.get(name)
        if not addr_list:
            continue
        for addr in addr_list:
            candidate = (addr.address or "").lower()
            if (
                len(candidate) == 17
                and candidate.count(":") == 5
                and candidate != "00:00:00:00:00:00"
            ):
                return candidate

    return None


def _get_cpu_model() -> str | None:
    """Best-effort CPU model string, mirroring Node's os.cpus()[0].model."""
    system = platform.system()
    try:
        if system == "Darwin":
            import subprocess

            out = subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            return out.decode().strip() or None
        if system == "Linux":
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.lower().startswith("model name"):
                        return line.split(":", 1)[1].strip() or None
        if system == "Windows":
            return platform.processor() or None
    except Exception:
        return None
    return None


def _get_core_count() -> int | None:
    count = os.cpu_count()
    return count if count and count > 0 else None


def _get_memory_bytes() -> int:
    """Total system memory in bytes, or 0 if unknown."""
    try:
        if hasattr(os, "sysconf"):
            if "SC_PHYS_PAGES" in os.sysconf_names and "SC_PAGE_SIZE" in os.sysconf_names:
                pages = os.sysconf("SC_PHYS_PAGES")
                page_size = os.sysconf("SC_PAGE_SIZE")
                if pages > 0 and page_size > 0:
                    return pages * page_size
    except (ValueError, OSError):
        pass
    try:
        if platform.system() == "Darwin":
            import subprocess

            out = subprocess.check_output(
                ["sysctl", "-n", "hw.memsize"],
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            return int(out.decode().strip())
    except Exception:
        pass
    return 0


def _get_os_version() -> str | None:
    """OS version string, mirroring the JS logic at fingerprint.ts:77."""
    system = platform.system()
    release = platform.release()
    if system == "Darwin":
        try:
            major = int(release.split(".")[0])
            return f"macOS {major - 9}"
        except (ValueError, IndexError):
            return None
    if system == "Linux":
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"') or None
        except OSError:
            pass
        return f"Linux {release}" if release else None
    if system == "Windows":
        return f"Windows {release}" if release else None
    return release or None


def _get_terminal_emulator() -> str | None:
    return os.environ.get("TERM_PROGRAM") or os.environ.get("TERMINAL_EMULATOR") or None


def _get_shell() -> str | None:
    shell = os.environ.get("SHELL") or os.environ.get("ComSpec")
    if not shell:
        return None
    parts = shell.replace("\\", "/").split("/")
    return parts[-1] or None


def _get_locale() -> str | None:
    try:
        loc = locale_mod.getlocale()[0]
        return loc.replace("_", "-") if loc else None
    except Exception:
        return None


def _get_timezone() -> str | None:
    try:
        import time

        return time.tzname[0] if time.tzname else None
    except Exception:
        return None


def _detect_ci_provider() -> str | None:
    env = os.environ
    if env.get("GITHUB_ACTIONS"):
        return "github-actions"
    if env.get("GITLAB_CI"):
        return "gitlab-ci"
    if env.get("CIRCLECI"):
        return "circleci"
    if env.get("JENKINS_URL"):
        return "jenkins"
    if env.get("TRAVIS"):
        return "travis"
    if env.get("BUILDKITE"):
        return "buildkite"
    if env.get("CODEBUILD_BUILD_ID"):
        return "codebuild"
    if env.get("TF_BUILD"):
        return "azure-devops"
    if env.get("CI"):
        return "ci"
    return None


def _detect_container_type() -> str | None:
    env = os.environ
    if env.get("CODESPACES"):
        return "codespaces"
    if env.get("GITPOD_WORKSPACE_ID"):
        return "gitpod"
    if env.get("WSL_DISTRO_NAME"):
        return "wsl"
    if env.get("DOCKER_CONTAINER"):
        return "docker"
    try:
        if os.path.exists("/.dockerenv"):
            return "docker"
    except OSError:
        pass
    return None


def _detect_package_manager() -> str | None:
    if os.environ.get("POETRY_ACTIVE"):
        return "poetry"
    if os.environ.get("PIPENV_ACTIVE"):
        return "pipenv"
    if os.environ.get("UV"):
        return "uv"
    if os.environ.get("VIRTUAL_ENV"):
        return "pip"
    return None


def _get_terminal_columns() -> int | None:
    try:
        size = os.get_terminal_size()
        return size.columns
    except OSError:
        return None


# ─── main collector ───────────────────────────────────────────────────────────


def collect_machine_fingerprint() -> MachineFingerprint:
    hostname_hash = hashlib.sha256(socket.gethostname().encode("utf-8")).hexdigest()
    mac = _get_mac_address()
    mac_hash = hashlib.sha256(mac.encode("utf-8")).hexdigest() if mac else "no-mac"

    cpu_model = _get_cpu_model()
    core_count = _get_core_count()
    memory_bytes = _get_memory_bytes()
    memory_gb: float | None = (
        _round_half_away_from_zero(memory_bytes / (1024**3), 1) if memory_bytes > 0 else None
    )

    os_name = normalize_platform(platform.system())
    arch = normalize_arch(platform.machine())
    os_version = _get_os_version()
    terminal = _get_terminal_emulator()

    # Format memory for hash input — matches JS String(memoryGb ?? 0)
    memory_for_hash = _format_memory_gb(memory_gb) if memory_gb is not None else "0"

    composite = "|".join(
        [
            hostname_hash,
            mac_hash,
            cpu_model or "unknown-cpu",
            str(core_count or 0),
            memory_for_hash,
            os_name,
            arch,
            os_version or "unknown-osver",
            terminal or "unknown-term",
        ]
    )
    fingerprint_hash = hashlib.sha256(composite.encode("utf-8")).hexdigest()

    ci = _detect_ci_provider()
    container = _detect_container_type()

    return MachineFingerprint(
        fingerprint_hash=fingerprint_hash,
        os=os_name,
        arch=arch,
        cpu_model=cpu_model,
        core_count=core_count,
        memory_gb=memory_gb,
        runtime="python",
        runtime_version=platform.python_version(),
        shell=_get_shell(),
        is_ci=ci is not None,
        is_container=container is not None,
        ci_provider=ci,
        container_type=container,
        locale=_get_locale(),
        timezone=_get_timezone(),
        os_version=os_version,
        terminal_emulator=terminal,
        package_manager=_detect_package_manager(),
        python_version_major=sys.version_info.major,
        is_tty=sys.stdout.isatty(),
        terminal_columns=_get_terminal_columns(),
        wsl_distro=os.environ.get("WSL_DISTRO_NAME") or None,
        process_versions={
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
        },
    )
