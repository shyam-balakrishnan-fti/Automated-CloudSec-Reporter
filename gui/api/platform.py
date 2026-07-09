"""
api/platform.py — OS detection, tool availability checks, AWS profile discovery.

Called at startup and by the preflight endpoint.
Nothing here modifies any state — pure detection only.
"""

from __future__ import annotations

import configparser
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from api.models import PlatformInfo, PreflightCheck, PreflightResult


# ── OS detection ──────────────────────────────────────────────────────

def get_os() -> str:
    """Returns 'windows', 'linux', or 'darwin'."""
    s = platform.system().lower()
    if s == "windows":
        return "windows"
    if s == "darwin":
        return "darwin"
    return "linux"


def scubagear_supported() -> bool:
    """ScubaGear is a PowerShell module — only available on Windows."""
    return get_os() == "windows"


# ── Tool availability ─────────────────────────────────────────────────

def uv_available() -> bool:
    return shutil.which("uv") is not None


def _run_silent(cmd: list[str]) -> tuple[bool, str]:
    """Run a command, return (success, stdout). Never raises."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.returncode == 0, result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False, ""


def prowler_installed() -> tuple[bool, str]:
    """
    Returns (installed: bool, version: str).
    Tries `prowler -v` first, then falls back to checking uv tool list.
    """
    ok, out = _run_silent(["prowler", "-v"])
    if ok and out:
        return True, out.split("\n")[0]

    # uv tool install puts binaries in a non-PATH location on some systems.
    # Check via `uv tool list` as fallback.
    if uv_available():
        ok2, out2 = _run_silent(["uv", "tool", "list"])
        if ok2 and "prowler" in out2.lower():
            return True, "(version unknown — not in PATH)"

    return False, ""


def scubagear_installed() -> tuple[bool, str]:
    """
    Returns (installed: bool, version: str).
    Only meaningful on Windows — always returns (False, '') on other platforms.
    """
    if not scubagear_supported():
        return False, ""

    ok, out = _run_silent([
        "powershell", "-NoProfile", "-Command",
        "(Get-Module -ListAvailable ScubaGear | Select-Object -First 1).Version.ToString()"
    ])
    if ok and out:
        return True, out
    return False, ""


# ── AWS profile discovery ─────────────────────────────────────────────

def aws_profiles() -> list[str]:
    """
    Return named profiles from ~/.aws/credentials and ~/.aws/config.
    Always includes 'default' first if a credentials file exists.
    Returns empty list if neither file exists.
    """
    profiles: list[str] = []

    credentials_path = Path.home() / ".aws" / "credentials"
    config_path      = Path.home() / ".aws" / "config"

    def _read_profiles(path: Path, strip_prefix: str = "") -> list[str]:
        if not path.exists():
            return []
        parser = configparser.ConfigParser()
        try:
            parser.read(path, encoding="utf-8")
        except Exception:
            return []
        result = []
        for section in parser.sections():
            name = section
            if strip_prefix and name.startswith(strip_prefix):
                name = name[len(strip_prefix):]
            result.append(name)
        return result

    cred_profiles = _read_profiles(credentials_path)
    conf_profiles = _read_profiles(config_path, strip_prefix="profile ")

    # Merge, deduplicate, keep 'default' first
    seen: set[str] = set()
    for p in cred_profiles + conf_profiles:
        if p not in seen:
            seen.add(p)
            profiles.append(p)

    # Ensure 'default' is always first if present
    if "default" in profiles and profiles[0] != "default":
        profiles.remove("default")
        profiles.insert(0, "default")

    return profiles


def aws_credentials_configured(profile: str = "") -> tuple[bool, str]:
    """
    Quick check: can we make an STS get-caller-identity call?
    Returns (ok: bool, identity_or_error: str).
    This actually calls AWS — only use in preflight, not on every page load.
    """
    cmd = ["aws", "sts", "get-caller-identity", "--output", "text"]
    if profile:
        cmd += ["--profile", profile]

    if shutil.which("aws") is None:
        return False, "AWS CLI not found — install it or set credentials via environment variables"

    ok, out = _run_silent(cmd)
    if ok:
        return True, out.split("\n")[0] if out else "OK"
    return False, "Credentials check failed — run `aws configure` or check your profile"


# ── Full platform info ────────────────────────────────────────────────


# ── Platform info cache ───────────────────────────────────────────────
# prowler_installed() and scubagear_installed() run subprocesses.
# Cache the result for 60 seconds so repeated /api/platform calls
# don't re-run subprocess checks on every navigation event.

import time as _time
_platform_cache: dict = {}
_platform_cache_ts: float = 0.0
_PLATFORM_CACHE_TTL = 60.0  # seconds

def get_platform_info(force: bool = False) -> PlatformInfo:
    global _platform_cache, _platform_cache_ts

    now = _time.monotonic()
    if not force and _platform_cache and (now - _platform_cache_ts) < _PLATFORM_CACHE_TTL:
        return PlatformInfo(**_platform_cache)

    prowler_ok, _ = prowler_installed()
    scuba_ok, _   = scubagear_installed()

    info = PlatformInfo(
        os=get_os(),
        scubagear_available=scubagear_supported(),
        python_version=sys.version.split()[0],
        uv_available=uv_available(),
        prowler_installed=prowler_ok,
        scubagear_installed=scuba_ok,
        aws_profiles=aws_profiles(),
    )
    _platform_cache    = info.model_dump()
    _platform_cache_ts = now
    return info


# ── Preflight checks ──────────────────────────────────────────────────

def run_preflight(
    pipeline: str,
    input_file: str,
    aws_profile: str,
    credential_source: str,
    output_dir: str,
) -> PreflightResult:
    """
    Run all preflight checks for a given pipeline run configuration.
    Returns a PreflightResult with individual check results.
    A run cannot start if any blocking check fails.
    """
    checks: list[PreflightCheck] = []
    os_name = get_os()

    # ── 1. uv available ───────────────────────────────────────────────
    if uv_available():
        checks.append(PreflightCheck(
            name="uv package manager",
            status="ok",
            message="uv is installed and on PATH",
            blocking=False,
        ))
    else:
        checks.append(PreflightCheck(
            name="uv package manager",
            status="warning",
            message=(
                "uv not found on PATH. Install from https://docs.astral.sh/uv/ "
                "or run: curl -LsSf https://astral.sh/uv/install.sh | sh"
            ),
            blocking=False,
        ))

    # ── 2. Prowler installed ──────────────────────────────────────────
    if pipeline in ("prowler", "both"):
        import sys as _sys
        py_minor = _sys.version_info.minor
        py_major = _sys.version_info.major
        if py_major == 3 and py_minor > 12:
            checks.append(PreflightCheck(
                name="Python version",
                status="warning",
                message=(
                    f"System Python is 3.{py_minor}. Prowler requires Python 3.12 or below. "
                    f"The startup script installs Prowler using Python 3.12 automatically."
                ),
                blocking=False,
            ))

        prowler_ok, prowler_ver = prowler_installed()
        if prowler_ok:
            checks.append(PreflightCheck(
                name="Prowler",
                status="ok",
                message=f"Prowler installed: {prowler_ver}",
                blocking=False,
            ))
        else:
            msg = (
                "Prowler not installed. Run start.ps1 / start.sh which installs "
                "Prowler using Python 3.12 automatically.\n\n"
                "Or manually: uv tool install prowler --python 3.12"
            )
            checks.append(PreflightCheck(
                name="Prowler",
                status="error",
                message=msg,
                blocking=True,
            ))

    # ── 3. ScubaGear installed ────────────────────────────────────────
    if pipeline in ("scubagear", "both"):
        if not scubagear_supported():
            checks.append(PreflightCheck(
                name="ScubaGear",
                status="error",
                message=(
                    f"ScubaGear requires Windows. "
                    f"Current platform: {os_name}. "
                    f"ScubaGear is a PowerShell module and cannot run on this OS."
                ),
                blocking=True,
            ))
        else:
            scuba_ok, scuba_ver = scubagear_installed()
            if scuba_ok:
                checks.append(PreflightCheck(
                    name="ScubaGear",
                    status="ok",
                    message=f"ScubaGear installed: {scuba_ver}",
                    blocking=False,
                ))
            else:
                checks.append(PreflightCheck(
                    name="ScubaGear",
                    status="error",
                    message=(
                        "ScubaGear not installed. "
                        "Open PowerShell as Administrator and run:\n"
                        "  Install-Module -Name PowerShellGet -Force\n"
                        "  Install-Module -Name ScubaGear -Force"
                    ),
                    blocking=True,
                ))

    # ── 4. Input file readable ────────────────────────────────────────
    if input_file:
        p = Path(input_file)
        if not p.exists():
            checks.append(PreflightCheck(
                name="Input file",
                status="error",
                message=f"File not found: {input_file}",
                blocking=True,
            ))
        elif not p.is_file():
            checks.append(PreflightCheck(
                name="Input file",
                status="error",
                message=f"Path is not a file: {input_file}",
                blocking=True,
            ))
        else:
            checks.append(PreflightCheck(
                name="Input file",
                status="ok",
                message=f"File readable: {p.name} ({p.stat().st_size // 1024} KB)",
                blocking=False,
            ))
    else:
        checks.append(PreflightCheck(
            name="Input file",
            status="error",
            message="No input file specified",
            blocking=True,
        ))

    # ── 5. Output directory writable ─────────────────────────────────
    if output_dir:
        op = Path(output_dir)
        try:
            op.mkdir(parents=True, exist_ok=True)
            test_file = op / ".write_test"
            test_file.touch()
            test_file.unlink()
            checks.append(PreflightCheck(
                name="Output directory",
                status="ok",
                message=f"Output directory writable: {output_dir}",
                blocking=False,
            ))
        except (OSError, PermissionError) as e:
            checks.append(PreflightCheck(
                name="Output directory",
                status="error",
                message=f"Cannot write to output directory: {e}",
                blocking=True,
            ))
    else:
        checks.append(PreflightCheck(
            name="Output directory",
            status="warning",
            message="Output directory not set — will use pipeline default",
            blocking=False,
        ))

    # ── 6. AWS credentials ────────────────────────────────────────────
    if credential_source == "profile":
        profile_list = aws_profiles()
        if not profile_list:
            checks.append(PreflightCheck(
                name="AWS credentials",
                status="warning",
                message=(
                    "No AWS profiles found in ~/.aws/credentials or ~/.aws/config. "
                    "Configure via `aws configure` or use raw key input."
                ),
                blocking=False,
            ))
        elif aws_profile and aws_profile not in profile_list:
            checks.append(PreflightCheck(
                name="AWS credentials",
                status="error",
                message=f"Profile '{aws_profile}' not found. Available: {', '.join(profile_list)}",
                blocking=True,
            ))
        else:
            checks.append(PreflightCheck(
                name="AWS credentials",
                status="ok",
                message=f"AWS profile '{aws_profile or 'default'}' found",
                blocking=False,
            ))
    else:
        # Keys — just note they'll be validated at runtime
        checks.append(PreflightCheck(
            name="AWS credentials",
            status="ok",
            message="Using temporary access keys (validated at runtime)",
            blocking=False,
        ))

    can_proceed = not any(c.blocking and c.status == "error" for c in checks)
    return PreflightResult(can_proceed=can_proceed, checks=checks)