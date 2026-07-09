"""
api/installer.py — Tool installation logic.

Prowler:   uv tool install prowler  (cross-platform)
ScubaGear: PowerShell Install-Module (Windows only)

Each install function streams output lines to an SseStream so the
analyst sees live progress in the GUI. The same async subprocess
pattern is reused by the pipeline runner in Phase 3.

Design decisions:
  - Never auto-run installs. Only called when analyst clicks Install.
  - Execution policy detection is read-only. Fixing it is left to the analyst.
  - uv bootstrap (if uv itself is missing) is included — worst-case scenario.
"""

from __future__ import annotations

import asyncio
import platform
import shutil
import sys
from pathlib import Path

from api.sse import SseStream


# ── Async subprocess helper ───────────────────────────────────────────

async def _stream_subprocess(
    cmd: list[str],
    stream: SseStream,
    env: dict | None = None,
    cwd: str | None = None,
) -> int:
    """
    Run a subprocess, stream each stdout/stderr line to the SseStream.
    Returns the process return code.
    """
    import os
    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,   # merge stderr into stdout
            env=proc_env,
            cwd=cwd,
        )
    except FileNotFoundError:
        await stream.send_log(f"Command not found: {cmd[0]}", stream="stderr")
        return 1

    assert proc.stdout is not None
    async for raw_line in proc.stdout:
        line = raw_line.decode("utf-8", errors="replace").rstrip()
        if line:
            await stream.send_log(line)

    await proc.wait()
    return proc.returncode


# ── uv bootstrap ──────────────────────────────────────────────────────

async def install_uv(stream: SseStream) -> bool:
    """
    Install uv itself if it's missing.
    Uses the official install script on Linux/macOS.
    On Windows uses the PowerShell install command.
    Returns True on success.
    """
    os_name = platform.system().lower()
    await stream.send_log("uv not found — attempting bootstrap install...")

    if os_name == "windows":
        cmd = [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-Command",
            "irm https://astral.sh/uv/install.ps1 | iex"
        ]
    else:
        # curl-pipe-sh — standard uv install
        cmd = ["sh", "-c", "curl -LsSf https://astral.sh/uv/install.sh | sh"]

    rc = await _stream_subprocess(cmd, stream)
    if rc == 0:
        await stream.send_log("✓ uv installed successfully")
        return True
    else:
        await stream.send_log(
            "✗ uv install failed. Install manually from https://docs.astral.sh/uv/",
            stream="stderr",
        )
        return False


# ── Prowler installation ──────────────────────────────────────────────

async def install_prowler(stream: SseStream) -> bool:
    """
    Install Prowler via uv tool install.
    Bootstraps uv first if it's missing.
    Returns True on success.
    """
    await stream.send_status("running")
    await stream.send_log("=== Prowler Installation ===")

    # Step 1: ensure uv is available
    uv_path = shutil.which("uv")
    if not uv_path:
        ok = await install_uv(stream)
        if not ok:
            await stream.send_status("failed")
            await stream.close()
            return False
        # Re-check after install
        uv_path = shutil.which("uv")
        if not uv_path:
            await stream.send_log(
                "uv installed but not found on PATH. "
                "You may need to restart your terminal or add ~/.local/bin to PATH.",
                stream="stderr",
            )
            await stream.send_status("failed")
            await stream.close()
            return False

    await stream.send_log(f"Using uv: {uv_path}")

    # Step 2: uv tool install prowler
    await stream.send_log("Running: uv tool install prowler")
    await stream.send_log("This may take 1–2 minutes on first install...")

    rc = await _stream_subprocess(["uv", "tool", "install", "prowler"], stream)

    if rc == 0:
        await stream.send_log("✓ Prowler installed successfully")

        # Verify it's callable
        prowler_path = shutil.which("prowler")
        if prowler_path:
            await stream.send_log(f"✓ prowler binary found at: {prowler_path}")
        else:
            await stream.send_log(
                "⚠ Prowler installed via uv but 'prowler' is not on PATH. "
                "Run: uv tool update-shell  — then restart your terminal.",
                stream="stderr",
            )

        # Windows-specific warning
        if platform.system().lower() == "windows":
            await stream.send_log(
                "⚠ Windows note: Prowler may have dependency issues on native Windows. "
                "If prowler commands fail at runtime, see https://docs.prowler.com "
                "for WSL-based installation instructions."
            )

        await stream.send_status("complete")
        await stream.close()
        return True
    else:
        await stream.send_log("✗ Prowler installation failed (see output above)", stream="stderr")
        await stream.send_status("failed")
        await stream.close()
        return False


# ── ScubaGear installation ────────────────────────────────────────────

async def check_powershell_execution_policy(stream: SseStream) -> tuple[bool, str]:
    """
    Check the current PowerShell execution policy.
    Returns (policy_allows_install: bool, policy_name: str).
    Policies that allow Install-Module: RemoteSigned, Unrestricted, Bypass.
    Blocking policies: Restricted, AllSigned (blocks unsigned modules).
    """
    rc = await _stream_subprocess(
        [
            "powershell", "-NoProfile", "-Command",
            "Get-ExecutionPolicy -Scope CurrentUser"
        ],
        stream,
    )
    # The output will have been sent to stream already.
    # Re-run silently to capture the value.
    try:
        import subprocess
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-ExecutionPolicy -Scope CurrentUser"],
            capture_output=True, text=True, timeout=10,
        )
        policy = result.stdout.strip()
    except Exception:
        policy = "Unknown"

    allows = policy.lower() in ("remotesigned", "unrestricted", "bypass")
    return allows, policy


async def install_scubagear(stream: SseStream) -> bool:
    """
    Install ScubaGear via PowerShell Install-Module.
    Windows only — caller must verify OS before calling.
    Returns True on success.
    """
    await stream.send_status("running")
    await stream.send_log("=== ScubaGear Installation ===")

    if platform.system().lower() != "windows":
        await stream.send_log(
            "✗ ScubaGear requires Windows. Current OS is not Windows.",
            stream="stderr",
        )
        await stream.send_status("failed")
        await stream.close()
        return False

    # Step 1: check execution policy
    await stream.send_log("Checking PowerShell execution policy...")
    policy_ok, policy_name = await check_powershell_execution_policy(stream)

    if not policy_ok:
        await stream.send_log(
            f"✗ PowerShell execution policy is '{policy_name}' — "
            f"this blocks module installation.",
            stream="stderr",
        )
        await stream.send_log(
            "To fix, open PowerShell as your normal user (not Administrator) and run:\n"
            "  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser\n"
            "Then retry the ScubaGear installation.",
            stream="stderr",
        )
        await stream.send_status("failed")
        await stream.close()
        return False

    await stream.send_log(f"✓ Execution policy is '{policy_name}' — OK")

    # Step 2: ensure PowerShellGet is up to date
    await stream.send_log("Updating PowerShellGet (required for ScubaGear)...")
    rc = await _stream_subprocess(
        [
            "powershell", "-NoProfile", "-Command",
            "Install-Module -Name PowerShellGet -Force -AllowClobber -Scope CurrentUser"
        ],
        stream,
    )
    if rc != 0:
        await stream.send_log(
            "⚠ PowerShellGet update failed — continuing anyway (existing version may work)",
        )

    # Step 3: install ScubaGear
    await stream.send_log("Installing ScubaGear module (this may take several minutes)...")
    rc = await _stream_subprocess(
        [
            "powershell", "-NoProfile", "-Command",
            "Install-Module -Name ScubaGear -Force -AllowClobber -Scope CurrentUser"
        ],
        stream,
    )

    if rc == 0:
        # Step 4: verify
        await stream.send_log("Verifying installation...")
        rc2 = await _stream_subprocess(
            [
                "powershell", "-NoProfile", "-Command",
                "(Get-Module -ListAvailable ScubaGear | "
                "Select-Object -First 1).Version.ToString()"
            ],
            stream,
        )
        await stream.send_log("✓ ScubaGear installed successfully")
        await stream.send_status("complete")
        await stream.close()
        return True
    else:
        await stream.send_log(
            "✗ ScubaGear installation failed (see output above)\n"
            "Common causes:\n"
            "  • Execution policy blocking unsigned modules\n"
            "  • No internet access to PSGallery\n"
            "  • Insufficient permissions (try running as Administrator)",
            stream="stderr",
        )
        await stream.send_status("failed")
        await stream.close()
        return False