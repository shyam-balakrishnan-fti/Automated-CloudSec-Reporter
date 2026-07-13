"""
api/scanner.py — Prowler scan execution.

Responsibilities:
  - Build the correct prowler CLI command for AWS or Azure
  - Inject scan credentials into subprocess environment
    (raw secrets never touch the DB — injected at launch time only)
  - Stream stdout/stderr to an SseStream
  - Write every log line to scan_logs in SQLite
  - Advance scan status: pending → running → complete / failed
  - Detect and return the output CSV path on completion

AWS command:
    prowler aws
      --access-key-id KEY --secret-access-key SECRET [--session-token TOKEN]
      --region REGION
      --output-formats csv --output-filename prowler-output --output-path OUTPUT_DIR
      [--resource-arn ARN1 ARN2 ...]
      [--services iam s3 ...]

Azure command:
    prowler azure --sp-env-auth
      [--subscription-ids SUB_ID]
      --output-formats csv --output-filename prowler-output --output-path OUTPUT_DIR
      [--services entra storage ...]
    env: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET

Output file detection:
    Prowler writes {output_path}/prowler-output_*.csv
    We glob for the most recently modified CSV after completion.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import signal
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiosqlite

from api.sse import SseStream
from api.runner import _find_python

# ── Active scan process registry ─────────────────────────────────────
_active_scans: dict[str, asyncio.subprocess.Process] = {}


def _register_scan(scan_id: str, proc: asyncio.subprocess.Process) -> None:
    _active_scans[scan_id] = proc


def _deregister_scan(scan_id: str) -> None:
    _active_scans.pop(scan_id, None)


async def cancel_scan(scan_id: str) -> bool:
    proc = _active_scans.get(scan_id)
    if not proc:
        return False
    try:
        if platform.system().lower() == "windows":
            proc.terminate()
        else:
            proc.send_signal(signal.SIGTERM)
    except (ProcessLookupError, OSError):
        pass
    _deregister_scan(scan_id)
    return True


# ── Prowler binary location ───────────────────────────────────────────

def _find_prowler() -> str:
    """
    Find the prowler binary.
    uv tool install puts it in a tool-specific venv, not always on PATH.
    Try PATH first, then common uv tool locations.
    """
    prowler = shutil.which("prowler")
    if prowler:
        return prowler

    # uv tool bin directory
    home = Path.home()
    candidates = [
        home / ".local" / "bin" / "prowler",
        home / ".local" / "bin" / "prowler.exe",
        home / "AppData" / "Local" / "uv" / "tools" / "prowler" / "Scripts" / "prowler.exe",
        home / "AppData" / "Local" / "uv" / "tools" / "prowler" / "bin" / "prowler",
        Path("C:/") / "Users" / os.environ.get("USERNAME", "") / "AppData" / "Local" / "uv" / "tools" / "prowler" / "Scripts" / "prowler.exe",
    ]
    for c in candidates:
        if c.exists():
            return str(c)

    return "prowler"  # fallback — will fail with clear error if not found


# ── Command builder ───────────────────────────────────────────────────

def build_scan_command(scan: dict, output_dir: Path) -> list[str]:
    """
    Build the prowler CLI command for a scan record.
    Raw secrets are NOT in the scan dict — they come from the in-memory
    credentials store and are injected into the env separately.
    """
    prowler = _find_prowler()
    provider = scan["provider"]
    output_dir.mkdir(parents=True, exist_ok=True)

    if provider == "aws":
        cmd = [
            prowler, "aws",
            "-M", "csv",                         # output format
            "-F", "prowler-output",               # output filename base
            "-o", str(output_dir),                # output directory
        ]

        if scan.get("scan_region"):
            cmd += ["--region", scan["scan_region"]]

        # Resource scope — ARN list
        resource_scope = _parse_json_list(scan.get("resource_scope", ""))
        if resource_scope:
            cmd += ["--resource-arn"] + resource_scope

        # Services scope
        services_scope = _parse_json_list(scan.get("services_scope", ""))
        if services_scope:
            cmd += ["-s"] + services_scope

    elif provider == "azure":
        cmd = [
            prowler, "azure",
            "--sp-env-auth",
            "-M", "csv",
            "-F", "prowler-output",
            "-o", str(output_dir),
        ]

        if scan.get("azure_subscription_id"):
            cmd += ["--subscription-ids", scan["azure_subscription_id"]]

        # Services scope
        services_scope = _parse_json_list(scan.get("services_scope", ""))
        if services_scope:
            cmd += ["-s"] + services_scope

    else:
        raise ValueError(f"Unknown scan provider: {provider}")

    return cmd


def build_scan_env(scan: dict, raw_secrets: Optional[dict] = None) -> dict[str, str]:
    """
    Build the subprocess environment for a scan.
    Injects credentials from raw_secrets (never from DB).
    """
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    secrets = raw_secrets or {}
    provider = scan["provider"]

    if provider == "aws":
        cred_source = scan.get("credential_source", "keys")
        if cred_source == "profile" and scan.get("aws_profile"):
            env["AWS_PROFILE"] = scan["aws_profile"]
        else:
            if secrets.get("aws_access_key_id"):
                env["AWS_ACCESS_KEY_ID"]     = secrets["aws_access_key_id"]
            if secrets.get("aws_secret_access_key"):
                env["AWS_SECRET_ACCESS_KEY"] = secrets["aws_secret_access_key"]
            if secrets.get("aws_session_token"):
                env["AWS_SESSION_TOKEN"]     = secrets["aws_session_token"]

        if scan.get("scan_region"):
            env["AWS_DEFAULT_REGION"] = scan["scan_region"]

    elif provider == "azure":
        if scan.get("azure_tenant_id"):
            env["AZURE_TENANT_ID"] = scan["azure_tenant_id"]
        if scan.get("azure_client_id"):
            env["AZURE_CLIENT_ID"] = scan["azure_client_id"]
        if secrets.get("azure_client_secret"):
            env["AZURE_CLIENT_SECRET"] = secrets["azure_client_secret"]

    return env


# ── Output file detection ─────────────────────────────────────────────

def find_scan_output(output_dir: Path) -> Optional[Path]:
    """
    Find the primary findings CSV from a completed Prowler v5 scan.

    We pass -F prowler-output so Prowler writes:
      {output_dir}/prowler-output.csv              (exact match — prefer this)
      {output_dir}/prowler-output_ACCOUNT_DATE.csv (timestamped variant)

    Compliance CSVs go into {output_dir}/compliance/ — we never look there.
    Strategy: only look in the root of output_dir, match prowler-output*.csv.
    """
    # Only look in the root directory — never recurse into compliance/ subdirs
    root_csvs = [f for f in output_dir.iterdir()
                 if f.is_file() and f.suffix.lower() == ".csv"]

    if not root_csvs:
        return None

    # Prefer exact filename match first
    for f in root_csvs:
        if f.name.lower() == "prowler-output.csv":
            return f

    # Then any file starting with prowler-output
    prowler_csvs = [f for f in root_csvs
                    if f.name.lower().startswith("prowler-output")]
    if prowler_csvs:
        return max(prowler_csvs, key=lambda f: f.stat().st_size)

    # Fallback — largest CSV in root if naming is unexpected
    return max(root_csvs, key=lambda f: f.stat().st_size)


# ── DB helpers ────────────────────────────────────────────────────────

async def _update_scan_status(
    scan_id: str,
    status: str,
    db: aiosqlite.Connection,
    **kwargs,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    if status in ("complete", "failed", "cancelled"):
        await db.execute(
            "UPDATE scans SET status=?, completed_at=? WHERE id=?",
            (status, now, scan_id),
        )
    elif status == "running":
        await db.execute(
            "UPDATE scans SET status=?, started_at=? WHERE id=?",
            (status, now, scan_id),
        )
    else:
        await db.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))

    for col, val in kwargs.items():
        await db.execute(f"UPDATE scans SET {col}=? WHERE id=?", (val, scan_id))

    await db.commit()


async def _append_scan_log(
    scan_id: str,
    line: str,
    stream_name: str,
    db: aiosqlite.Connection,
) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "INSERT INTO scan_logs (scan_id, ts, stream, line) VALUES (?, ?, ?, ?)",
        (scan_id, ts, stream_name, line),
    )
    await db.commit()


# ── Main scan executor ────────────────────────────────────────────────

async def execute_scan(
    scan: dict,
    stream: SseStream,
    output_dir: Path,
    raw_secrets: Optional[dict] = None,
) -> None:
    """
    Route to the correct scan executor based on scan type.
    - prowler_aws / prowler_azure: Prowler subprocess
    - scubagear: ScubaGear WPF UI launcher + ActionPlan.csv poller
    """
    scan_type = scan.get("scan_type", scan.get("provider", "aws"))

    if scan_type == "scubagear":
        await execute_scubagear_scan(scan, stream, output_dir)
        return

    from db.database import _DB_PATH

    scan_id  = scan["id"]
    provider = scan["provider"]

    async with aiosqlite.connect(_DB_PATH) as db:

        # ── Step 1: build command ─────────────────────────────────────
        try:
            cmd = build_scan_command(scan, output_dir)
            env = build_scan_env(scan, raw_secrets)
        except Exception as e:
            await stream.send_log(f"Failed to build scan command: {e}", stream="stderr")
            await stream.send_status("failed")
            await _update_scan_status(scan_id, "failed", db)
            await stream.close()
            return

        await stream.send_log(f"Starting Prowler scan ({provider.upper()})...")
        await stream.send_log(f"Command: {' '.join(cmd)}")
        await stream.send_log(f"Output:  {output_dir}")
        await stream.send_log("─" * 60)

        # ── Step 2: launch ────────────────────────────────────────────
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
                cwd=str(output_dir),
            )
        except (FileNotFoundError, OSError) as e:
            msg = str(e)
            if "prowler" in msg.lower() or "not found" in msg.lower():
                msg = (
                    "Prowler binary not found. "
                    "Install via: uv tool install prowler --python 3.12\n"
                    f"Detail: {e}"
                )
            await stream.send_log(msg, stream="stderr")
            await stream.send_status("failed")
            await _update_scan_status(scan_id, "failed", db)
            await stream.close()
            return

        _register_scan(scan_id, proc)
        await _update_scan_status(scan_id, "running", db)
        await stream.send_status("running")

        scan_start = datetime.now(timezone.utc)

        # ── Step 3: stream output ─────────────────────────────────────
        stdout_q: asyncio.Queue[str | None] = asyncio.Queue()

        async def _read():
            assert proc.stdout is not None
            async for raw in proc.stdout:
                await stdout_q.put(raw.decode("utf-8", errors="replace").rstrip())
            await stdout_q.put(None)

        reader = asyncio.create_task(_read())

        while True:
            try:
                line = await asyncio.wait_for(stdout_q.get(), timeout=15.0)
            except asyncio.TimeoutError:
                await stream.send_json({"type": "heartbeat"})
                continue
            if line is None:
                break
            if not line:
                continue
            await stream.send_log(line)
            await _append_scan_log(scan_id, line, "stdout", db)

        reader.cancel()

        # ── Step 4: wait for exit ─────────────────────────────────────
        await proc.wait()
        _deregister_scan(scan_id)
        rc = proc.returncode

        duration = int((datetime.now(timezone.utc) - scan_start).total_seconds())
        await stream.send_log("─" * 60)

        # Prowler exit codes:
        #   0 = scan complete, all checks passed
        #   1 = scan complete, findings found (FAIL results) — this is NORMAL
        #   2 = usage/argument error
        #   other = actual crash
        scan_succeeded = rc in (0, 1) or rc is None

        if scan_succeeded:
            # Detect output file
            output_file = find_scan_output(output_dir)
            if output_file:
                await stream.send_log(f"✓ Scan complete — output: {output_file.name}")
                await stream.send_json({
                    "type":        "scan_complete",
                    "output_file": str(output_file),
                    "output_dir":  str(output_dir),
                    "duration":    duration,
                })
                await _update_scan_status(
                    scan_id, "complete", db,
                    output_file=str(output_file),
                    output_dir=str(output_dir),
                    duration_secs=duration,
                )
            else:
                await stream.send_log(
                    "⚠ Prowler exited cleanly but no CSV output found. "
                    "Check the output directory.",
                    stream="stderr",
                )
                await _update_scan_status(
                    scan_id, "complete", db,
                    output_dir=str(output_dir),
                    duration_secs=duration,
                )
            await stream.send_status("complete")

        elif rc == -15 or rc == 15:
            await stream.send_log("Scan was cancelled.", stream="stderr")
            await _update_scan_status(scan_id, "cancelled", db, duration_secs=duration)
            await stream.send_status("cancelled")

        else:
            await stream.send_log(
                f"✗ Prowler exited with code {rc} — scan failed (not a findings error)",
                stream="stderr",
            )
            await _update_scan_status(scan_id, "failed", db, duration_secs=duration)
            await stream.send_status("failed")

        await stream.close()


# ── Helpers ───────────────────────────────────────────────────────────

def _parse_json_list(value: str) -> list[str]:
    """Parse a JSON array string or return empty list."""
    if not value:
        return []
    try:
        result = json.loads(value)
        return [str(x).strip() for x in result if str(x).strip()]
    except (json.JSONDecodeError, TypeError):
        return []


# ── AWS services reference ────────────────────────────────────────────
# Common Prowler AWS service names for the UI selector

AWS_SERVICES = [
    "accessanalyzer", "account", "acm", "apigateway", "appstream",
    "athena", "autoscaling", "backup", "bedrock", "cloudformation",
    "cloudfront", "cloudtrail", "cloudwatch", "codebuild", "cognito",
    "config", "dax", "directoryservice", "dlm", "dms", "dynamodb",
    "ec2", "ecr", "ecs", "efs", "eks", "elasticache", "elb", "emr",
    "glacier", "glue", "guardduty", "iam", "inspector2", "kafka",
    "kinesis", "kms", "lambda", "lightsail", "macie", "mq",
    "networkfirewall", "opensearch", "rds", "redshift", "route53",
    "s3", "sagemaker", "secretsmanager", "securityhub", "ses",
    "shield", "sns", "sqs", "ssm", "trustedadvisor", "vpc",
    "waf", "workspaces",
]

AZURE_SERVICES = [
    "aisearch", "app", "appinsights", "appservice", "authorization",
    "blob", "compute", "container", "containerregistry", "cosmosdb",
    "defender", "disk", "dns", "entra", "eventhub", "frontdoor",
    "iam", "keyvault", "monitor", "mysql", "network", "postgresql",
    "servicebus", "sql", "sqlserver", "storage", "vm",
]


# ── ScubaGear scan ────────────────────────────────────────────────────

SCUBA_PRODUCTS = ["aad", "defender", "exo", "sharepoint", "teams", "powerplatform"]

SCUBA_PRODUCT_LABELS = {
    "aad":           "Entra ID (AAD)",
    "defender":      "Microsoft Defender",
    "exo":           "Exchange Online",
    "sharepoint":    "SharePoint Online",
    "teams":         "Microsoft Teams",
    "powerplatform": "Power Platform",
}


def generate_scubagear_yaml(
    output_dir: Path,
    tenant_domain: str,
    display_name: str,
    m365_environment: str = "commercial",
    products: Optional[list[str]] = None,
) -> Path:
    """
    Generate a ScubaGear YAML configuration file pre-filled with our output
    directory. The analyst loads this into Start-SCuBAConfigApp via
    -ConfigFilePath so the output lands exactly where we expect it.

    ScubaGear YAML format based on:
    https://github.com/cisagov/ScubaGear/blob/main/docs/configuration/configuration.md
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Use all products if none specified
    product_list = products or SCUBA_PRODUCTS

    # ScubaGear expects Windows-style paths in YAML on Windows
    output_path_str = str(output_dir).replace("\\", "/")

    yaml_content = f"""# ScubaGear configuration — generated by Cloud Security Reporter GUI
# Load this file in Start-SCuBAConfigApp via File > Import Configuration

ProductNames:
{chr(10).join(f"  - {p}" for p in product_list)}

M365Environment: {m365_environment}

OrgDisplayName: "{display_name}"

OutPath: "{output_path_str}"

OutFolderName: "ScubaResults"

# Authentication will be handled interactively via the ScubaConfigApp UI
"""

    yaml_path = output_dir / "scubagear_scan_config.yaml"
    yaml_path.write_text(yaml_content, encoding="utf-8")
    return yaml_path


def find_scuba_output(output_dir: Path, scan_started_at: float = 0.0) -> Optional[Path]:
    """
    Find ActionPlan.csv from a completed ScubaGear scan.

    ScubaGear writes to default locations when no output path is set:
      ~/Documents/M365BaselineConformance_DATE/ActionPlan.csv
      ~/Desktop/M365BaselineConformance_DATE/ActionPlan.csv

    Search all likely locations. Only return files newer than scan_started_at
    to avoid picking up results from previous scans.
    """
    search_dirs = [
        output_dir,
        Path.home() / "Documents",
        Path.home() / "Desktop",
        Path.cwd(),
    ]

    candidates = []
    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        try:
            for f in search_dir.rglob("ActionPlan.csv"):
                try:
                    if scan_started_at and f.stat().st_mtime < (scan_started_at - 30):
                        continue
                    candidates.append(f)
                except OSError:
                    continue
        except PermissionError:
            continue

    if not candidates:
        for search_dir in search_dirs:
            if not search_dir.exists():
                continue
            try:
                for f in search_dir.rglob("ScubaResults.csv"):
                    try:
                        if scan_started_at and f.stat().st_mtime < (scan_started_at - 30):
                            continue
                        candidates.append(f)
                    except OSError:
                        continue
            except PermissionError:
                continue

    if not candidates:
        return None
    return max(candidates, key=lambda f: f.stat().st_mtime)


async def execute_scubagear_scan(
    scan: dict,
    stream: SseStream,
    output_dir: Path,
) -> None:
    """
    Launch ScubaGear via Start-SCuBAConfigApp with no config file.

    ConvertFrom-Yaml errors occur when -ConfigFilePath is passed and
    the powershell-yaml module is missing. To avoid this entirely we
    launch the app clean and show the analyst the output path to paste.

    Flow:
      1. Create output directory
      2. Launch Start-SCuBAConfigApp (no arguments)
      3. Show analyst the output path to set in Advanced Settings
      4. Poll every 10s for ActionPlan.csv in output_dir + default locations
      5. Mark complete when found
    """
    from db.database import _DB_PATH
    import time

    scan_id = scan["id"]

    async with aiosqlite.connect(_DB_PATH) as db:

        # ── Step 1: create output directory ──────────────────────────
        output_dir.mkdir(parents=True, exist_ok=True)
        import os as _os
        # Use os.path.normpath to get native OS separators (backslashes on Windows)
        output_path_display = _os.path.normpath(str(output_dir))

        # ── Step 2: show instructions ─────────────────────────────────
        await stream.send_log("=" * 60)
        await stream.send_log("ScubaGear Scan")
        await stream.send_log("=" * 60)
        await stream.send_log("ScubaGear is opening in a new window.")
        await stream.send_log("")
        await stream.send_log("In the ScubaGear window:")
        await stream.send_log("  1. Go to Advanced Settings")
        await stream.send_log("  2. Set Output Path to the path shown on screen")
        await stream.send_log("  3. Configure your tenant and authenticate")
        await stream.send_log("  4. Click Run ScubaGear")
        await stream.send_log("  5. Return here when done — page updates automatically")
        await stream.send_log("=" * 60)

        await stream.send_json({
            "type":        "scuba_instructions",
            "output_path": output_path_display,
        })

        # ── Step 3: launch ScubaConfigApp ────────────────────────────
        # ScubaGear may be installed locally (e.g. Documents/ScubaGear-1.8.0)
        # rather than in PSModulePath. Search common locations and import
        # from the explicit .psd1 path if the standard import fails.
        ps_command = (
            "Import-Module ScubaGear -Force -ErrorAction SilentlyContinue; "
            "if (-not (Get-Module ScubaGear)) { "
            "$psd1 = Get-ChildItem $env:USERPROFILE -Recurse -Filter ScubaGear.psd1 "
            "-ErrorAction SilentlyContinue | Select-Object -First 1; "
            "if ($psd1) { Import-Module $psd1.FullName -Force } }; "
            "Start-SCuBAConfigApp"
        )
        ps_cmd = [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-Command", ps_command,
        ]

        await _update_scan_status(scan_id, "running", db)
        await stream.send_status("running")

        try:
            proc = await asyncio.create_subprocess_exec(
                *ps_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except (FileNotFoundError, OSError) as e:
            await stream.send_log(f"Failed to launch ScubaGear: {e}", stream="stderr")
            await stream.send_status("failed")
            await _update_scan_status(scan_id, "failed", db)
            await stream.close()
            return

        _register_scan(scan_id, proc)
        scan_start    = datetime.now(timezone.utc)
        scan_start_ts = time.time()

        # ── Step 4: poll for ActionPlan.csv ──────────────────────────
        POLL_INTERVAL = 10
        MAX_WAIT      = 7200  # 2 hours

        elapsed     = 0
        output_file = None

        while elapsed < MAX_WAIT:
            await asyncio.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL

            proc_done = proc.returncode is not None
            if not proc_done:
                try:
                    await asyncio.wait_for(asyncio.shield(proc.wait()), timeout=0.1)
                    proc_done = True
                except asyncio.TimeoutError:
                    pass

            output_file = find_scuba_output(output_dir, scan_start_ts)

            mins = elapsed // 60
            secs = elapsed % 60
            await stream.send_log(f"  Waiting... {mins}m {secs}s elapsed")
            await stream.send_json({"type": "heartbeat"})

            if output_file:
                await stream.send_log(f"✓ Found: {output_file.name}")
                break

            if proc_done and not output_file:
                await stream.send_log(
                    "ScubaGear was closed before scan completed.", stream="stderr"
                )
                await _update_scan_status(scan_id, "failed", db)
                await stream.send_status("failed")
                _deregister_scan(scan_id)
                await stream.close()
                return

        _deregister_scan(scan_id)
        duration = int((datetime.now(timezone.utc) - scan_start).total_seconds())

        if output_file:
            await stream.send_log("✓ ScubaGear scan complete")
            await stream.send_json({
                "type":        "scan_complete",
                "output_file": str(output_file),
                "output_dir":  str(output_dir),
                "duration":    duration,
            })
            await _update_scan_status(
                scan_id, "complete", db,
                output_file=str(output_file),
                output_dir=str(output_dir),
                duration_secs=duration,
            )
            await stream.send_status("complete")
        else:
            await stream.send_log("Timed out after 2 hours.", stream="stderr")
            await _update_scan_status(scan_id, "failed", db, duration_secs=duration)
            await stream.send_status("failed")

        await stream.close()