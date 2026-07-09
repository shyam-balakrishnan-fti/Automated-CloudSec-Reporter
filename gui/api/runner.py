"""
api/runner.py — Pipeline subprocess execution.

Responsibilities:
  - Locate the repo root (auto-detect from gui/__file__)
  - Build the correct CLI command for Prowler or ScubaGear
  - Inject AWS credentials into subprocess environment
  - Stream stdout/stderr to an SseStream (consumed by the frontend)
  - Write every log line to run_logs in SQLite
  - Advance run.status through the state machine
  - Detect review server ready (parse port from stdout)
  - Handle cancellation cleanly (SIGTERM / terminate())

State machine:
  pending → running → awaiting_review → enriching → complete
                                                   → failed
                                                   → cancelled

Review detection:
  Both review UIs print a line containing their port number when ready.
  Prowler:    "Review UI available at http://localhost:8742"
  ScubaGear:  "Review UI available at http://localhost:8743"
  The runner parses these and emits a status event so the frontend
  can show the "Open Review UI" button.
"""

from __future__ import annotations

import asyncio
import os
import platform
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiosqlite

from api.sse import SseStream
from db.database import get_db

# ── Repo root detection ───────────────────────────────────────────────

def find_repo_root() -> Path:
    """
    Walk up from gui/ until we find a directory containing both
    src/run_pipeline.py and scubagear/src/run_scubagear.py.
    Raises RuntimeError if not found.
    """
    candidate = Path(__file__).parent.parent.resolve()

    for _ in range(5):  # max 5 levels up
        prowler_entry = candidate / "src" / "run_pipeline.py"
        scuba_entry   = candidate / "scubagear" / "src" / "run_scubagear.py"
        if prowler_entry.exists() and scuba_entry.exists():
            return candidate
        candidate = candidate.parent

    raise RuntimeError(
        "Cannot locate repo root. Expected to find src/run_pipeline.py "
        "and scubagear/src/run_scubagear.py in a parent directory of gui/. "
        f"Searched up from: {Path(__file__).parent.parent.resolve()}"
    )


def _find_python(repo_root: Path) -> str:
    """
    Return the Python executable that has the pipeline dependencies installed.

    Priority:
      1. repo_root/.venv/bin/python3   (Linux/macOS root venv)
      2. repo_root/.venv/Scripts/python.exe  (Windows root venv)
      3. sys.executable fallback (GUI's own venv — will likely fail if deps missing)

    The GUI runs in gui/.venv which does NOT have openpyxl, boto3 etc.
    The pipeline dependencies are installed in the root .venv.
    """
    candidates = [
        repo_root / ".venv" / "bin" / "python3",
        repo_root / ".venv" / "bin" / "python",
        repo_root / ".venv" / "Scripts" / "python.exe",
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    # Fallback — log a warning at runtime via the stream
    return sys.executable


# ── CLI command builder ───────────────────────────────────────────────

def build_command(run: dict, repo_root: Path) -> list[str]:
    """
    Build the subprocess command list for a given run record.
    Uses the root venv Python so pipeline dependencies (openpyxl, boto3, etc.)
    are available. The GUI runs in its own separate venv (gui/.venv).
    """
    pipeline = run["pipeline"]
    python   = _find_python(repo_root)

    if pipeline == "prowler":
        entry = repo_root / "src" / "run_pipeline.py"
        cmd = [
            python, str(entry),
            "--input",     run["input_file"],
            "--format",    run["input_format"],
            "--config",    run["config_path"],
            "--output-dir", run["output_dir"],  # run-specific dir — avoids stale approvals
        ]
        cmd.append("--no-browser")   # GUI handles browser opening via review banner
        cmd.append("--force-review") # always start fresh — never reuse old approval files
        if run.get("skip_review"):
            cmd.append("--skip-review")
        if run.get("skip_llm"):
            cmd.append("--skip-grouping")  # scubagear uses --skip-grouping not --skip-llm

    elif pipeline == "scubagear":
        entry = repo_root / "scubagear" / "src" / "run_scubagear.py"
        cmd = [
            python, str(entry),
            "--action-plan", run["input_file"],
            "--config",      run["config_path"],
        ]
        if run.get("tenant_id"):
            cmd += ["--tenant-id", run["tenant_id"]]
        cmd += ["--output-dir", run["output_dir"]]  # run-specific dir
        cmd.append("--no-browser")   # GUI handles browser opening via review banner
        # Note: --force-review is not supported by run_scubagear.py
        if run.get("skip_review"):
            cmd.append("--skip-review")
        if run.get("skip_llm"):
            cmd.append("--skip-grouping")  # scubagear uses --skip-grouping not --skip-llm

    else:
        raise ValueError(f"Unknown pipeline: {pipeline}")

    return cmd


def build_env(run: dict) -> dict[str, str]:
    """
    Build the subprocess environment.
    Injects AWS credentials if provided, otherwise inherits ambient env.
    Raw keys are never stored in the DB — they come from the in-memory
    run config passed at launch time.
    """
    env = os.environ.copy()

    cred_source = run.get("credential_source", "profile")

    if cred_source == "profile" and run.get("aws_profile"):
        env["AWS_PROFILE"]         = run["aws_profile"]
        env["AWS_DEFAULT_REGION"]  = run.get("aws_region", "ap-southeast-2")

    elif cred_source == "keys":
        if run.get("aws_access_key_id"):
            env["AWS_ACCESS_KEY_ID"]     = run["aws_access_key_id"]
        if run.get("aws_secret_access_key"):
            env["AWS_SECRET_ACCESS_KEY"] = run["aws_secret_access_key"]
        if run.get("aws_session_token"):
            env["AWS_SESSION_TOKEN"]     = run["aws_session_token"]
        env["AWS_DEFAULT_REGION"] = run.get("aws_region", "ap-southeast-2")

    return env


# ── Review UI detection ───────────────────────────────────────────────

_REVIEW_MARKERS = {
    "prowler":   ["localhost:8742", "port 8742", ":8742"],
    "scubagear": ["localhost:8743", "port 8743", ":8743"],
}

def _detect_review_ready(line: str, pipeline: str) -> bool:
    markers = _REVIEW_MARKERS.get(pipeline, [])
    line_lower = line.lower()
    return any(m in line_lower for m in markers)


_ENRICHING_MARKERS = [
    "stage 3", "[ stage 3 ]", "enriching", "llm enrichment",
    "starting enrichment",
    "approved grouping:",
    "approved grouping:", "stage 3", "enrich",
]

def _detect_enriching(line: str) -> bool:
    return any(m in line.lower() for m in _ENRICHING_MARKERS)


_COMPLETE_MARKERS = [
    "stage 5", "[ stage 5 ]", "excel rendered", "report written",
    "pipeline complete", "run complete",
    # ScubaGear uses "pipeline complete" (already in line 193)
    "pipeline complete", "✓ pipeline complete",
]

def _detect_complete(line: str) -> bool:
    return any(m in line.lower() for m in _COMPLETE_MARKERS)


# ── Active process registry ───────────────────────────────────────────

_active_processes: dict[str, asyncio.subprocess.Process] = {}


def get_active_process(run_id: str) -> Optional[asyncio.subprocess.Process]:
    return _active_processes.get(run_id)


def _register_process(run_id: str, proc: asyncio.subprocess.Process) -> None:
    _active_processes[run_id] = proc


def _deregister_process(run_id: str) -> None:
    _active_processes.pop(run_id, None)


async def cancel_run(run_id: str) -> bool:
    """
    Send SIGTERM (Linux/macOS) or terminate() (Windows) to the pipeline process.
    Returns True if a process was found and signalled.
    Leaves checkpoint files on disk — DB status is updated to 'cancelled' by the caller.
    """
    proc = _active_processes.get(run_id)
    if not proc:
        return False

    try:
        if platform.system().lower() == "windows":
            proc.terminate()
        else:
            proc.send_signal(signal.SIGTERM)
    except (ProcessLookupError, OSError):
        pass

    _deregister_process(run_id)
    return True


# ── DB helpers ────────────────────────────────────────────────────────

async def _update_run_status(run_id: str, status: str, db: aiosqlite.Connection) -> None:
    now = datetime.now(timezone.utc).isoformat()
    if status in ("complete", "failed", "cancelled"):
        await db.execute(
            "UPDATE runs SET status = ?, completed_at = ? WHERE id = ?",
            (status, now, run_id),
        )
    elif status == "running":
        await db.execute(
            "UPDATE runs SET status = ?, started_at = ? WHERE id = ?",
            (status, now, run_id),
        )
    else:
        await db.execute("UPDATE runs SET status = ? WHERE id = ?", (status, run_id))
    await db.commit()


async def _append_log(
    run_id: str,
    line: str,
    stream_name: str,
    db: aiosqlite.Connection,
) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "INSERT INTO run_logs (run_id, ts, stream, line) VALUES (?, ?, ?, ?)",
        (run_id, ts, stream_name, line),
    )
    await db.commit()




# ── Review approval polling ───────────────────────────────────────────

async def poll_for_approval(run_id: str, output_dir: str, stream: SseStream) -> None:
    """
    Poll for grouping_approved.json to detect when the analyst has approved
    and the pipeline has resumed from the review stage.

    Called when the GUI reconnects to an awaiting_review run. The pipeline
    process is still running (blocked on threading.Event) — we just need to
    watch for the approval file and emit a status update when it appears.

    Polls every 3 seconds for up to 4 hours (pipeline timeout).
    Exits early if the run status changes (pipeline resumes naturally
    and the SSE stream picks it up).
    """
    from db.database import _DB_PATH
    import aiosqlite

    # Search recursively — pipeline writes to output_dir/{client_slug}/grouping_approved.json
    base_dir  = Path(output_dir)
    max_polls = 4800  # 4 hours at 3s intervals

    for _ in range(max_polls):
        await asyncio.sleep(3)

        # Check if the approval file has appeared anywhere under output_dir
        approval_files = list(base_dir.rglob("grouping_approved.json")) if base_dir.exists() else []
        if approval_files:
            await stream.send_json({
                "type":    "review_approved",
                "message": f"Grouping approved ({approval_files[0].name}) — pipeline resuming",
            })
            await stream.send_status("enriching")
            return

        # Check if run is no longer awaiting_review in DB (pipeline moved on)
        async with aiosqlite.connect(_DB_PATH) as db:
            cursor = await db.execute(
                "SELECT status FROM runs WHERE id = ?", (run_id,)
            )
            row = await cursor.fetchone()
            if row and row[0] not in ("awaiting_review", "running"):
                return  # pipeline completed/failed — stream will catch it

    await stream.send_log(
        "⚠ Review polling timed out after 4 hours.", stream="stderr"
    )

# ── Main runner ───────────────────────────────────────────────────────

async def execute_run(
    run: dict,
    stream: SseStream,
    raw_credentials: Optional[dict] = None,
) -> None:
    """
    Execute a pipeline run end-to-end as an asyncio background task.

      1. Locates repo root and root venv Python
      2. Builds command + environment
      3. Launches subprocess
      4. Streams stdout line by line → SseStream + DB log
      5. Advances run status based on output markers
      6. Marks run complete/failed on exit
    """
    run_id   = run["id"]
    pipeline = run["pipeline"]

    # Merge raw credentials into run dict for env building (never persisted)
    run_with_creds = dict(run)
    if raw_credentials:
        run_with_creds.update(raw_credentials)

    from db.database import _DB_PATH
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # ── Step 1: locate repo root ──────────────────────────────────
        try:
            repo_root = find_repo_root()
        except RuntimeError as e:
            await stream.send_log(str(e), stream="stderr")
            await stream.send_status("failed")
            await _update_run_status(run_id, "failed", db)
            await stream.close()
            return

        # ── Step 2: build command ─────────────────────────────────────
        try:
            cmd = build_command(run, repo_root)
            env = build_env(run_with_creds)
        except Exception as e:
            await stream.send_log(f"Failed to build command: {e}", stream="stderr")
            await stream.send_status("failed")
            await _update_run_status(run_id, "failed", db)
            await stream.close()
            return

        await stream.send_log(f"Starting {pipeline} pipeline...")
        await stream.send_log(f"Python:  {cmd[0]}")
        await stream.send_log(f"Script:  {cmd[1]}")
        await stream.send_log(f"Working directory: {repo_root}")
        await stream.send_log("─" * 60)

        # ── Step 3: launch subprocess ─────────────────────────────────
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
                cwd=str(repo_root),
            )
        except (FileNotFoundError, OSError) as e:
            await stream.send_log(f"Failed to start process: {e}", stream="stderr")
            await stream.send_status("failed")
            await _update_run_status(run_id, "failed", db)
            await stream.close()
            return

        _register_process(run_id, proc)

        # Brief wait to catch immediate failures (bad flags, missing file, etc.)
        # argparse errors exit in <1s with code 2
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
            if proc.returncode is not None and proc.returncode != 0:
                # Process already died — read any output before reporting failure
                if proc.stdout:
                    out = await proc.stdout.read(4096)
                    err_text = out.decode("utf-8", errors="replace").strip()
                    if err_text:
                        await stream.send_log(err_text, stream="stderr")
                await stream.send_log(
                    f"Process exited immediately with code {proc.returncode}. "
                    f"Check the command flags and input file path.",
                    stream="stderr",
                )
                await _update_run_status(run_id, "failed", db)
                await stream.send_status("failed")
                _deregister_process(run_id)
                await stream.close()
                return
        except asyncio.TimeoutError:
            pass  # Process still running after 2s — good, proceed normally

        await _update_run_status(run_id, "running", db)
        await stream.send_status("running")

        # ── Step 4: stream output + concurrent DB status watcher ──────
        # The watcher polls DB every 3s and pushes status events to the
        # SSE stream. This guarantees the UI catches every stage transition
        # even if the stdout detection misses a marker line.
        current_status = "running"
        last_pushed_status = "running"

        async def _status_watcher():
            nonlocal last_pushed_status
            from db.database import _DB_PATH as _dp
            while True:
                await asyncio.sleep(3)
                try:
                    async with aiosqlite.connect(_dp) as _wdb:
                        cur = await _wdb.execute(
                            "SELECT status FROM runs WHERE id = ?", (run_id,)
                        )
                        row = await cur.fetchone()
                        if not row:
                            return
                        db_status = row[0]
                        if db_status != last_pushed_status:
                            last_pushed_status = db_status
                            await stream.send_status(db_status)
                            if db_status == "awaiting_review":
                                port = 8742 if pipeline == "prowler" else 8743
                                await stream.send_json({
                                    "type":     "review_ready",
                                    "port":     port,
                                    "url":      f"http://localhost:{port}/review",
                                    "pipeline": pipeline,
                                })
                        if db_status in ("complete", "failed", "cancelled"):
                            return
                except Exception:
                    pass

        watcher_task = asyncio.create_task(_status_watcher())

        # Read stdout in a separate task so we can keep the SSE stream
        # alive with heartbeats even when stdout is blocked (e.g. review wait)
        stdout_lines: asyncio.Queue[str | None] = asyncio.Queue()

        async def _read_stdout():
            assert proc.stdout is not None
            async for raw_line in proc.stdout:
                line = raw_line.decode("utf-8", errors="replace").rstrip()
                await stdout_lines.put(line)
            await stdout_lines.put(None)  # sentinel

        stdout_task = asyncio.create_task(_read_stdout())

        # Process lines with a timeout — send heartbeats when pipeline is silent
        while True:
            try:
                line = await asyncio.wait_for(stdout_lines.get(), timeout=10.0)
            except asyncio.TimeoutError:
                # Pipeline is silent (e.g. waiting for review approval)
                # Send a heartbeat to keep the SSE connection alive
                await stream.send_json({"type": "heartbeat"})
                continue

            if line is None:
                break  # stdout closed — process has exited

            if not line:
                continue

            await stream.send_log(line)
            await _append_log(run_id, line, "stdout", db)

            # Fast-path: update DB immediately on detection.
            # The watcher pushes the status event to SSE within 3s.
            if current_status == "running" and _detect_review_ready(line, pipeline):
                current_status = "awaiting_review"
                await _update_run_status(run_id, "awaiting_review", db)

            elif current_status == "awaiting_review" and _detect_enriching(line):
                current_status = "enriching"
                await _update_run_status(run_id, "enriching", db)

            elif current_status in ("running", "enriching") and _detect_complete(line):
                current_status = "enriching"

        watcher_task.cancel()
        stdout_task.cancel()

        # ── Step 5: process exit ──────────────────────────────────────
        await proc.wait()
        _deregister_process(run_id)
        rc = proc.returncode

        await stream.send_log("─" * 60)

        if rc == 0:
            await stream.send_log("✓ Pipeline completed successfully (exit code 0)")
            await _update_run_status(run_id, "complete", db)
            await stream.send_status("complete")

            # Locate output Excel.
            # Pipeline writes to output_dir/{client_slug}/*.xlsx so search recursively.
            output_dir = Path(run.get("output_dir", ""))
            xlsx_files = []
            if output_dir.exists():
                xlsx_files = list(output_dir.rglob("*.xlsx"))
            if xlsx_files:
                # Prefer the most recently modified file if multiple exist
                xlsx_file = max(xlsx_files, key=lambda f: f.stat().st_mtime)
                xlsx_path = str(xlsx_file)
                await db.execute(
                    "UPDATE runs SET excel_path = ? WHERE id = ?",
                    (xlsx_path, run_id),
                )
                await db.commit()
                await stream.send_json({
                    "type":       "output_ready",
                    "excel_path": xlsx_path,
                    "filename":   xlsx_file.name,
                })

        elif rc == -15:
            # SIGTERM — cancelled by user
            await stream.send_log("Run was cancelled.", stream="stderr")
            await _update_run_status(run_id, "cancelled", db)
            await stream.send_status("cancelled")

        else:
            await stream.send_log(
                f"✗ Pipeline exited with code {rc}", stream="stderr"
            )
            await _update_run_status(run_id, "failed", db)
            await stream.send_status("failed")

        await stream.close()