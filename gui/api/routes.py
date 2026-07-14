"""
api/routes.py — All FastAPI route handlers.

Routers:
  /api/platform          OS info, tool availability
  /api/engagements       CRUD for engagement records
  /api/engagements/{id}/runs   Run creation and listing
  /api/runs/{id}         Run detail, preflight
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse

from api.models import (
    CredentialSource,
    EngagementCreate,
    EngagementResponse,
    PipelineType,
    PreflightResult,
    RunCreate,
    RunResponse,
    PlatformInfo,
    ScanCreate,
    ScanProvider,
)
from api.platform import (
    get_platform_info, run_preflight,
    prowler_installed, scubagear_installed, scubagear_supported,
)
from api.config_writer import write_prowler_config, write_scubagear_config
from api.sse import register_stream, get_stream, remove_stream
from api import installer
from db.database import get_db

router = APIRouter()

_now = lambda: datetime.now(timezone.utc).isoformat()


# ── Platform ──────────────────────────────────────────────────────────

@router.get("/platform", response_model=PlatformInfo)
async def platform_info():
    """
    Returns OS, tool availability, and AWS profiles.
    Called by the frontend on page load to determine which pipelines
    are available and populate the profile picker.
    """
    return get_platform_info()


# ── Engagements ───────────────────────────────────────────────────────

@router.get("/engagements", response_model=list[EngagementResponse])
async def list_engagements(
    include_archived: bool = False,
    db: aiosqlite.Connection = Depends(get_db),
):
    """List engagements, newest first. Excludes archived by default."""
    if include_archived:
        cursor = await db.execute(
            "SELECT * FROM engagements ORDER BY created_at DESC"
        )
    else:
        cursor = await db.execute(
            "SELECT * FROM engagements WHERE archived_at IS NULL ORDER BY created_at DESC"
        )
    rows = await cursor.fetchall()

    results = []
    for row in rows:
        eng = dict(row)

        # Attach run count and last run status
        c2 = await db.execute(
            "SELECT COUNT(*), MAX(created_at) FROM runs WHERE engagement_id = ?",
            (eng["id"],),
        )
        count_row = await c2.fetchone()
        run_count = count_row[0] if count_row else 0

        last_status = None
        if run_count:
            c3 = await db.execute(
                "SELECT status FROM runs WHERE engagement_id = ? ORDER BY created_at DESC LIMIT 1",
                (eng["id"],),
            )
            sr = await c3.fetchone()
            last_status = sr[0] if sr else None

        results.append(EngagementResponse(
            **eng,
            run_count=run_count,
            last_run_status=last_status,
        ))
    return results


@router.post("/engagements", response_model=EngagementResponse, status_code=status.HTTP_201_CREATED)
async def create_engagement(
    body: EngagementCreate,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Create a new engagement."""
    eid = str(uuid.uuid4())
    now = _now()

    await db.execute(
        """
        INSERT INTO engagements
            (id, client_name, assessment_period, analyst, pipeline_type, created_at, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (eid, body.client_name, body.assessment_period, body.analyst,
         body.pipeline_type.value, now, body.notes),
    )
    await db.commit()

    return EngagementResponse(
        id=eid,
        client_name=body.client_name,
        assessment_period=body.assessment_period,
        analyst=body.analyst,
        pipeline_type=body.pipeline_type,
        created_at=now,
        archived_at=None,
        notes=body.notes,
        run_count=0,
        last_run_status=None,
    )


@router.get("/engagements/{engagement_id}", response_model=EngagementResponse)
async def get_engagement(
    engagement_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    cursor = await db.execute(
        "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Engagement not found")

    eng = dict(row)
    c2 = await db.execute(
        "SELECT COUNT(*) FROM runs WHERE engagement_id = ?", (engagement_id,)
    )
    count_row = await c2.fetchone()
    run_count = count_row[0] if count_row else 0

    last_status = None
    if run_count:
        c3 = await db.execute(
            "SELECT status FROM runs WHERE engagement_id = ? ORDER BY created_at DESC LIMIT 1",
            (engagement_id,),
        )
        sr = await c3.fetchone()
        last_status = sr[0] if sr else None

    return EngagementResponse(**eng, run_count=run_count, last_run_status=last_status)


@router.patch("/engagements/{engagement_id}/archive", response_model=EngagementResponse)
async def archive_engagement(
    engagement_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Soft-delete an engagement. Runs are preserved."""
    cursor = await db.execute(
        "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Engagement not found")

    now = _now()
    await db.execute(
        "UPDATE engagements SET archived_at = ? WHERE id = ?",
        (now, engagement_id),
    )
    await db.commit()

    eng = dict(row)
    eng["archived_at"] = now
    return EngagementResponse(**eng, run_count=0, last_run_status=None)


# ── Runs ──────────────────────────────────────────────────────────────

@router.get("/engagements/{engagement_id}/runs", response_model=list[RunResponse])
async def list_runs(
    engagement_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    cursor = await db.execute(
        "SELECT * FROM runs WHERE engagement_id = ? ORDER BY created_at DESC",
        (engagement_id,),
    )
    rows = await cursor.fetchall()
    return [_run_row_to_response(dict(r)) for r in rows]


@router.post(
    "/engagements/{engagement_id}/runs",
    response_model=RunResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_run(
    engagement_id: str,
    body: RunCreate,
    db: aiosqlite.Connection = Depends(get_db),
):
    """
    Create a run record and write the config.toml for it.
    Does NOT start the pipeline — that is Phase 3.
    """
    # Verify engagement exists
    cursor = await db.execute(
        "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
    )
    eng_row = await cursor.fetchone()
    if not eng_row:
        raise HTTPException(status_code=404, detail="Engagement not found")
    eng = dict(eng_row)

    run_id = str(uuid.uuid4())
    now    = _now()


    # Determine output base directory.
    # Use short paths on Windows to avoid the 259-char limit (OneDrive makes paths very long).
    # The pipeline appends client_name as a subfolder automatically.
    import platform as _plat
    if _plat.system().lower() == "windows":
        short_base = Path("C:/CloudSecReports")
        output_dir = short_base / run_id[:8]
    else:
        pipeline_base = "data" if body.pipeline == PipelineType.PROWLER else Path("scubagear") / "data"
        output_dir = (Path.cwd().parent / pipeline_base / "output" / run_id).resolve()

    # Write config.toml
    # Template path: go up from gui/ to repo root, then into templates/
    repo_root     = Path.cwd().parent
    prowler_tmpl  = str(repo_root / "templates" / "Output_Template.xlsx")
    scuba_tmpl    = str(repo_root / "scubagear" / "templates" / "Output_Template.xlsx")

    config_path_str = ""
    if body.pipeline == PipelineType.PROWLER:
        config_path = write_prowler_config(
            output_dir=output_dir,
            client_name=eng["client_name"],
            assessment_period=eng["assessment_period"],
            analyst=eng["analyst"],
            aws_region=body.aws_region,
            template_path=prowler_tmpl,
            deployment_name=getattr(body, "deployment_name", "") or "",
        )
        config_path_str = str(config_path)
    elif body.pipeline == PipelineType.SCUBAGEAR:
        config_path = write_scubagear_config(
            output_dir=output_dir,
            client_name=eng["client_name"],
            assessment_period=eng["assessment_period"],
            analyst=eng["analyst"],
            aws_region=body.aws_region,
            tenant_id=body.tenant_id,
            template_path=scuba_tmpl,
            deployment_name=getattr(body, "deployment_name", "") or "",
        )
        config_path_str = str(config_path)

    await db.execute(
        """
        INSERT INTO runs (
            id, engagement_id, pipeline, status,
            input_file, input_format, tenant_id,
            credential_source, aws_profile, aws_region,
            skip_review, skip_llm,
            config_path, output_dir,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id, engagement_id, body.pipeline.value, "pending",
            body.input_file, body.input_format, body.tenant_id,
            body.credential_source.value, body.aws_profile, body.aws_region,
            int(body.skip_review), int(body.skip_llm),
            config_path_str, str(output_dir),
            now,
        ),
    )
    await db.commit()

    return RunResponse(
        id=run_id,
        engagement_id=engagement_id,
        pipeline=body.pipeline.value,
        status="pending",
        input_file=body.input_file,
        input_format=body.input_format,
        tenant_id=body.tenant_id,
        credential_source=body.credential_source.value,
        aws_profile=body.aws_profile,
        aws_region=body.aws_region,
        skip_review=body.skip_review,
        skip_llm=body.skip_llm,
        created_at=now,
        started_at=None,
        completed_at=None,
        findings_total=None,
        findings_included=None,
        groups_total=None,
        groups_enriched=None,
        risk_high=None,
        risk_medium=None,
        risk_low=None,
        llm_failures=None,
        excel_path=None,
        config_path=config_path_str,
        output_dir=str(output_dir),
    )


@router.get("/runs/{run_id}", response_model=RunResponse)
async def get_run(
    run_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    cursor = await db.execute("SELECT * FROM runs WHERE id = ?", (run_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Run not found")
    return _run_row_to_response(dict(row))


@router.get("/runs/{run_id}/preflight", response_model=PreflightResult)
async def preflight_run(
    run_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Run preflight checks for a pending run."""
    cursor = await db.execute("SELECT * FROM runs WHERE id = ?", (run_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Run not found")
    run = dict(row)

    return run_preflight(
        pipeline=run["pipeline"],
        input_file=run["input_file"],
        aws_profile=run["aws_profile"],
        credential_source=run["credential_source"],
        output_dir=run["output_dir"],
    )


# ── Helpers ───────────────────────────────────────────────────────────

def _run_row_to_response(row: dict) -> RunResponse:
    return RunResponse(
        id=row["id"],
        engagement_id=row["engagement_id"],
        pipeline=row["pipeline"],
        status=row["status"],
        input_file=row["input_file"],
        input_format=row["input_format"],
        tenant_id=row["tenant_id"],
        credential_source=row["credential_source"],
        aws_profile=row["aws_profile"],
        aws_region=row["aws_region"],
        skip_review=bool(row["skip_review"]),
        skip_llm=bool(row["skip_llm"]),
        created_at=row["created_at"],
        started_at=row.get("started_at"),
        completed_at=row.get("completed_at"),
        findings_total=row.get("findings_total"),
        findings_included=row.get("findings_included"),
        groups_total=row.get("groups_total"),
        groups_enriched=row.get("groups_enriched"),
        risk_high=row.get("risk_high"),
        risk_medium=row.get("risk_medium"),
        risk_low=row.get("risk_low"),
        llm_failures=row.get("llm_failures"),
        excel_path=row.get("excel_path"),
        config_path=row.get("config_path"),
        output_dir=row.get("output_dir"),
    )


# ── Tool status ───────────────────────────────────────────────────────

@router.get("/tools/status")
async def tools_status():
    """
    Current installation status of Prowler and ScubaGear.
    Called by the UI to refresh status after an install completes.
    """
    prowler_ok, prowler_ver   = prowler_installed()
    scuba_ok,   scuba_ver     = scubagear_installed()
    scuba_avail               = scubagear_supported()

    return {
        "prowler": {
            "installed": prowler_ok,
            "version":   prowler_ver,
        },
        "scubagear": {
            "available":  scuba_avail,
            "installed":  scuba_ok,
            "version":    scuba_ver,
        },
    }


# ── Tool installation (SSE streams) ──────────────────────────────────

@router.post("/tools/install/{tool}")
async def install_tool(tool: str):
    """
    Start a tool installation and return an SSE task_id.
    The client then connects to GET /api/tools/install/{task_id}/stream
    to receive live output.

    tool: "prowler" | "scubagear"
    """
    if tool not in ("prowler", "scubagear"):
        raise HTTPException(status_code=400, detail=f"Unknown tool: {tool}")

    if tool == "scubagear" and not scubagear_supported():
        raise HTTPException(
            status_code=400,
            detail="ScubaGear is only available on Windows",
        )

    task_id = str(uuid.uuid4())
    stream  = register_stream(task_id)

    # Launch install in background — client streams via GET below
    if tool == "prowler":
        asyncio.create_task(installer.install_prowler(stream))
    else:
        asyncio.create_task(installer.install_scubagear(stream))

    return {"task_id": task_id}


@router.get("/tools/install/{task_id}/stream")
async def stream_install(task_id: str):
    """
    SSE endpoint — streams live output from a running installation.
    Connect immediately after POST /tools/install/{tool} returns task_id.
    """
    stream = get_stream(task_id)
    if not stream:
        raise HTTPException(status_code=404, detail="Install task not found or already completed")
    return stream.response()


# ── Run execution (Phase 3) ───────────────────────────────────────────

# In-memory store of raw credentials keyed by run_id.
# Never written to DB. Cleared when run completes/fails/cancels.
_pending_credentials: dict[str, dict] = {}


@router.post("/runs/{run_id}/start")
async def start_run(
    run_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    """
    Start a pending run.
    Returns {task_id} — client connects to /runs/{run_id}/stream for live output.
    Raw credentials must have been registered via POST /runs/{run_id}/credentials first.
    """
    from api import runner

    cursor = await db.execute("SELECT * FROM runs WHERE id = ?", (run_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Run not found")

    run = dict(row)

    if run["status"] not in ("pending", "failed"):
        raise HTTPException(
            status_code=400,
            detail=f"Run is in status '{run['status']}' — only pending or failed runs can be started",
        )

    # Register SSE stream
    stream = register_stream(run_id)

    # Retrieve raw credentials if provided
    raw_creds = _pending_credentials.pop(run_id, None)

    # Launch pipeline in background
    asyncio.create_task(runner.execute_run(run, stream, raw_creds))

    return {"task_id": run_id, "status": "starting"}


@router.post("/runs/{run_id}/credentials")
async def register_credentials(
    run_id: str,
    body: dict,
    db: aiosqlite.Connection = Depends(get_db),
):
    """
    Register raw AWS credentials for a run, in memory only.
    Must be called before POST /runs/{run_id}/start when credential_source == 'keys'.
    Credentials are cleared from memory as soon as the run starts.
    """
    cursor = await db.execute("SELECT id, status FROM runs WHERE id = ?", (run_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Run not found")

    # Only store the fields we actually need
    creds = {}
    for field in ("aws_access_key_id", "aws_secret_access_key", "aws_session_token"):
        if body.get(field):
            creds[field] = body[field]

    _pending_credentials[run_id] = creds
    return {"registered": True}


@router.get("/runs/{run_id}/stream")
async def stream_run(run_id: str):
    """
    SSE endpoint — streams live output from a running pipeline.
    Connect immediately after POST /runs/{run_id}/start.
    If the run has already completed, returns 404 (stream was consumed).
    """
    stream = get_stream(run_id)
    if not stream:
        raise HTTPException(
            status_code=404,
            detail="No active stream for this run. "
                   "The run may not have started yet or the stream has already closed.",
        )
    return stream.response()


@router.post("/runs/{run_id}/cancel")
async def cancel_run(
    run_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    """
    Cancel a running pipeline by sending SIGTERM to the subprocess.
    Checkpoint files on disk are preserved for inspection.
    """
    from api import runner

    cursor = await db.execute("SELECT status FROM runs WHERE id = ?", (run_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Run not found")

    current_status = row[0]
    if current_status not in ("running", "awaiting_review", "enriching"):
        raise HTTPException(
            status_code=400,
            detail=f"Run is '{current_status}' — only active runs can be cancelled",
        )

    signalled = await runner.cancel_run(run_id)

    # Update DB status — the background task may also set it,
    # but setting it here ensures it's visible immediately.
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "UPDATE runs SET status = 'cancelled', completed_at = ? WHERE id = ?",
        (now, run_id),
    )
    await db.commit()

    return {"cancelled": signalled, "run_id": run_id}


@router.get("/runs/{run_id}/logs")
async def get_run_logs(
    run_id: str,
    offset: int = 0,
    db: aiosqlite.Connection = Depends(get_db),
):
    """
    Fetch stored log lines for a run (for replay after page refresh).
    offset: skip the first N lines (for incremental fetching).
    """
    cursor = await db.execute(
        "SELECT ts, stream, line FROM run_logs WHERE run_id = ? "
        "ORDER BY id LIMIT 2000 OFFSET ?",
        (run_id, offset),
    )
    rows = await cursor.fetchall()
    return [{"ts": r[0], "stream": r[1], "line": r[2]} for r in rows]


# ── Run stream reconnect (Phase 4) ───────────────────────────────────

@router.post("/runs/{run_id}/reconnect")
async def reconnect_run_stream(
    run_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    """
    Reconnect to an active run after the client navigated away.

    For runs in awaiting_review / running / enriching:
      - Creates a new SSE stream
      - Replays the last 50 log lines so the panel isn't empty
      - If awaiting_review, starts approval polling in the background
      - Returns task_id (== run_id) for the client to connect to /stream

    The client calls GET /runs/{run_id}/stream after this to receive events.
    """
    from api import runner

    cursor = await db.execute("SELECT * FROM runs WHERE id = ?", (run_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Run not found")

    run = dict(row)
    status = run["status"]

    if status not in ("running", "awaiting_review", "enriching"):
        raise HTTPException(
            status_code=400,
            detail=f"Run status is '{status}' — only active runs can be reconnected",
        )

    # Close any existing stream for this run (shouldn't exist, but be safe)
    existing = get_stream(run_id)
    if existing and not existing._closed:
        await existing.close()
    remove_stream(run_id)

    # Create a fresh stream
    stream = register_stream(run_id)

    # Replay last 50 stored log lines so the panel isn't blank on reconnect
    cursor2 = await db.execute(
        """SELECT ts, stream, line FROM run_logs WHERE run_id = ?
           ORDER BY id DESC LIMIT 50""",
        (run_id,),
    )
    recent_rows = await cursor2.fetchall()
    recent_rows = list(reversed(recent_rows))  # restore chronological order

    async def _seed_and_poll():
        # Emit current status so any listeners get an immediate update
        await stream.send_status(status)

        # If awaiting review, emit review_ready and start approval polling
        if status == "awaiting_review":
            port = 8742 if run["pipeline"] == "prowler" else 8743
            await stream.send_json({
                "type":     "review_ready",
                "port":     port,
                "url":      f"http://localhost:{port}/review",
                "pipeline": run["pipeline"],
            })
            await runner.poll_for_approval(run_id, run["output_dir"], stream)

    asyncio.create_task(_seed_and_poll())

    return {"task_id": run_id, "status": status, "replayed_lines": len(recent_rows)}


# ── Phase 5: Output management ────────────────────────────────────────

@router.get("/runs/{run_id}/download")
async def download_excel(
    run_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    """
    Stream the completed Excel report to the browser as a file download.
    Returns 404 if the run has no output file yet.
    """
    from fastapi.responses import FileResponse

    cursor = await db.execute(
        "SELECT excel_path, status FROM runs WHERE id = ?", (run_id,)
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Run not found")

    excel_path, status = row[0], row[1]

    if not excel_path:
        raise HTTPException(
            status_code=404,
            detail=f"No output file for this run (status: {status})",
        )

    p = Path(excel_path)
    if not p.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Output file not found on disk: {excel_path}",
        )

    return FileResponse(
        path=str(p),
        filename=p.name,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@router.get("/runs/{run_id}/outputs")
async def list_run_outputs(
    run_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    """
    List all output files for a run (JSON checkpoints + Excel).
    Returns file names, sizes, and types — used by the output panel.
    """
    cursor = await db.execute(
        "SELECT output_dir, excel_path, status FROM runs WHERE id = ?", (run_id,)
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Run not found")

    output_dir, excel_path, status = row[0], row[1], row[2]

    files = []
    if output_dir:
        p = Path(output_dir)
        if p.exists():
            # Pipeline writes into a client_name subfolder — search recursively
            for f in sorted(p.rglob("*")):
                if f.is_file():
                    files.append({
                        "name":     f.name,
                        "size_kb":  round(f.stat().st_size / 1024, 1),
                        "type":     _classify_output_file(f.name),
                        "is_excel": f.suffix == ".xlsx",
                    })

    return {
        "run_id":     run_id,
        "status":     status,
        "output_dir": output_dir,
        "files":      files,
        "excel_path": excel_path,
    }


def _classify_output_file(name: str) -> str:
    """Human-readable file type label for the output panel."""
    mapping = {
        "canonical_findings.json":  "All findings (audit trail)",
        "output_groups.json":       "Dedup groups",
        "grouping_proposal.json":   "AI grouping proposal",
        "grouping_approved.json":   "Approved grouping",
        "m365_grouping_approved.json": "Approved grouping (M365)",
        "enriched_groups.json":     "Enriched groups",
        "run_manifest.json":        "Run manifest",
        "run_summary.json":         "Run summary",
        "config.toml":              "Pipeline config",
        "scubagear_config.toml":    "Pipeline config",
    }
    if name in mapping:
        return mapping[name]
    if name.endswith(".xlsx"):
        return "Excel report"
    if name.endswith(".json"):
        return "JSON checkpoint"
    if name.endswith(".toml"):
        return "Config file"
    return "File"


@router.get("/engagements/{engagement_id}/summary")
async def engagement_summary(
    engagement_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    """
    Return all runs for an engagement with their risk distributions.
    Used by the run comparison table.
    """
    cursor = await db.execute(
        "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
    )
    eng_row = await cursor.fetchone()
    if not eng_row:
        raise HTTPException(status_code=404, detail="Engagement not found")

    cursor2 = await db.execute(
        """SELECT id, pipeline, status, created_at, completed_at,
                  findings_total, findings_included, groups_total,
                  risk_high, risk_medium, risk_low, llm_failures,
                  excel_path, input_file
           FROM runs WHERE engagement_id = ?
           ORDER BY created_at DESC""",
        (engagement_id,),
    )
    runs = await cursor2.fetchall()

    return {
        "engagement": dict(eng_row),
        "runs": [dict(r) for r in runs],
    }


# ── Debug / test endpoints ────────────────────────────────────────────

@router.post("/debug/mock-run")
async def create_mock_run(db: aiosqlite.Connection = Depends(get_db)):
    """
    Create a fake run that simulates the full pipeline lifecycle:
    pending → running → awaiting_review → enriching → complete
    with 5s delays between stages. No pipeline is actually executed.
    Used to test SSE streaming and UI updates without AWS/LLM.
    """
    import uuid
    from api.sse import register_stream

    run_id = str(uuid.uuid4())
    now    = datetime.now(timezone.utc).isoformat()

    await db.execute(
        """INSERT INTO runs
           (id, engagement_id, pipeline, status, input_file, input_format,
            tenant_id, credential_source, aws_profile, aws_region,
            skip_review, skip_llm, config_path, output_dir, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (run_id, "debug", "prowler", "pending", "/tmp/mock.csv", "auto",
         "", "profile", "default", "ap-southeast-2",
         0, 0, "/tmp/config.toml", "/tmp/mock-output", now),
    )
    await db.commit()

    stream = register_stream(run_id)

    async def _mock_pipeline():
        from db.database import _DB_PATH
        async with aiosqlite.connect(_DB_PATH) as mdb:
            await asyncio.sleep(2)
            await stream.send_log("[ Stage 1 ] Ingesting mock findings...")
            await mdb.execute("UPDATE runs SET status='running', started_at=? WHERE id=?",
                              (datetime.now(timezone.utc).isoformat(), run_id))
            await mdb.commit()
            await stream.send_status("running")

            for i in range(3):
                await asyncio.sleep(3)
                await stream.send_log(f"  Processing batch {i+1}/3...")

            await asyncio.sleep(2)
            await stream.send_log("[ Stage 2.5 ] Semantic grouping...")
            await asyncio.sleep(4)
            await stream.send_log("  → 8 group(s) proposed")
            await stream.send_log("🌐 Grouping review: http://localhost:8742/review")
            await mdb.execute("UPDATE runs SET status='awaiting_review' WHERE id=?", (run_id,))
            await mdb.commit()
            await stream.send_status("awaiting_review")
            await stream.send_json({
                "type": "review_ready",
                "port": 8742,
                "url":  "http://localhost:8742/review",
                "pipeline": "prowler",
            })

            # Simulate analyst approving after 8s
            await asyncio.sleep(8)
            await stream.send_log("✓ Grouping approved — pipeline resuming")
            await mdb.execute("UPDATE runs SET status='enriching' WHERE id=?", (run_id,))
            await mdb.commit()
            await stream.send_status("enriching")
            await stream.send_json({"type": "review_approved", "message": "Grouping approved"})

            await asyncio.sleep(2)
            await stream.send_log("[ Stage 3 ] LLM enrichment — 8 groups...")
            for i in range(4):
                await asyncio.sleep(3)
                await stream.send_log(f"  Enriched group {i*2+1}-{i*2+2}/8")

            await asyncio.sleep(2)
            await stream.send_log("[ Stage 5 ] Excel rendered → MockReport.xlsx")
            await stream.send_log("=" * 60)
            await stream.send_log("PIPELINE COMPLETE")
            await mdb.execute(
                "UPDATE runs SET status='complete', completed_at=?, risk_high=3, risk_medium=4, risk_low=1 WHERE id=?",
                (datetime.now(timezone.utc).isoformat(), run_id),
            )
            await mdb.commit()
            await stream.send_status("complete")
            await stream.send_json({
                "type": "output_ready",
                "excel_path": "/tmp/MockReport.xlsx",
                "filename": "MockReport.xlsx",
            })
            await stream.close()

    asyncio.create_task(_mock_pipeline())
    return {"run_id": run_id, "message": "Mock run started — connect to /api/runs/{run_id}/stream"}


@router.delete("/runs/{run_id}")
async def delete_run(
    run_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    """
    Delete a pending run record and its logs.
    Only pending runs can be deleted — active/complete runs are preserved.
    """
    cursor = await db.execute("SELECT status FROM runs WHERE id = ?", (run_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Run not found")
    if row[0] != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Only pending runs can be deleted (status: {row[0]})",
        )
    await db.execute("DELETE FROM run_logs WHERE run_id = ?", (run_id,))
    await db.execute("DELETE FROM runs WHERE id = ?", (run_id,))
    await db.commit()
    return {"deleted": True, "run_id": run_id}


# ── Scans ─────────────────────────────────────────────────────────────
# In-memory store of raw scan secrets keyed by scan_id.
# Never written to DB. Cleared when scan starts.
_pending_scan_secrets: dict[str, dict] = {}


@router.get("/engagements/{engagement_id}/scans")
async def list_scans(
    engagement_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    """List all scans for an engagement, newest first."""
    cursor = await db.execute(
        "SELECT * FROM scans WHERE engagement_id=? ORDER BY created_at DESC",
        (engagement_id,),
    )
    rows = await cursor.fetchall()
    return [_scan_row(dict(r)) for r in rows]


@router.post("/engagements/{engagement_id}/scans", status_code=201)
async def create_scan(
    engagement_id: str,
    body: ScanCreate,
    db: aiosqlite.Connection = Depends(get_db),
):
    """
    Create a scan record. Does NOT start the scan yet.
    Raw secrets are registered via POST /scans/{id}/secrets before start.
    """
    from api.scanner import AWS_SERVICES, AZURE_SERVICES
    import json as _json

    cursor = await db.execute(
        "SELECT id FROM engagements WHERE id=?", (engagement_id,)
    )
    if not await cursor.fetchone():
        raise HTTPException(status_code=404, detail="Engagement not found")

    scan_id = str(uuid.uuid4())
    now     = _now()

    # Determine output directory.
    # Use a short root path to avoid Windows 259-char path limit,
    # especially when the project is inside OneDrive.
    import platform as _platform
    if _platform.system().lower() == "windows":
        # Use C:\ScubaScans or C:\ProwlerScans to keep paths short
        provider_val = body.provider.value
        short_root = Path("C:/ScubaScans") if provider_val == "scubagear" else Path("C:/ProwlerScans")
        output_dir = short_root / scan_id[:8]  # use first 8 chars of UUID
    else:
        repo_root  = Path(__file__).parent.parent.parent
        output_dir = repo_root / "data" / "scans" / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)

    # Determine scan_type
    scan_type = getattr(body, "scan_type", None)
    if not scan_type:
        if body.provider.value == "scubagear":
            scan_type = "scubagear"
        elif body.provider.value == "azure":
            scan_type = "prowler_azure"
        else:
            scan_type = "prowler_aws"

    await db.execute(
        """INSERT INTO scans (
            id, engagement_id, provider, scan_type, status,
            credential_source, aws_profile, scan_region, scan_account_id,
            azure_tenant_id, azure_client_id, azure_subscription_id,
            resource_scope, services_scope,
            output_dir, output_file, created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            scan_id, engagement_id, body.provider.value, scan_type, "pending",
            body.credential_source.value, body.aws_profile,
            body.scan_region, body.scan_account_id,
            body.azure_tenant_id, body.azure_client_id, body.azure_subscription_id,
            _json.dumps(body.resource_scope),
            _json.dumps(body.services_scope),
            str(output_dir), "", now,
        ),
    )
    await db.commit()

    return {"id": scan_id, "engagement_id": engagement_id,
            "provider": body.provider.value, "status": "pending",
            "output_dir": str(output_dir), "created_at": now}


@router.post("/scans/{scan_id}/secrets")
async def register_scan_secrets(
    scan_id: str,
    body: dict,
    db: aiosqlite.Connection = Depends(get_db),
):
    """
    Register raw scan credentials in memory only.
    Must be called before POST /scans/{scan_id}/start.
    Secrets are cleared from memory as soon as the scan starts.
    """
    cursor = await db.execute("SELECT id FROM scans WHERE id=?", (scan_id,))
    if not await cursor.fetchone():
        raise HTTPException(status_code=404, detail="Scan not found")

    allowed = {
        "aws_access_key_id", "aws_secret_access_key", "aws_session_token",
        "azure_client_secret",
    }
    _pending_scan_secrets[scan_id] = {
        k: v for k, v in body.items() if k in allowed and v
    }
    return {"registered": True}


@router.post("/scans/{scan_id}/start")
async def start_scan(
    scan_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Start a pending scan. Returns task_id for SSE stream."""
    from api import scanner
    from api.sse import register_stream

    cursor = await db.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    row    = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = dict(row)
    if scan["status"] not in ("pending", "failed"):
        raise HTTPException(
            status_code=400,
            detail=f"Scan status is '{scan['status']}' — only pending or failed scans can be started",
        )

    stream  = register_stream(f"scan-{scan_id}")
    secrets = _pending_scan_secrets.pop(scan_id, {})
    output_dir = Path(scan["output_dir"])

    asyncio.create_task(
        scanner.execute_scan(scan, stream, output_dir, secrets)
    )

    return {"task_id": f"scan-{scan_id}", "status": "starting"}


@router.get("/scans/{scan_id}/stream")
async def stream_scan(scan_id: str):
    """SSE endpoint — live Prowler stdout."""
    from api.sse import get_stream
    stream = get_stream(f"scan-{scan_id}")
    if not stream:
        raise HTTPException(status_code=404, detail="No active stream for this scan")
    return stream.response()


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Kill the running Prowler process."""
    from api import scanner

    cursor = await db.execute("SELECT status FROM scans WHERE id=?", (scan_id,))
    row    = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row[0] != "running":
        raise HTTPException(status_code=400, detail=f"Scan is '{row[0]}' — only running scans can be cancelled")

    await scanner.cancel_scan(scan_id)
    now = _now()
    await db.execute(
        "UPDATE scans SET status='cancelled', completed_at=? WHERE id=?",
        (now, scan_id),
    )
    await db.commit()
    return {"cancelled": True}


@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    cursor = await db.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    row    = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_row(dict(row))


@router.get("/scans/{scan_id}/logs")
async def get_scan_logs(
    scan_id: str,
    offset: int = 0,
    db: aiosqlite.Connection = Depends(get_db),
):
    cursor = await db.execute(
        "SELECT ts, stream, line FROM scan_logs WHERE scan_id=? ORDER BY id LIMIT 5000 OFFSET ?",
        (scan_id, offset),
    )
    rows = await cursor.fetchall()
    return [{"ts": r[0], "stream": r[1], "line": r[2]} for r in rows]


@router.get("/meta/services")
async def list_services():
    """Return available Prowler service names for the scope selector."""
    from api.scanner import AWS_SERVICES, AZURE_SERVICES, SCUBA_PRODUCTS, SCUBA_PRODUCT_LABELS
    return {
        "aws":       AWS_SERVICES,
        "azure":     AZURE_SERVICES,
        "scubagear": SCUBA_PRODUCTS,
        "scubagear_labels": SCUBA_PRODUCT_LABELS,
    }


# ── Scan row helper ───────────────────────────────────────────────────

def _scan_row(row: dict) -> dict:
    import json as _j
    row["resource_scope"] = _j.loads(row.get("resource_scope") or "[]")
    row["services_scope"] = _j.loads(row.get("services_scope") or "[]")
    return row


@router.get("/defaults")
async def get_defaults():
    """
    Return server-side defaults for the Settings page.
    These come from environment variables set in start.ps1 / start.sh.
    Only called once on first launch to pre-populate Settings.
    Never returns raw secret values — only safe display values.
    """
    import os
    return {
        "deployment_name": os.environ.get("BEDROCK_DEPLOYMENT_NAME", ""),
        "aws_region":      os.environ.get("AWS_DEFAULT_REGION", "ap-southeast-2"),
        # Return profile name if set, otherwise hint that env keys are configured
        "aws_profile":     os.environ.get("AWS_PROFILE", ""),
        "has_env_keys":    bool(os.environ.get("AWS_ACCESS_KEY_ID")),
    }