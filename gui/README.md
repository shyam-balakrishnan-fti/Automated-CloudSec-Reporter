# Automated Cloud Security Reporter

A pipeline that takes raw cloud security scanner output and produces client-ready Excel security assessment reports. It normalises scanner data, uses an LLM (Claude via AWS Bedrock) to semantically group related findings and write professional narratives, and renders everything into a formatted Excel report - all from a single GUI.

---

## Table of Contents

- [Overview](#overview)
- [Pipelines](#pipelines)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [GUI Walkthrough](#gui-walkthrough)
- [CLI Usage](#cli-usage)
- [Configuration](#configuration)
- [Repository Structure](#repository-structure)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)

---

## Overview

The tool automates three things that normally take hours of manual work:

1. **Normalisation** - Parses raw scanner output (CSV, XLSX, JSON, OCSF) into a clean internal model
2. **AI grouping** - Semantically groups related findings using Claude via AWS Bedrock, with analyst review
3. **Report generation** - Writes professional risk narratives and produces a formatted Excel report

The analyst reviews and approves the AI-proposed grouping before enrichment runs. Every field change is recorded in an append-only audit trail.

---

## Pipelines

### Prowler (AWS / Azure infrastructure)

Scans AWS and Azure infrastructure against security best practices.

| Item | Detail |
|------|--------|
| Input formats | CSV, XLSX, JSON, OCSF |
| Output | `AWS` or `Azure` sheet in `Output_Template.xlsx` |
| Review UI port | `8742` |
| Supported Python | 3.9 – 3.12 |

### ScubaGear (Microsoft 365 / Entra ID)

Scans Microsoft 365 and Entra ID against CISA SCuBA baseline controls.

| Item | Detail |
|------|--------|
| Input formats | `ActionPlan.csv` or `ScubaResults.csv` |
| Output | `Azure` sheet in `Output_Template.xlsx` |
| Review UI port | `8743` |
| Platform | **Windows only** (PowerShell module) |

---

## Prerequisites

### All platforms

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.11+ (GUI), 3.9–3.12 (Prowler) | Prowler does not support Python 3.13+ |
| AWS account | - | Bedrock access required for LLM enrichment |
| AWS Bedrock | - | Private inference profile or model ARN |
| Git | Any | For cloning and updates |

### Windows only (ScubaGear)

| Requirement | Notes |
|-------------|-------|
| PowerShell 5.1+ | Pre-installed on Windows 10/11 |
| PowerShell execution policy | `RemoteSigned` or `Unrestricted` at `CurrentUser` scope |

### AWS setup

Before running enrichment, ensure zero data retention is configured on Bedrock:

```bash
# Verify
aws bedrock get-account-data-retention --region ap-southeast-2

# Enable zero data retention
aws bedrock put-account-data-retention --mode none --region ap-southeast-2
```

---

## Quick Start

### Option A - GUI (recommended)

**Linux / macOS:**
```bash
bash gui/start.sh
```

**Windows** (right-click → Run with PowerShell, or):
```powershell
powershell -ExecutionPolicy Bypass -File gui\start.ps1
```

The startup script will:
1. Check your Python version
2. Install `uv` if missing
3. Install Prowler (using Python 3.12)
4. Install ScubaGear (Windows only)
5. Install all pipeline and GUI dependencies
6. Open the GUI at `http://localhost:8000`

On subsequent launches, already-installed tools are skipped automatically.

### Option B - CLI

**Prowler:**
```bash
cd cloud-tool
source .venv/bin/activate
python src/run_pipeline.py \
  --input path/to/prowler-output.csv \
  --config config/config.toml \
  --format auto
```

**ScubaGear:**
```bash
python scubagear/src/run_scubagear.py \
  --action-plan path/to/ActionPlan.csv \
  --config scubagear/config/scubagear_config.toml \
  --tenant-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

---

## GUI Walkthrough

### 1. First-time setup

Open **Tools & Setup** from the sidebar. The page shows the installation status of Prowler, ScubaGear (Windows only), and uv. Click **Install** on any missing tool to install it with live progress streaming.

Go to **Settings** and fill in:
- **Bedrock Deployment Name** - your private inference profile ARN (required for LLM enrichment)
- **AWS Region** - default `ap-southeast-2`
- **AWS Profile** - your named AWS CLI profile

Click **Save Settings**. These values are stored locally in your browser and applied to every new run automatically.

### 2. Create an engagement

An engagement represents one client assessment. Go to **Engagements → New Engagement** and fill in:
- Client name
- Assessment period (e.g. `July 2026`)
- Analyst name
- Pipeline type (Prowler / ScubaGear / Both)

### 3. Start a run

Open an engagement and click **+ New Run**. Configure:
- Pipeline (Prowler or ScubaGear)
- Input file path (absolute path to scanner output)
- Input format (auto-detected by default)
- AWS credentials (profile picker or temporary keys)
- Tenant ID (ScubaGear only)

Click **Check Preflight →** to validate the configuration. If all checks pass, click **Start Run →**.

### 4. Monitor progress

The run detail view shows a **progress timeline** with five stages:

```
Queued → Processing → Awaiting Review → Enriching → Complete
```

Each stage card is collapsible to show the raw pipeline output for that stage.

### 5. Grouping review

When the pipeline reaches the grouping stage, the **review UI** loads in an embedded iframe. The analyst can:
- Drag finding chips between group cards to reorganise
- Rename groups
- Apply AI instructions to individual groups or the entire board
- Override risk ratings (High / Medium / Low)
- Approve the final grouping

After approval, the pipeline automatically resumes into the enrichment stage.

### 6. Download the report

When the run completes, a **Report Ready** banner appears with a download button. The **Output Files** panel lists all generated files (JSON checkpoints, config, Excel report).

### 7. Run comparison

Engagements with two or more completed runs show a **Run Comparison** table comparing risk distribution (High / Medium / Low counts), findings included, and run duration side by side.

---

## CLI Usage

### Prowler pipeline flags

```
--input   -i    Path to Prowler output file (required)
--output-dir    Output directory (default: data/output)
--config  -c    Path to config.toml
--format  -f    Input format: auto | csv | xlsx | json
--skip-llm      Skip AI grouping and enrichment (Stage 1+2 only)
--skip-review   Auto-approve AI grouping without analyst review
--force-review  Re-run review even if grouping_approved.json exists
--no-browser    Do not auto-open browser (used by GUI)
```

### ScubaGear pipeline flags

```
--action-plan   Path to ActionPlan.csv or ScubaResults.csv (required)
--config        Path to scubagear_config.toml
--tenant-id     Azure tenant UUID
--output-dir    Output directory
--skip-grouping Skip semantic grouping stage
--skip-review   Auto-approve AI grouping
--no-browser    Do not auto-open browser (used by GUI)
--port          Review UI port (default: 8743)
```

---

## Configuration

### `config/config.toml` (Prowler)

Edit `[engagement]` before every run:

```toml
[engagement]
client_name       = "Acme Corp"
assessment_period = "July 2026"
analyst           = "Your Name"
output_filename   = "SecurityReport.xlsx"
```

Set `[llm]` once at setup:

```toml
[llm]
provider        = "bedrock_runtime"
deployment_name = "arn:aws:bedrock:ap-southeast-2:123456789:your-profile"
aws_region      = "ap-southeast-2"
max_tokens      = 1500
timeout_seconds = 60
```

The `[risk_matrix]`, `[severity_rules]`, and `[output.colours]` sections rarely need changing.

### `scubagear/config/scubagear_config.toml` (ScubaGear)

Same structure as above, with additional sections:

```toml
[engagement]
tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

[service_map]
"MS.AAD"      = { section = "Microsoft Entra ID", ref_prefix = "ENT" }
"MS.DEFENDER" = { section = "Microsoft 365 Defender", ref_prefix = "DEF" }
# ... etc
```

> When using the GUI, config files are generated automatically from your Settings and engagement details. Manual editing is only needed for CLI usage.

---

## Repository Structure

```
cloud-tool/
├── config/
│   └── config.toml                   Prowler pipeline configuration
│
├── data/
│   ├── output/                       Prowler pipeline outputs (per run)
│   └── sample-scuba-output/          Sample ScubaGear report
│
├── src/                              Prowler pipeline source
│   ├── models.py                     CanonicalFinding Pydantic model
│   ├── stage1_ingest.py              Ingestion (CSV/XLSX/JSON/OCSF)
│   ├── stage2_process.py             Filter, dedup, group, likelihood
│   ├── stage2_5_grouping.py          Semantic grouping (LLM + consolidation)
│   ├── stage_reviewer.py             Grouping review UI (port 8742)
│   ├── stage3_llm.py                 LLM enrichment
│   ├── stage5_render_excel.py        Excel renderer
│   └── run_pipeline.py               Prowler orchestrator + CLI
│
├── scubagear/
│   ├── config/
│   │   └── scubagear_config.toml     ScubaGear pipeline configuration
│   └── src/
│       ├── sg_models.py              ScubaFinding Pydantic model
│       ├── sg_ingest.py              CSV ingestion
│       ├── sg_process.py             Filter, dedup, OutputGroups
│       ├── sg_grouping.py            Semantic grouping (M365-specific)
│       ├── sg_reviewer.py            Grouping review UI (port 8743)
│       ├── sg_enrich.py              LLM enrichment (M365-specific)
│       ├── sg_render_excel.py        Excel renderer
│       └── run_scubagear.py          ScubaGear orchestrator + CLI
│
├── templates/
│   └── Output_Template.xlsx          Excel template (AWS + Azure sheets)
│
├── gui/                              Web GUI (FastAPI)
│   ├── main.py                       FastAPI application entry point
│   ├── pyproject.toml                GUI Python dependencies (uv-managed)
│   ├── start.sh                      Linux/macOS startup script
│   ├── start.ps1                     Windows startup script
│   ├── api/
│   │   ├── config_writer.py          Generates config.toml per run
│   │   ├── installer.py              Tool installation (Prowler, ScubaGear)
│   │   ├── models.py                 Pydantic request/response models
│   │   ├── platform.py               OS detection, preflight checks
│   │   ├── routes.py                 All API route handlers
│   │   ├── runner.py                 Pipeline subprocess execution + SSE
│   │   └── sse.py                    Server-Sent Events infrastructure
│   ├── db/
│   │   ├── database.py               SQLite connection management
│   │   └── schema.sql                Engagements, runs, run logs tables
│   ├── static/
│   │   └── logo.jpeg                 Company logo
│   └── templates/
│       └── index.html                Single-page application shell
│
└── tests/                            Prowler pipeline tests (328 tests)
```

---

## Architecture

### Pipeline stages

```
Input file
    │
    ▼
Stage 1 - Ingest
    Parse scanner output into canonical finding objects
    Compute SHA-256 fingerprint, detect schema version
    │
    ▼
Stage 2 - Process
    Filter by status/criticality
    Deduplicate (stable cross-scan keys)
    Group by check_id into OutputGroups
    Assign likelihood ratings
    │
    ▼
Stage 2.5 - Semantic Grouping (LLM)
    Chunk groups, send to Claude via Bedrock
    Propose semantic merges across check types
    Run consolidation pass to eliminate cross-chunk duplicates
    │
    ▼
Review UI - Analyst Approval
    Drag-and-drop grouping editor
    AI instruction boxes (per-group and board-wide)
    Risk rating overrides
    │
    ▼
Stage 3 - LLM Enrichment
    Generate: title, root cause, situation, consequence, recommendations
    Apply risk matrix (likelihood × consequence)
    Write [REQUIRES_HUMAN_INPUT] placeholders on failure
    │
    ▼
Stage 5 - Excel Render
    Copy Output_Template.xlsx
    Write enriched groups into AWS / Azure sheet
    Colour-code risk ratings
    │
    ▼
Output_Template.xlsx (populated)
```

### GUI architecture

```
Browser (SPA)
    │  HTTP / SSE
    ▼
FastAPI (gui/main.py - port 8000)
    ├── /api/engagements     Engagement CRUD
    ├── /api/runs            Run management
    ├── /api/runs/{id}/stream   SSE live output
    ├── /api/tools           Tool installation
    └── /api/platform        OS detection, preflight
    │
    ├── SQLite (gui/db/reporter.db)
    │   ├── engagements
    │   ├── runs
    │   └── run_logs
    │
    └── Subprocess
        ├── src/run_pipeline.py      (Prowler)
        └── scubagear/src/run_scubagear.py  (ScubaGear)
            │
            └── Review UI servers (ports 8742 / 8743)
                Embedded as iframe in the GUI
```

### LLM calls

All LLM calls go through AWS Bedrock Converse API:

- **Grouping calls** - JSON array response: `[{group_name, check_ids, rationale}]`
- **Enrichment calls** - JSON object: `{finding_title, root_cause_narrative, situation_narrative, consequence_narrative, consequence_rating, access_required, recommendations}`
- **Retry** - one automatic retry with a correction prompt on validation failure
- **Cache** - set `PIPELINE_LLM_CACHE_DIR` env var to cache responses by prompt hash

---

## Troubleshooting

### Prowler fails on Windows with pandas build error

Prowler requires Python 3.12 or below. pandas 2.x does not have wheels for Python 3.13+.

```powershell
uv tool install prowler --python 3.12
```

The `start.ps1` script does this automatically.

### UnicodeEncodeError on Windows (✓ characters)

The pipeline prints Unicode characters that Windows CP1252 cannot encode. Fixed by the GUI automatically (`PYTHONIOENCODING=utf-8`). For CLI usage:

```powershell
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"
python src/run_pipeline.py ...
```

### OneDrive hardlink error (os error 396)

uv uses hardlinks which OneDrive blocks. Fixed in `start.ps1` via `UV_LINK_MODE=copy`. For manual installs:

```powershell
$env:UV_LINK_MODE = "copy"
$env:UV_CACHE_DIR = "C:\uv-cache"
uv tool install prowler --python 3.12 --link-mode copy
```

### ScubaGear execution policy error

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Pipeline stuck in Queued status

The server was likely started with `--reload` which restarts on file changes and destroys active run state. Always use:

```powershell
uv run python main.py
```

Never use `uvicorn main:app --reload` while runs are active.

### deployment_name is required error

Set your Bedrock deployment name in **Settings** in the GUI, or add it directly to the generated config.toml:

```toml
[llm]
deployment_name = "arn:aws:bedrock:REGION:ACCOUNT_ID:your-profile"
```

### Found existing grouping_approved.json - applying (0 groups)

A stale approval file from a previous run is being picked up. Delete the output directory for the affected engagement and re-run, or use the GUI which isolates each run in its own directory.

---

## Security Notes

- **API keys are never stored in config files** - use environment variables or AWS CLI profiles
- **AWS Bedrock zero data retention** - configure at the account level before use (see Prerequisites)
- **GUI settings** - stored in browser `localStorage` only, never sent to the server except as part of run configuration
- **Raw AWS keys** - if provided in the GUI, they are held in memory only for the duration of the run and never written to the database
- **Deployment name / inference profile ARN** - stored in browser `localStorage`, written to the generated config.toml for the duration of the run only
- The GUI runs on `127.0.0.1` (localhost only) by default - it is not exposed to the network

---

## Dependencies

### Pipeline (root `.venv`)

```
boto3       AWS SDK - Bedrock calls
pydantic    Data models and validation
openpyxl    Excel read/write
tomllib     Config parsing (stdlib in Python 3.11+)
```

### GUI (`gui/.venv`)

```
fastapi         Web framework
uvicorn         ASGI server
aiosqlite       Async SQLite
jinja2          HTML templating
python-multipart Form parsing
pydantic        Request/response validation
```

Python 3.11+ required for both. No other external dependencies.