# FTI - Automated Cloud Security Reporter

A production-grade pipeline that converts cloud security scanner output into client-ready security assessment reports. Supports two independent pipelines:

- **Prowler** — AWS and Azure infrastructure scanning (CSV, XLSX, JSON / OCSF)
- **ScubaGear** — Microsoft 365 and Entra ID CISA SCuBA baseline compliance scanning (CSV)

Both pipelines follow the same flow: ingest → process → semantic grouping → analyst review UI → LLM enrichment → Excel report. They share no code and have no runtime dependencies on each other.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
  - [Prowler Pipeline](#prowler-pipeline)
  - [ScubaGear Pipeline](#scubagear-pipeline)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Prowler Configuration](#prowler-configuration)
  - [ScubaGear Configuration](#scubagear-configuration)
- [Running the Pipeline](#running-the-pipeline)
  - [Prowler](#prowler)
  - [ScubaGear](#scubagear)
- [Review UI](#review-ui)
- [Output Files](#output-files)
  - [Prowler Outputs](#prowler-outputs)
  - [ScubaGear Outputs](#scubagear-outputs)
- [Supported Input Formats](#supported-input-formats)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Bedrock Setup](#bedrock-setup)
- [Sample Outputs](#sample-outputs)

---

## Overview

### What both pipelines do

1. **Ingest** scanner output — normalise to an internal model with a full field-level audit trail
2. **Process** findings: filter by status/criticality, deduplicate, assign likelihood ratings, route to output sections
3. **Group semantically** using LLM — sort by service/category, chunk into batches of ~15, run an automatic cross-chunk consolidation pass to catch missed merges
4. **Open a browser-based review UI** where analysts can drag findings between groups, rename groups, use per-group or board-wide AI instructions to refine grouping, and override Risk Ratings per group
5. **Enrich** only the final approved groups — situation, consequence, root cause narratives, consequence rating — using Claude via AWS Bedrock
6. **Render** a client-facing Excel report with colour-coded risk ratings, per-section organisation, and sequential reference numbers

### What neither pipeline does

- Store any customer data persistently — all processing is in-memory per run
- Call any external service other than AWS Bedrock (no third-party APIs, no telemetry)
- Enrich individual findings before grouping — enrichment runs only on the final approved groups (~16 LLM calls), not all individual findings (~100+ calls)

---

## Architecture

### Prowler Pipeline

```
Prowler Output (CSV / XLSX / JSON / OCSF)
           │
           ▼
┌─────────────────────┐
│  Stage 1: Ingest    │  Parses, normalises schema (v3→v4→CanonicalFinding),
│  stage1_ingest.py   │  fixes line endings, auto-detects delimiters,
└─────────┬───────────┘  SHA-256 fingerprint, full audit trail
          │
          ▼
┌─────────────────────┐
│  Stage 2: Process   │  Filters by status, deduplicates (type-stratified,
│  stage2_process.py  │  never cross-account), groups by check_id,
└─────────┬───────────┘  assigns likelihood ratings, routes to output section
          │
          ▼
┌──────────────────────────┐
│  Stage 2.5: Grouping     │  Sorts by category+service → sequential chunks
│  stage2_5_grouping.py    │  of ~15 with running group-name list → automatic
└──────────┬───────────────┘  consolidation pass (conservative merge criteria)
           │
           ▼
┌──────────────────────────┐
│  Review UI               │  Localhost HTTP server at :8742. Analyst reviews
│  stage_reviewer.py       │  groups, drags chips, uses AI instruction boxes,
└──────────┬───────────────┘  overrides risk ratings. Approve → pipeline continues.
           │
           ▼
┌─────────────────────┐
│  Stage 3: Enrich    │  LLM enrichment on FINAL approved groups only.
│  stage3_llm.py      │  Writes narratives + consequence rating + risk rating.
└─────────┬───────────┘  One Bedrock call per group, not per finding.
          │
          ▼
┌──────────────────────────┐
│  Stage 5: Excel Render   │  Populates Output_Template.xlsx. Routes AWS
│  stage5_render_excel.py  │  findings to AWS sheet, Azure to Azure sheet.
└──────────────────────────┘  Resources embedded in Situation column.
```

### ScubaGear Pipeline

```
ScubaGear Output (ActionPlan.csv or ScubaResults.csv)
           │
           ▼
┌─────────────────────┐
│  Stage 1: Ingest    │  Column-presence-checked CSV parsing → ScubaFinding
│  sg_ingest.py       │  objects. Strips HTML from Requirement field, extracts
└─────────┬───────────┘  instance counts from Details text, resolves M365 service
          │               from Control ID prefix (MS.AAD.*, MS.DEFENDER.*, etc.)
          ▼
┌─────────────────────┐
│  Stage 2: Process   │  Filters by status and criticality (Shall / Should / May
│  sg_process.py      │  and compound variants), deduplicates by stable key,
└─────────┬───────────┘  assigns per-section ref numbers (ENT1, DEF1, SPT1, ...)
          │
          ▼
┌──────────────────────────┐
│  Stage 2.5: Grouping     │  Sorts by M365 service section → sequential chunks
│  sg_grouping.py          │  of ~15 → automatic consolidation pass.
└──────────┬───────────────┘  M365-specific merge criteria: same service AND same
           │                  root cause only. No cross-service merges.
           ▼
┌──────────────────────────┐
│  Review UI               │  Localhost HTTP server at :8743. Groups displayed
│  sg_reviewer.py          │  under collapsible M365 service section headers
└──────────┬───────────────┘  (Entra ID, Defender, Exchange Online, SharePoint
           │                  Online, Teams, Power Platform). Analyst drags chips,
           │                  uses AI instruction boxes, overrides risk ratings.
           ▼
┌─────────────────────┐
│  Stage 3: Enrich    │  LLM enrichment with M365-specific prompts. References
│  sg_enrich.py       │  CISA SCuBA baseline context, admin portal steps, and
└─────────┬───────────┘  PowerShell cmdlets in remediation guidance. Respects
          │               analyst risk rating overrides from the review UI.
          ▼
┌──────────────────────────┐
│  Stage 5: Excel Render   │  Populates the Azure sheet in Output_Template.xlsx.
│  sg_render_excel.py      │  Reassigns ref numbers after grouping to ensure
└──────────────────────────┘  sequential order (ENT1, ENT2... DEF1, DEF2...).
                              Section headings written in template order.
```

### Key design decisions (shared by both pipelines)

**Grouping before enrichment.** The LLM proposes groups first, the analyst approves, then enrichment runs on the final ~16 groups — not the original ~100 individual checks. This keeps LLM costs proportional to report line items and ensures narratives are written with full merged context.

**Conservative merge criteria.** Prowler: only merges checks that share the same AWS service AND the same remediation path. ScubaGear: only merges controls that share the same M365 service AND the same root cause. Different services are never auto-merged — the analyst uses the review UI to merge manually if desired.

**Analyst always has final say.** The AI proposes, the analyst approves. The review UI supports drag-and-drop rearrangement, per-group AI instructions, board-wide AI instructions, inline group renaming, and per-group Risk Rating overrides. Nothing goes to the Excel renderer until the analyst clicks Approve.

**Token and timeout scaling.** LLM calls scale `max_tokens` and `timeout_seconds` dynamically based on item count and call mode. A flat config value is not used for any call — this prevents truncation errors on large scans.

**LLM response caching.** Set `PIPELINE_LLM_CACHE_DIR=.llm_cache` to cache every prompt→response pair by SHA-256 key. Subsequent runs with identical inputs reuse cached responses at zero Bedrock cost — essential for iterative development.

---

## Prerequisites

- Python 3.11+ (3.12 recommended — `tomllib` is stdlib from 3.11)
- AWS credentials configured (`~/.aws/credentials` or environment variables)
- Zero data retention configured on your Bedrock account (see [Bedrock Setup](#bedrock-setup))

```bash
pip install boto3 openpyxl pydantic
```

---

## Installation

```bash
git clone https://github.com/shyam-balakrishnan-fti/Automated-CloudSec-Reporter
cd Automated-CloudSec-Reporter
pip install -r requirements.txt
```

---

## Configuration

### Prowler Configuration

All Prowler configuration lives in `config/config.toml`. Update the `[engagement]` section before every run.

```toml
# ── Engagement (change every run) ──────────────────────────────────
[engagement]
client_name       = "Acme Corp"          # used as output subfolder name
assessment_period = "June 2026"
analyst           = "analyst"
output_filename   = "SecurityReport_Jun2026.xlsx"

# ── LLM ────────────────────────────────────────────────────────────
[llm]
provider         = "bedrock_runtime"
deployment_name  = "au.anthropic.claude-opus-4-8"   # cross-region inference profile
aws_region       = "ap-southeast-2"
max_tokens       = 1500    # base — calls scale above this automatically
timeout_seconds  = 60      # base — calls scale above this automatically

# ── Processing ─────────────────────────────────────────────────────
[processing]
include_statuses = ["FAIL", "MUTED(FAIL)"]

# ── Severity rules ──────────────────────────────────────────────────
[severity_rules]
critical = "High"
high     = "High"
medium   = "Medium"
low      = "Low"

likelihood_high_if_categories = ["internet-exposed"]

# ── Risk matrix ─────────────────────────────────────────────────────
[risk_matrix]
High_Major      = "High"
High_Moderate   = "High"
High_Minor      = "High"
Medium_Major    = "High"
Medium_Moderate = "Medium"
Medium_Minor    = "Medium"
Low_Major       = "Medium"
Low_Moderate    = "Medium"
Low_Minor       = "Low"

# ── Output ──────────────────────────────────────────────────────────
[output]
template_path    = "templates/Output_Template.xlsx"
ref_prefix       = "AWS"
ref_prefix_azure = "AZ"
```

### ScubaGear Configuration

ScubaGear configuration lives in `scubagear/config/scubagear_config.toml`. Update the `[engagement]` section before every run.

```toml
# ── Engagement (change every run) ──────────────────────────────────
[engagement]
client_name       = "Acme Corp"          # used as output subfolder name
assessment_period = "June 2026"
analyst           = "analyst"
tenant_id         = ""                   # fallback if --tenant-id not supplied
output_filename   = "M365_SecurityReport.xlsx"

# ── LLM ────────────────────────────────────────────────────────────
[llm]
provider         = "bedrock_runtime"
deployment_name  = "anthropic.claude-opus-4-8"
aws_region       = "ap-southeast-2"
max_tokens       = 1500
timeout_seconds  = 60

# ── Processing ─────────────────────────────────────────────────────
[processing]
# Criticality levels to include. ActionPlan.csv is pre-filtered to Shall/FAIL.
# Add "Should" here to include SHOULD-level controls when using ScubaResults.csv.
include_criticality = ["Shall", "Shall/3rd Party", "Shall/Not Implemented"]
input_file          = "ActionPlan"    # "ActionPlan" or "ScubaResults"

# ── Severity mapping ────────────────────────────────────────────────
# Shall variants all map to "high" regardless of qualifier.
# The raw criticality value is preserved in criticality_raw for LLM context.
[severity_map]
"Shall"                 = "high"
"Should"                = "medium"
"May"                   = "low"
"Shall/3rd Party"       = "high"
"Shall/Not Implemented" = "high"

# ── Risk matrix ─────────────────────────────────────────────────────
[risk_matrix]
High_Major      = "High"
High_Moderate   = "High"
High_Minor      = "High"
Medium_Major    = "High"
Medium_Moderate = "Medium"
Medium_Minor    = "Medium"
Low_Major       = "Medium"
Low_Moderate    = "Medium"
Low_Minor       = "Low"

# ── Output ──────────────────────────────────────────────────────────
[output]
template_path = "templates/Output_Template.xlsx"
target_sheet  = "Azure"
```

---

## Running the Pipeline

### Prowler

```bash
python3 src/run_pipeline.py \
  --input /path/to/prowler-output.json \
  --format json \
  --output-dir data/output
```

The pipeline will:
1. Run Stages 1 and 2 (deterministic — no LLM calls)
2. Run Stage 2.5 grouping (LLM — prints chunk progress to terminal)
3. Open the browser-based review UI at `http://localhost:8742/review`
4. Wait for analyst approval
5. Run Stage 3 enrichment on the approved groups
6. Render the Excel report to `data/output/{client_name}/`

#### Prowler CLI flags

| Flag | Description |
|------|-------------|
| `--input`, `-i` | Path to Prowler CSV, XLSX, or JSON file (required) |
| `--output-dir`, `-o` | Base output directory (default: `data/output`) |
| `--config`, `-c` | Path to config.toml (default: `config/config.toml`) |
| `--format`, `-f` | Force input format: `auto`, `csv`, `xlsx`, `json` (default: `auto`) |
| `--skip-llm` | Skip Stages 2.5 and 3 — produces Stage 1+2 outputs only |
| `--skip-review` | Skip the review UI — use AI grouping proposal directly |
| `--force-review` | Force the review UI even if `grouping_approved.json` already exists |
| `--no-browser` | Start the review server but do not auto-open the browser |

### ScubaGear

```bash
python3 scubagear/src/run_scubagear.py \
  --action-plan /path/to/ActionPlan.csv \
  --tenant-id   <azure-tenant-uuid>
```

The pipeline will:
1. Run Stages 1 and 2 (deterministic — no LLM calls)
2. Run Stage 2.5 grouping (LLM — prints chunk progress to terminal)
3. Open the browser-based review UI at `http://localhost:8743/review`
4. Wait for analyst approval
5. Run Stage 3 enrichment on the approved groups
6. Render the Excel report to `scubagear/data/output/{client_name}/`

#### ScubaGear CLI flags

| Flag | Description |
|------|-------------|
| `--action-plan` | Path to ActionPlan.csv or ScubaResults.csv (required unless default found) |
| `--tenant-id` | Azure tenant UUID. Overrides `[engagement] tenant_id` in config |
| `--config` | Path to scubagear_config.toml (default: `scubagear/config/scubagear_config.toml`) |
| `--output-dir` | Base output directory (default: `scubagear/data/output`). Client name appended automatically |
| `--no-browser` | Start the review server but do not auto-open the browser |
| `--skip-grouping` | Skip Stage 2.5 — enrich each control individually |
| `--skip-review` | Skip the review UI — use AI grouping proposal directly |
| `--port` | Review UI port (default: 8743) |

#### Using ScubaResults.csv for SHOULD-level controls

By default, `ActionPlan.csv` is used — it is pre-filtered by ScubaGear to SHALL failures only. To include SHOULD-level controls:

```toml
# In scubagear_config.toml:
[processing]
include_criticality = ["Shall", "Shall/3rd Party", "Shall/Not Implemented", "Should"]
input_file          = "ScubaResults"
```

Then pass the ScubaResults file:

```bash
python3 scubagear/src/run_scubagear.py \
  --action-plan /path/to/ScubaResults.csv \
  --tenant-id   <azure-tenant-uuid>
```

### Caching LLM responses during development

Set `PIPELINE_LLM_CACHE_DIR` to cache every LLM prompt→response pair to disk. Both pipelines respect this variable. Subsequent runs with identical inputs reuse cached responses at zero Bedrock cost.

```bash
export PIPELINE_LLM_CACHE_DIR=.llm_cache

# Prowler
python3 src/run_pipeline.py --input prowler.json --format json

# ScubaGear
python3 scubagear/src/run_scubagear.py --action-plan ActionPlan.csv --tenant-id <uuid>
```

Add `.llm_cache/` to `.gitignore`.

### Running over SSH

Use `--no-browser` to suppress auto-opening. The review URL is printed to the terminal.

```bash
# On the remote server
python3 src/run_pipeline.py --input prowler.json --no-browser           # Prowler  — port 8742
python3 scubagear/src/run_scubagear.py --action-plan ActionPlan.csv \
  --tenant-id <uuid> --no-browser                                        # ScubaGear — port 8743

# On your local machine (open the relevant port)
ssh -L 8742:localhost:8742 user@remote-server   # Prowler
ssh -L 8743:localhost:8743 user@remote-server   # ScubaGear
```

---

## Review UI

Both pipelines use the same review UI architecture. Key differences between the two UIs:

| Feature | Prowler (port 8742) | ScubaGear (port 8743) |
|---------|--------------------|-----------------------|
| Group cards | Flat grid | Grouped under collapsible M365 service section headers |
| Chip labels | AWS check IDs (e.g. `iam_root_mfa_enabled`) | M365 control IDs (e.g. `MS.AAD.3.1v1`) |
| Resource panel | ARNs, account names, regions | Control details text, service name |
| Risk Rating | Computed from matrix | Editable dropdown per card — analyst override preserved through enrichment |

### Group cards (both pipelines)

Each card shows:
- **Ref label** (e.g. ENT1, DEF2) — preview of the Excel reference number
- **Group name** — click to rename inline
- **Badges** — merged/standalone, severity, instance count, affected accounts/tenants
- **Risk Rating dropdown** (ScubaGear) — override the computed risk rating for this group
- **Rationale** — the AI's explanation of why these checks were grouped (editable)
- **Check chips** — draggable; drag between cards to move a check to a different group
- **Control details / Affected resources** — collapsible panel
- **AI instruction box** — per-group narrow instruction (e.g. "split this — legacy auth is different from MFA enforcement")

### Global AI instruction bar

At the top of the page. Applies to the entire board with full visibility across all groups. Use for broad corrections:

> "Merge all Entra ID MFA controls into one group"
> "Split the Defender group — ATP and identity protection have different remediation owners"

### Manual drag-and-drop

Drag any chip from one group card and drop it onto another. Resource context, instance count, and section assignment update immediately. No LLM call.

### Other controls

- **New Group**: creates an empty group card — name it, then drag chips into it
- **Reset to Proposed Grouping**: reverts all changes back to the original AI proposal
- **Approve & Continue**: validates (no unassigned chips, no empty groups, no unnamed groups), writes the approval file, and signals the pipeline to continue

---

## Output Files

All outputs are written to `{output_dir}/{client_name}/` where `client_name` is taken from the config and sanitised for filesystem use (spaces → underscores, special characters stripped).

### Prowler Outputs

| File | Stage | Description |
|------|-------|-------------|
| `canonical_findings.json` | 1 | Every finding with all 41 raw fields and full audit trail |
| `output_groups.json` | 2 | One group per unique check_id, post-dedup |
| `run_manifest.json` | 2 | Run metadata, counts, warnings |
| `stage1_summary.txt` | 1 | Human-readable ingestion summary |
| `stage2_summary.txt` | 2 | Human-readable processing summary |
| `grouping_proposal.json` | 2.5 | AI's proposed grouping before analyst review |
| `grouping_approved.json` | Review | Analyst-approved final grouping |
| `enriched_groups.json` | 3 | Final groups with LLM narratives and risk ratings |
| `SecurityReport_*.xlsx` | 5 | Client-facing Excel report |

### ScubaGear Outputs

| File | Stage | Description |
|------|-------|-------------|
| `m365_grouping_approved.json` | Review | Analyst-approved final grouping including any risk rating overrides |
| `run_summary.json` | 5 | Run metadata: stage counts, enrichment results, risk distribution |
| `M365_SecurityReport.xlsx` | 5 | Client-facing Excel report |

### Excel report structure

Both pipelines use `templates/Output_Template.xlsx` and produce the same 10-column structure:

| Column | Content |
|--------|---------|
| Ref | Sequential reference per section (ENT1, ENT2… DEF1… for ScubaGear; AWS1, AZ1… for Prowler) |
| Finding | LLM-generated title |
| Risk Rating | Colour-coded: High (red), Medium (amber), Low (green) |
| Root Cause | LLM-generated narrative |
| Likelihood Rating | Rules-based from severity and categories |
| Consequence Rating | LLM-generated: Minor / Moderate / Major |
| Access Required | LLM-generated |
| Situation | LLM-generated narrative |
| Consequence | LLM-generated narrative |
| Recommendations | LLM-generated remediation guidance (ScubaGear: references specific admin portals and cmdlets) |

**Prowler** routes findings to the `AWS` sheet (AWS findings) or `Azure` sheet (Azure findings).

**ScubaGear** writes to the `Azure` sheet, organised under M365 service section headings in this order:

1. Microsoft Entra ID (previously Azure Active Directory)
2. Microsoft 365 Defender
3. Microsoft Exchange Online
4. Microsoft SharePoint Online
5. Microsoft Teams
6. Microsoft Power Platform
7. Azure Resources

---

## Supported Input Formats

### Prowler

| Version | Format | Notes |
|---------|--------|-------|
| v3 | CSV, XLSX | Column aliases mapped automatically (e.g. `ACCOUNT_ID` → `ACCOUNT_UID`) |
| v4 | CSV, XLSX, JSON | Native column names |
| v5 | JSON (OCSF) | Nested OCSF structure flattened to v4 schema automatically |

- **CSV**: auto-detects delimiter (comma, semicolon, tab, pipe), fixes Prowler's double-CRLF line ending bug, handles UTF-8 and latin-1 encoding
- **XLSX**: reads first sheet, strips whitespace from headers
- **JSON flat**: array of objects with Prowler column names as keys
- **JSON OCSF**: nested Prowler v5 format, mapped to flat v4 schema

### ScubaGear

| File | Description |
|------|-------------|
| `ActionPlan.csv` | Pre-filtered to SHALL/FAIL controls. Recommended default input. Supports both the 8-column older team export and the 16-column GitHub sample format — column presence is checked at runtime, never positional. |
| `ScubaResults.csv` | Full scan output including PASS results and SHOULD-level controls. Use when engagement scope includes SHOULD findings. |

The ingestor handles both the full 16-column format (from ScubaGear GitHub releases) and the stripped-down 8-column format produced by older team exports. The 5 required columns are `Control ID`, `Requirement`, `Result`, `Criticality`, and `Details`. All others default to `None` if absent.

---

## Testing

### Prowler

All tests run offline — LLM calls are mocked. No AWS credentials required.

```bash
PYTHONPATH=src python3 tests/test_stage1.py    # 80 tests — ingestion
PYTHONPATH=src python3 tests/test_stage2.py    # 81 tests — processing
PYTHONPATH=src python3 tests/test_stage2_5.py  # 54 tests — grouping
PYTHONPATH=src python3 tests/test_stage3.py    # 113 tests — enrichment
```

Total: 328 tests, 0 failures.

### ScubaGear smoke test

```bash
cd scubagear/src
python3 -c "
import sys, tomllib
sys.path.insert(0, '.')
from pathlib import Path
from sg_ingest import ingest
from sg_process import process

with open('../config/scubagear_config.toml', 'rb') as f:
    config = tomllib.load(f)

result = ingest(Path('path/to/ActionPlan.csv'), config, tenant_id='test-tenant')
proc   = process(result, config)
print(f'Ingest: {result.finding_count} findings')
print(f'Process: {proc.group_count} groups')
for g in proc.output_groups[:5]:
    print(f'  {g.representative.ref_label():6}  {g.check_id}  {g.output_section}')
"
```

### Verifying Bedrock connectivity

```bash
python3 src/test_bedrock_connection.py
```

Sends a minimal prompt to Bedrock and prints the response. Confirms credentials, model access, and region are configured correctly before a full pipeline run.

---

## Project Structure

```
cloud-tool/
├── config/
│   └── config.toml                   Prowler pipeline configuration
│
├── data/
│   └── output/                       Prowler pipeline outputs
│       └── {client_name}/
│
├── src/                              Prowler pipeline source
│   ├── models.py                     CanonicalFinding dataclass (41 raw_* fields,
│   │                                 audit trail, enrichment fields)
│   ├── stage1_ingest.py              Ingestion: CSV/XLSX/JSON/OCSF parsing
│   ├── stage2_process.py             Processing: filter, dedup, group, likelihood
│   ├── stage2_5_grouping.py          Semantic grouping: chunked LLM + consolidation
│   ├── stage_reviewer.py             Browser review UI: HTTP server, drag-and-drop
│   ├── stage3_llm.py                 LLM enrichment for final approved groups
│   ├── stage5_render_excel.py        Excel report renderer
│   ├── run_pipeline.py               Prowler pipeline orchestrator and CLI
│   ├── test_bedrock_connection.py    Bedrock connectivity check
│   └── static/
│       └── logo.jpeg                 Company logo shown in review UI sidebar
│
├── scubagear/                        ScubaGear pipeline (fully independent)
│   ├── config/
│   │   └── scubagear_config.toml     ScubaGear pipeline configuration
│   │
│   ├── data/
│   │   └── output/                   ScubaGear pipeline outputs
│   │       └── {client_name}/
│   │
│   ├── src/                          ScubaGear pipeline source
│   │   ├── sg_models.py              ScubaFinding Pydantic model — M365-native schema
│   │   │                             with SECTION_ORDER, service map, HTML stripper
│   │   ├── sg_ingest.py              CSV ingestion: column-presence-checked,
│   │   │                             handles 8-col and 16-col export variants
│   │   ├── sg_process.py             Filter by criticality, dedup, build OutputGroups,
│   │   │                             assign per-section ref numbers
│   │   ├── sg_grouping.py            Semantic grouping: M365-specific merge criteria,
│   │   │                             chunked LLM calls with consolidation pass
│   │   ├── sg_reviewer.py            Browser review UI: section-grouped cards,
│   │   │                             editable Risk Rating dropdown, drag-and-drop
│   │   ├── sg_enrich.py              LLM enrichment: M365-specific prompts with
│   │   │                             admin portal and cmdlet references, Bedrock cache
│   │   ├── sg_render_excel.py        Excel renderer: re-sorts and reassigns ref numbers
│   │   │                             after grouping, writes all 7 M365 section headings
│   │   └── run_scubagear.py          ScubaGear pipeline orchestrator and CLI
│   │
│   └── templates/
│       └── Output_Template.xlsx      Shared Excel template (Azure sheet used for M365)
│
├── templates/
│   └── Output_Template.xlsx          Excel template with AWS and Azure sheets
│
└── tests/                            Prowler pipeline tests (328 tests)
    ├── test_stage1.py
    ├── test_stage2.py
    ├── test_stage2_5.py
    └── test_stage3.py
```

---

## Bedrock Setup

### Enabling zero data retention

AWS Bedrock must be configured with zero data retention before processing any client data. This is a one-time account-level setting per region, and applies to both pipelines.

```bash
# Check current setting
aws bedrock get-account-data-retention --region ap-southeast-2

# Enable zero retention
aws bedrock put-account-data-retention --mode none --region ap-southeast-2
```

### Model access

Both pipelines use `anthropic.claude-opus-4-8` via the Bedrock Converse API. The Prowler pipeline uses the AU cross-region inference profile (`au.anthropic.claude-opus-4-8`) by default. Request model access in the AWS Bedrock console under **Model access** before first use.

To switch to a different model or region, update `deployment_name` and `aws_region` in the relevant config file. No code changes are required.

### AWS credentials

Both pipelines use standard AWS credential resolution — `~/.aws/credentials`, environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), or an IAM role. No API keys are stored in the codebase or config files.

Minimum required IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:Converse"
      ],
      "Resource": "arn:aws:bedrock:ap-southeast-2::foundation-model/*"
    }
  ]
}
```

---

## Sample Outputs

Reference Excel reports generated from real pipeline runs are committed to the repository for review and QA purposes. These illustrate the final report structure, section layout, colour-coded risk ratings, and LLM-generated narratives.

| Pipeline | Path |
|----------|------|
| Prowler | [SecurityReport.xlsx](data/output/Sample-Output/SecurityReport.xlsx) |
| ScubaGear | [M365_SecurityReport.xlsx](data/sample-scuba-output/SampleScuba/M365_SecurityReport.xlsx) |

> These files contain synthetic or anonymised data only. Do not commit reports containing real client data to version control — `data/output/` and `scubagear/data/output/` are in `.gitignore`.

## Contact

For any queries, changes, or updates contact:
Shyam Balakrishnan,
Intern, Cyber Team,
FTI Consulting, Sydney.