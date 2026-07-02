# FTI - Automated Cloud Security Reporter

A production-grade pipeline that converts [Prowler](https://github.com/prowler-cloud/prowler) cloud security scanner output into client-ready security assessment reports. Handles ingestion, deduplication, AI-driven semantic grouping, analyst review, LLM enrichment, and Excel rendering , with a browser-based review UI that lets analysts refine groupings before any report is generated.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Pipeline](#running-the-pipeline)
- [Review UI](#review-ui)
- [Output Files](#output-files)
- [Supported Input Formats](#supported-input-formats)
- [Testing](#testing)
- [Utilities](#utilities)
- [Project Structure](#project-structure)
- [Bedrock Setup](#bedrock-setup)

---

## Overview

### What it does

1. **Ingests** Prowler output in CSV, XLSX, or JSON format — including OCSF (Prowler v5), v3 and v4 schemas, and non-standard delimiters
2. **Processes** findings: filters by status, deduplicates across accounts, assigns likelihood ratings
3. **Groups semantically** using LLM — sorts by category and service, chunks into batches of ~15, runs an automatic cross-chunk consolidation pass to catch missed merges
4. **Opens a browser-based review UI** where analysts can drag individual findings between groups, rename groups, use per-group or board-wide AI instructions to refine grouping, and inspect affected resources per group
5. **Enriches** only the final approved groups — situation, consequence, root cause narratives, and consequence rating — using Claude via AWS Bedrock
6. **Renders** a client-facing Excel report with colour-coded risk ratings, affected resources embedded in the Situation column, and per-group recommendations built from raw Prowler remediation text

### What it does not do

- Store any customer data persistently — all processing is in-memory per run
- Call any external service other than AWS Bedrock (no third-party APIs, no telemetry)
- Enrich individual findings before grouping — enrichment runs only on the final approved groups, keeping LLM costs proportional to the number of report line items (~16 calls) not the total finding count (~101 calls)

---

## Architecture

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
│  Review UI               │  Localhost HTTP server, opens browser.
│  stage_reviewer.py       │  Analyst reviews groups, drags chips, uses AI
└──────────┬───────────────┘  instruction boxes. Approve → pipeline continues.
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

### Key design decisions

**Grouping before enrichment.** The LLM proposes groups first, the analyst approves them, then enrichment runs on the final ~16 groups — not the original ~101 individual checks. This keeps LLM costs proportional to report line items, and ensures narratives are written with the full merged context rather than for isolated individual checks.

**Conservative merge criteria.** Groups are only merged if they share the same AWS service AND the same remediation path. Different services (e.g. S3 public access and CloudTrail public access) are never auto-merged even if they share a theme — the analyst uses the review UI to merge manually if desired.

**Analyst always has final say.** The AI proposes, the analyst approves. The review UI supports drag-and-drop chip rearrangement, per-group AI instructions ("split this — root MFA is different from console MFA"), and board-wide AI instructions ("merge all S3 misconfiguration checks into one group regardless of nuance"). Nothing goes to the Excel renderer until the analyst clicks Approve.

---

## Prerequisites

- Python 3.12+
- AWS credentials configured (`~/.aws/credentials` or environment variables)
- Zero data retention configured on your Bedrock account (see [Bedrock Setup](#bedrock-setup))

```bash
pip install boto3 openpyxl pydantic toml
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

All configuration lives in `config/config.toml`. **Update the `[engagement]` section before every run.**

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

---

## Running the Pipeline

### Standard run

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
6. Render the Excel report

Output is written to `data/output/{client_name}/`.

### All CLI flags

| Flag | Description |
|------|-------------|
| `--input`, `-i` | Path to Prowler CSV, XLSX, or JSON file (required) |
| `--output-dir`, `-o` | Base output directory (default: `data/output`) |
| `--config`, `-c` | Path to config.toml (default: `config/config.toml`) |
| `--format`, `-f` | Force input format: `auto`, `csv`, `xlsx`, `json` (default: `auto`) |
| `--skip-llm` | Skip Stages 2.5 and 3 — produces Stage 1+2 outputs only |
| `--skip-review` | Skip the review UI — use AI grouping proposal directly |
| `--force-review` | Force the review UI even if `grouping_approved.json` already exists |
| `--no-browser` | Start the review server but do not auto-open the browser (use when running over SSH) |

### Re-using an approved grouping

If you have already approved a grouping in a previous run and only want to re-run enrichment and Excel rendering (e.g. after tweaking the risk matrix), simply re-run without `--force-review`. The pipeline will detect the existing `grouping_approved.json` and skip the review UI.

### Skipping LLM costs during development

Set the `PIPELINE_LLM_CACHE_DIR` environment variable to cache every LLM response to disk. Subsequent runs with the same inputs reuse cached responses at zero cost.

```bash
export PIPELINE_LLM_CACHE_DIR=.llm_cache
python3 src/run_pipeline.py --input prowler.json --format json
# First run: calls Bedrock, writes cache

python3 src/run_pipeline.py --input prowler.json --format json
# Subsequent runs: reads from cache, $0 cost
```

Add `.llm_cache/` to your `.gitignore`.

---

## Review UI

The review UI opens automatically in your browser when Stage 2.5 finishes. It runs on `http://localhost:8742/review`.

### Group cards

Each card shows:
- **Group name** (click to rename inline)
- **Badges**: merged/standalone, severity, instance count, affected accounts
- **Rationale**: the AI's explanation of why these checks were grouped (editable)
- **Check chips**: draggable — drag between cards to move a check to a different group
- **Affected resources**: collapsible panel showing ARNs, account names, and regions for every resource in this group, pulled directly from raw Prowler data
- **AI instruction box**: type a narrow instruction for this group only (e.g. "split this — IAM root MFA is a different risk from console user MFA")

### Global AI instruction bar

At the top of the page. Applies to the entire board with full visibility across all groups. Use this for broad corrections:

> "Merge all S3 misconfiguration checks into one group regardless of nuance"
> "Split the logging group — CloudTrail and VPC Flow Logs have different remediation owners"

### Manual drag-and-drop

Drag any check chip from one group card and drop it onto another. The destination card's resource context, instance count, and account badges update immediately. No LLM call — purely in-memory.

### Other controls

- **New Group** (sidebar): creates an empty group card with a working drop zone — name it, then drag checks into it
- **Reset to Proposed Grouping** (sidebar): reverts all changes back to the original AI proposal
- **Approve & Continue** (sidebar): validates (no unassigned checks, no unnamed groups, no empty groups), writes `grouping_approved.json`, and signals the pipeline to continue

### Running over SSH

Use `--no-browser` to start the server without auto-opening a browser. The review URL is printed to the terminal — open it in a browser with port forwarding.

```bash
# On the remote server
python3 src/run_pipeline.py --input prowler.json --no-browser

# On your local machine
ssh -L 8742:localhost:8742 user@remote-server
# Then open http://localhost:8742/review in your local browser
```

---

## Output Files

All outputs are written to `data/output/{client_name}/` where `client_name` comes from `config.toml`.

| File | Stage | Description |
|------|-------|-------------|
| `canonical_findings.json` | 1 | Every finding with all 41 raw fields and full audit trail |
| `output_groups.json` | 2 | One group per unique check_id, post-dedup |
| `run_manifest.json` | 2 | Run metadata, counts, warnings |
| `stage1_summary.txt` | 1 | Human-readable ingestion summary |
| `stage2_summary.txt` | 2 | Human-readable processing summary |
| `grouping_proposal.json` | 2.5 | AI's proposed grouping before analyst review |
| `grouping_approved.json` | Review | Analyst-approved final grouping |
| `enriched_groups.json` | 3 | Final groups with LLM narratives and risk ratings, including full affected resource detail per group |
| `SecurityReport_*.xlsx` | 5 | Client-facing Excel report |

### Excel report structure

The report uses `templates/Output_Template.xlsx`. Each finding row contains:

| Column | Content |
|--------|---------|
| Ref | AWS1, AWS2... (or AZ1, AZ2... for Azure) |
| Finding | LLM-generated title |
| Risk Rating | Colour-coded: High (red), Medium (amber), Low (green) |
| Root Cause | LLM-generated narrative |
| Likelihood Rating | Rules-based from categories and severity |
| Consequence Rating | LLM-generated: Minor / Moderate / Major |
| Access Required | LLM-generated |
| Situation | LLM-generated narrative + affected resource ARNs embedded inline |
| Consequence | LLM-generated narrative |
| Recommendations | Raw Prowler remediation text, one section per constituent check for merged groups |

AWS findings write to the `AWS` sheet. Azure findings write to the `Azure` sheet. Both sheets use the same column structure.

---

## Supported Input Formats

### Prowler versions

| Version | Format | Notes |
|---------|--------|-------|
| v3 | CSV, XLSX | Column aliases mapped automatically (e.g. `ACCOUNT_ID` → `ACCOUNT_UID`) |
| v4 | CSV, XLSX, JSON | Native column names |
| v5 | JSON (OCSF) | Nested OCSF structure flattened to v4 schema automatically |

### Input format handling

- **CSV**: auto-detects delimiter (comma, semicolon, tab, pipe), fixes Prowler's double-CRLF line ending bug, handles UTF-8 and latin-1 encoding
- **XLSX**: reads first sheet, strips whitespace from headers
- **JSON flat**: array of objects with Prowler column names as keys
- **JSON OCSF**: nested Prowler v5 format, mapped to flat v4 schema

### Cloud providers

| Provider | `PROVIDER` column value | Output sheet |
|----------|------------------------|--------------|
| AWS | `aws` | AWS |
| Azure | `azure` | Azure |
| GCP | `gcp` | GCP |

Both AWS and Azure Prowler outputs use identical column schemas — the `PROVIDER` column determines routing, nothing else changes.

---

## Testing

All tests run offline — LLM calls are mocked. No AWS credentials required.

```bash
# Run all test suites
PYTHONPATH=src python3 tests/test_stage1.py    # 80 tests — ingestion
PYTHONPATH=src python3 tests/test_stage2.py    # 81 tests — processing
PYTHONPATH=src python3 tests/test_stage2_5.py  # 54 tests — grouping
PYTHONPATH=src python3 tests/test_stage3.py    # 113 tests — enrichment
```

Total: 328 tests, 0 failures.

### Verifying Bedrock connectivity

```bash
python3 src/test_bedrock_connection.py
```

This sends a minimal prompt to Bedrock and prints the response. Confirms credentials, model access, and region configuration are correct before running a full pipeline.



---

## Project Structure

```
cloud-tool/
├── config/
│   └── config.toml               Configuration (engagement, LLM, risk matrix, output)
│
├── data/
│   ├── synthetic/                 Test data (generated, not committed)
│   └── output/                   Pipeline outputs, one subfolder per client
│       └── {client_name}/
│
├── src/
│   ├── models.py                  CanonicalFinding dataclass (41 raw_* fields,
│   │                              audit trail, enrichment fields)
│   ├── stage1_ingest.py           Ingestion: CSV/XLSX/JSON/OCSF parsing,
│   │                              normalisation, dedup key assignment
│   ├── stage2_process.py          Processing: filter, dedup, group,
│   │                              likelihood rating, section routing
│   ├── stage2_5_grouping.py       Semantic grouping: chunked LLM calls
│   │                              with running group list + consolidation pass
│   ├── stage_reviewer.py          Browser-based grouping review UI:
│   │                              HTTP server, drag-and-drop, AI instruction boxes
│   ├── stage3_llm.py              LLM enrichment for final approved groups
│   ├── stage5_render_excel.py     Excel report renderer
│   ├── run_pipeline.py            Pipeline orchestrator and CLI entry point
│   ├── pdf_to_docx.py             Standalone PDF→DOCX converter
│   ├── test_bedrock_connection.py Bedrock connectivity check
│   └── static/
│       └── logo.jpeg              Company logo shown in review UI sidebar
│
├── templates/
│   └── Output_Template.xlsx       Excel template with AWS and Azure sheets
│
└── tests/
    ├── test_stage1.py             80 tests — ingestion and parsing
    ├── test_stage2.py             81 tests — processing logic
    ├── test_stage2_5.py           54 tests — chunked grouping architecture
    └── test_stage3.py             113 tests — LLM enrichment and risk matrix
```

---

## Bedrock Setup

### Enabling zero data retention

AWS Bedrock must be configured with zero data retention before processing any client data. This is a one-time account-level setting per region.

```bash
# Check current setting
aws bedrock get-account-data-retention --region ap-southeast-2

# Enable zero retention
aws bedrock put-account-data-retention --mode none --region ap-southeast-2
```

### Model access

The pipeline uses `au.anthropic.claude-opus-4-8` — the AU geographic cross-region inference profile for `ap-southeast-2`. Request access in the AWS Bedrock console under **Model access** before first use.

To switch to a different region, update only `aws_region` in `config.toml`. No code changes are required.

### AWS credentials

The pipeline uses standard AWS credential resolution — `~/.aws/credentials`, environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), or an IAM role if running on EC2/ECS. No API keys are stored in the codebase or config.

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
## Contact:
For any queries/changes/updates contact:
Shyam Balakrishnan,
Intern, Cyber Team, 
FTI Consulting, Sydney.