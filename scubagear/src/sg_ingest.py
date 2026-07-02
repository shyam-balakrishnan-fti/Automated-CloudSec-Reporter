"""
sg_ingest.py — Stage 1: Ingest ScubaGear CSV output → ScubaFinding objects

Handles both file variants the pipeline may receive:
  - ActionPlan.csv   (pre-filtered to SHALL/FAIL, 8 columns in team export,
                      16 columns in GitHub sample)
  - ScubaResults.csv (full scan output, same column variants)

Column presence is checked at runtime — the ingestor never assumes positional
indexing. The 5 required columns must be present; all others default to None
if absent.

Key behaviours:
  - Strips HTML from Requirement (policy-indicators div) and raw_details
  - Normalises Result to PASS/FAIL/UNKNOWN
  - Treats "System.Object[]" in Comments as empty
  - Extracts best-effort instance_count from Details via regex
  - Resolves service_prefix / output_section / ref_prefix from Control ID
  - Builds stable_key and dedup_key
  - Assigns tenant_id from CLI arg or config fallback; warns if neither supplied
  - Logs unknown columns to extra_fields without crashing
"""

from __future__ import annotations

import csv
import hashlib
import logging
import uuid
from pathlib import Path
from typing import Any, Optional

from sg_models import (
    AuditEvent,
    ReportInclusion,
    ScannerStatus,
    ScubaFinding,
    extract_instance_count,
    resolve_service,
    strip_html,
)

logger = logging.getLogger(__name__)

# ── Required and optional column sets ─────────────────────────────────

REQUIRED_COLUMNS = {
    "Control ID",
    "Requirement",
    "Result",
    "Criticality",
    "Details",
}

# Maps CSV header → raw_ field name on ScubaFinding
OPTIONAL_COLUMN_MAP = {
    "Non-Compliance Reason":     "raw_non_compliance_reason",
    "Remediation Completion Date": "raw_remediation_date",
    "Justification":             "raw_justification",
    "OmittedEvaluationResult":   "raw_omitted_result",
    "OmittedEvaluationDetails":  "raw_omitted_details",
    "IncorrectResult":           "raw_incorrect_result",
    "IncorrectResultDetails":    "raw_incorrect_details",
    "OriginalResult":            "raw_original_result",
    "OriginalDetails":           "raw_original_details",
    "ResolutionDate":            "raw_resolution_date",
    "Comments":                  "raw_comments",
}

# Values that are structurally empty regardless of what the column is named
_EMPTY_VALUES = {"", "N/A", "System.Object[]", " "}


def _is_empty(value: Optional[str]) -> bool:
    return value is None or value.strip() in _EMPTY_VALUES


def _clean(value: Optional[str]) -> Optional[str]:
    """Return None for structurally empty values, stripped string otherwise."""
    if _is_empty(value):
        return None
    return value.strip()


# ── Result normalisation ───────────────────────────────────────────────

def _normalise_status(raw: Optional[str]) -> ScannerStatus:
    if not raw:
        return ScannerStatus.UNKNOWN
    v = raw.strip().lower()
    if v == "fail":
        return ScannerStatus.FAIL
    if v == "pass":
        return ScannerStatus.PASS
    return ScannerStatus.UNKNOWN


# ── Severity mapping ───────────────────────────────────────────────────

def _map_severity(criticality: str, severity_map: dict[str, str]) -> str:
    """
    Map raw Criticality string to pipeline severity level.
    Uses the config severity_map; falls back to "high" for any unrecognised
    Shall-prefixed value, "medium" for Should-prefixed, "low" otherwise.
    """
    if not criticality:
        return "medium"
    mapped = severity_map.get(criticality)
    if mapped:
        return mapped
    cl = criticality.lower()
    if cl.startswith("shall"):
        return "high"
    if cl.startswith("should"):
        return "medium"
    return "low"


# ── Likelihood from severity ───────────────────────────────────────────

def _initial_likelihood(severity: str) -> str:
    """
    Conservative initial likelihood from severity alone.
    The LLM grouping stage may revise upward based on check categories.
    """
    return {"high": "High", "medium": "Medium", "low": "Low"}.get(severity, "Medium")


# ── Key builders ──────────────────────────────────────────────────────

def _build_stable_key(tenant_id: str, control_id: str) -> str:
    return f"azure:{tenant_id}:{control_id}"


def _build_dedup_key(tenant_id: str, control_id: str) -> str:
    raw = f"azure|{tenant_id}|{control_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Single-row parser ─────────────────────────────────────────────────

def _parse_row(
    row: dict[str, str],
    source_file: str,
    run_id: str,
    tenant_id: str,
    severity_map: dict[str, str],
    service_map: Optional[dict] = None,
    row_num: int = 0,
) -> ScubaFinding:
    """
    Parse one CSV row dict into a ScubaFinding.
    Never raises — any malformed data results in a flagged finding.
    """
    # ── Required fields ───────────────────────────────────────────────
    control_id   = _clean(row.get("Control ID")) or ""
    raw_req      = _clean(row.get("Requirement")) or ""
    raw_result   = _clean(row.get("Result")) or ""
    raw_crit     = _clean(row.get("Criticality")) or ""
    raw_details  = _clean(row.get("Details")) or ""

    # Strip HTML from Requirement → check_title
    check_title = strip_html(raw_req)

    # Strip HTML from Details defensively (OriginalDetails can contain <a> tags)
    details_clean = strip_html(raw_details) if raw_details else ""

    # ── Service resolution ────────────────────────────────────────────
    service_prefix, output_section, ref_prefix = resolve_service(control_id, service_map)

    # ── Status / severity ─────────────────────────────────────────────
    scanner_status = _normalise_status(raw_result)
    severity       = _map_severity(raw_crit, severity_map)

    # ── Instance count (best-effort) ──────────────────────────────────
    instance_count = extract_instance_count(details_clean)

    # ── Keys ─────────────────────────────────────────────────────────
    stable_key = _build_stable_key(tenant_id, control_id)
    dedup_key  = _build_dedup_key(tenant_id, control_id)

    # ── Build finding ─────────────────────────────────────────────────
    finding = ScubaFinding(
        run_id          = run_id,
        source_file     = source_file,
        tenant_id       = tenant_id,
        stable_key      = stable_key,
        dedup_key       = dedup_key,
        # Raw required
        raw_control_id  = control_id or None,
        raw_requirement = raw_req or None,
        raw_result      = raw_result or None,
        raw_criticality = raw_crit or None,
        raw_details     = details_clean or None,
        # Normalised
        control_id      = control_id,
        check_title     = check_title,
        scanner_status  = scanner_status,
        criticality_raw = raw_crit,
        severity        = severity,
        service_prefix  = service_prefix,
        service_name    = _section_to_service_name(output_section),
        output_section  = output_section,
        ref_prefix      = ref_prefix,
        instance_count  = instance_count,
        likelihood_rating = _initial_likelihood(severity),
    )

    # ── Optional columns (present-check) ─────────────────────────────
    for col_header, field_name in OPTIONAL_COLUMN_MAP.items():
        val = _clean(row.get(col_header))
        if col_header == "Comments":
            # Always empty — PowerShell artefact
            setattr(finding, field_name, None)
        elif col_header in ("OriginalDetails",):
            # May also contain HTML
            setattr(finding, field_name, strip_html(val) if val else None)
        else:
            setattr(finding, field_name, val)

    # ── Unknown extra columns → extra_fields ─────────────────────────
    known = REQUIRED_COLUMNS | set(OPTIONAL_COLUMN_MAP.keys())
    for col, val in row.items():
        if col not in known and val and val.strip() not in _EMPTY_VALUES:
            finding.extra_fields[col] = val.strip()

    # ── Flag rows with missing Control ID ─────────────────────────────
    if not control_id:
        finding.flag_for_review(
            reason=f"Row {row_num}: Control ID is blank — cannot resolve service or build keys",
            stage="sg_ingest",
        )
        finding.set_report_inclusion(
            ReportInclusion.EXCLUDED,
            stage="sg_ingest",
            reason="Control ID blank — excluded from report",
        )

    # ── Ingestion audit event ─────────────────────────────────────────
    finding.add_audit(
        stage="sg_ingest",
        field="ingested",
        old_value=None,
        new_value=control_id,
        reason=f"Parsed from {source_file} row {row_num}",
    )

    return finding


def _section_to_service_name(section: str) -> str:
    """Short service name for display and LLM context."""
    _MAP = {
        "Microsoft Entra ID (previously Azure Active Directory)": "Entra ID",
        "Microsoft 365 Defender":       "Defender",
        "Microsoft Exchange Online":    "Exchange Online",
        "Microsoft SharePoint Online":  "SharePoint Online",
        "Microsoft Teams":              "Teams",
        "Microsoft Power Platform":     "Power Platform",
        "Azure Resources":              "Azure Resources",
    }
    return _MAP.get(section, section)


# ── CSV reader ────────────────────────────────────────────────────────

def _read_csv(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    """
    Read CSV, returning (rows, headers). Handles UTF-8 BOM.
    Raises FileNotFoundError if path does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    rows: list[dict[str, str]] = []
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        headers = list(reader.fieldnames or [])
        for row in reader:
            rows.append(dict(row))
    return rows, headers


# ── Ingest result ─────────────────────────────────────────────────────

from dataclasses import dataclass, field as dc_field


@dataclass
class IngestWarning:
    code:    str
    message: str


@dataclass
class IngestResult:
    run_id:      str
    findings:    list[ScubaFinding]
    warnings:    list[IngestWarning]
    source_file: str
    row_count:   int   = 0
    skipped:     int   = 0

    @property
    def finding_count(self) -> int:
        return len(self.findings)


# ── Main entry point ──────────────────────────────────────────────────

def ingest(
    csv_path: Path,
    config: dict[str, Any],
    tenant_id: str = "",
    run_id: Optional[str] = None,
) -> IngestResult:
    """
    Stage 1 entry point.

    Args:
        csv_path:  Path to ActionPlan.csv or ScubaResults.csv
        config:    Full config dict (parsed from scubagear_config.toml)
        tenant_id: From --tenant-id CLI flag; falls back to config if empty
        run_id:    Pipeline run UUID; generated if not supplied

    Returns IngestResult with all parsed ScubaFinding objects.
    Never raises on bad data — malformed rows are flagged and included.
    """
    run_id     = run_id or str(uuid.uuid4())
    warnings:  list[IngestWarning] = []
    engagement = config.get("engagement", {})
    sev_map    = config.get("severity_map", {})
    svc_map    = config.get("service_map", {})

    # ── Tenant ID resolution ──────────────────────────────────────────
    resolved_tenant = (
        tenant_id.strip()
        or engagement.get("tenant_id", "").strip()
        or "UNKNOWN-TENANT"
    )
    if resolved_tenant == "UNKNOWN-TENANT":
        warnings.append(IngestWarning(
            code="UNKNOWN_TENANT",
            message=(
                "Tenant ID not supplied via --tenant-id or config [engagement] tenant_id. "
                "stable_key and dedup_key will use 'UNKNOWN-TENANT' as placeholder. "
                "Provide --tenant-id <uuid> for production runs."
            ),
        ))
        logger.warning("Tenant ID unknown — keys will use placeholder 'UNKNOWN-TENANT'")

    # ── Column validation ─────────────────────────────────────────────
    rows, headers = _read_csv(csv_path)
    present = set(headers)
    missing = REQUIRED_COLUMNS - present
    if missing:
        raise ValueError(
            f"Input file {csv_path.name} is missing required columns: {sorted(missing)}"
        )

    optional_present = set(OPTIONAL_COLUMN_MAP.keys()) & present
    optional_absent  = set(OPTIONAL_COLUMN_MAP.keys()) - present
    if optional_absent:
        logger.info(
            "Optional columns absent (older export format) — will default to None: %s",
            sorted(optional_absent),
        )

    # ── Parse rows ────────────────────────────────────────────────────
    findings: list[ScubaFinding] = []
    skipped = 0

    print(
        f"\n[ Stage 1 ] Ingesting {csv_path.name} "
        f"({len(rows)} rows, {len(present)} columns, tenant={resolved_tenant})",
        flush=True,
    )

    for row_num, row in enumerate(rows, start=2):  # row 1 is header
        # Skip entirely blank rows (can appear at end of CSV)
        if all(_is_empty(v) for v in row.values()):
            skipped += 1
            continue

        finding = _parse_row(
            row=row,
            source_file=str(csv_path),
            run_id=run_id,
            tenant_id=resolved_tenant,
            severity_map=sev_map,
            service_map=svc_map,
            row_num=row_num,
        )
        findings.append(finding)

    status_counts: dict[str, int] = {}
    for f in findings:
        k = f.scanner_status.value
        status_counts[k] = status_counts.get(k, 0) + 1

    print(
        f"  ✓ Parsed {len(findings)} findings "
        f"({skipped} blank row(s) skipped): {status_counts}",
        flush=True,
    )
    if warnings:
        for w in warnings:
            print(f"  ⚠ [{w.code}] {w.message}", flush=True)

    return IngestResult(
        run_id      = run_id,
        findings    = findings,
        warnings    = warnings,
        source_file = str(csv_path),
        row_count   = len(rows),
        skipped     = skipped,
    )