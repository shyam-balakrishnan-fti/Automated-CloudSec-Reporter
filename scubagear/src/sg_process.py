"""
sg_process.py — Stage 2: Filter, deduplicate, group by Control ID

Responsibilities:
  - Filter to included statuses and criticality levels from config
  - Deduplicate by dedup_key (stable per-tenant-per-control-id hash)
  - Group by control_id to produce one OutputGroup per unique control
  - Assign per-section ref numbers (ENT1, ENT2, DEF1, DEF2, ...)
  - Assign likelihood_rating from severity (may be overridden by sg_grouping)

Note on grouping philosophy:
  ScubaGear has no per-resource rows (unlike Prowler). Each control_id
  appears at most once per scan. Grouping here is therefore trivial —
  one finding → one OutputGroup. The semantic grouping (sg_grouping.py)
  later merges OutputGroups that share root cause across control IDs.

Contract:
  process(ingest_result, config) -> ProcessResult
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from sg_models import (
    ReportInclusion,
    ScannerStatus,
    ScubaFinding,
    SECTION_ORDER,
)
from sg_ingest import IngestResult

logger = logging.getLogger(__name__)

# ── Severity ordering for representative selection ────────────────────

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


# ── OutputGroup ───────────────────────────────────────────────────────

@dataclass
class OutputGroup:
    """
    One control_id → one group. Representative is the single ScubaFinding
    (ScubaGear has no per-resource rows, so there is always exactly one).
    Mirrors the Prowler OutputGroup interface so sg_grouping.py can use
    identical patterns.
    """
    check_id:       str                  # control_id, e.g. "MS.AAD.3.1v1"
    representative: ScubaFinding
    instance_ids:   list[str]            = field(default_factory=list)
    instance_count: int                  = 1
    output_section: str                  = ""
    severity:       Optional[str]        = None
    likelihood_rating: Optional[str]     = None
    # tenant-level equivalents to Prowler's account_name / account_uid
    affected_tenant_ids: list[str]       = field(default_factory=list)

    def to_llm_context(self) -> dict[str, Any]:
        """Full context dict for Stage 3 enrichment."""
        ctx = self.representative.to_ai_lane()
        ctx["instance_count"]        = self.instance_count
        ctx["affected_account_names"] = self.affected_tenant_ids
        ctx["likelihood_rating"]     = self.likelihood_rating
        return ctx


# ── ProcessResult ─────────────────────────────────────────────────────

@dataclass
class ProcessResult:
    run_id:        str
    output_groups: list[OutputGroup]
    all_findings:  list[ScubaFinding]
    warnings:      list["ProcessWarning"]
    config:        dict[str, Any]
    total_ingested:    int = 0
    included_count:    int = 0
    excluded_count:    int = 0
    duplicate_count:   int = 0

    @property
    def group_count(self) -> int:
        return len(self.output_groups)


@dataclass
class ProcessWarning:
    code:    str
    message: str


# ── Filtering ─────────────────────────────────────────────────────────

def _should_include(finding: ScubaFinding, config: dict[str, Any]) -> tuple[bool, str]:
    """
    Returns (include: bool, reason: str).
    Checks scanner_status and criticality_raw against config [processing].
    """
    proc = config.get("processing", {})

    # Status: always include FAIL. PASS findings are excluded unless config says otherwise.
    # ScubaGear ActionPlan.csv is pre-filtered — all rows are FAIL. ScubaResults.csv
    # contains both PASS and FAIL; we only want FAIL for a findings report.
    if finding.scanner_status == ScannerStatus.PASS:
        return False, "Status=PASS — passing controls excluded from report"

    if finding.scanner_status == ScannerStatus.UNKNOWN:
        return False, f"Status=UNKNOWN — unrecognised result value '{finding.raw_result}'"

    # Criticality: filter to included levels
    include_crit = proc.get("include_criticality", ["Shall", "Shall/3rd Party", "Shall/Not Implemented"])
    if finding.criticality_raw and finding.criticality_raw not in include_crit:
        return False, (
            f"Criticality='{finding.criticality_raw}' not in include_criticality={include_crit}"
        )

    return True, ""


# ── Deduplication ─────────────────────────────────────────────────────

def _deduplicate(
    findings: list[ScubaFinding],
    warnings: list[ProcessWarning],
) -> list[ScubaFinding]:
    """
    Within-run dedup by dedup_key. The first occurrence is kept as primary;
    subsequent duplicates are marked and excluded from output_groups.
    In practice, ScubaGear should never emit the same control_id twice in
    one scan, but belt-and-suspenders.
    """
    seen: dict[str, str] = {}  # dedup_key → finding_instance_id
    for f in findings:
        if not f.dedup_key:
            continue
        if f.dedup_key in seen:
            f.is_duplicate  = True
            f.duplicate_of  = seen[f.dedup_key]
            f.set_report_inclusion(
                ReportInclusion.EXCLUDED,
                stage="sg_process",
                reason=f"Duplicate of {seen[f.dedup_key]} (same dedup_key)",
            )
            warnings.append(ProcessWarning(
                code="DUPLICATE_FINDING",
                message=(
                    f"Control {f.control_id} appears more than once in the source file. "
                    f"Keeping {seen[f.dedup_key]}, excluding {f.finding_instance_id}."
                ),
            ))
        else:
            seen[f.dedup_key] = f.finding_instance_id
    return findings


# ── Ref number assignment ─────────────────────────────────────────────

def _assign_ref_numbers(groups: list[OutputGroup]) -> None:
    """
    Assign per-section sequential ref numbers.
    Groups are already sorted by section (SECTION_ORDER) then severity.
    Counter resets per section: ENT1, ENT2, DEF1, DEF2, ...
    """
    counters: dict[str, int] = defaultdict(int)
    for g in groups:
        section = g.output_section
        counters[section] += 1
        g.representative.ref_number = counters[section]


# ── Group building ────────────────────────────────────────────────────

def _build_output_group(finding: ScubaFinding) -> OutputGroup:
    return OutputGroup(
        check_id         = finding.control_id,
        representative   = finding,
        instance_ids     = [finding.finding_instance_id],
        instance_count   = finding.instance_count,
        output_section   = finding.output_section,
        severity         = finding.severity,
        likelihood_rating = finding.likelihood_rating,
        affected_tenant_ids = [finding.tenant_id] if finding.tenant_id else [],
    )


def _sort_groups(groups: list[OutputGroup]) -> list[OutputGroup]:
    """
    Sort by:
      1. Section order (SECTION_ORDER index, unknown sections last)
      2. Severity (high → medium → low)
      3. Control ID for determinism
    """
    section_idx = {s: i for i, s in enumerate(SECTION_ORDER)}
    return sorted(
        groups,
        key=lambda g: (
            section_idx.get(g.output_section, 99),
            _SEV_ORDER.get(g.severity or "low", 3),
            g.check_id,
        ),
    )


# ── Main entry point ──────────────────────────────────────────────────

def process(
    ingest_result: IngestResult,
    config: dict[str, Any],
) -> ProcessResult:
    """
    Stage 2 entry point.

    1. Filter by status and criticality
    2. Deduplicate by dedup_key
    3. Build one OutputGroup per included finding
    4. Sort groups by section → severity → control_id
    5. Assign per-section ref numbers

    Returns ProcessResult ready for sg_grouping.
    """
    warnings: list[ProcessWarning] = []
    findings  = ingest_result.findings
    total     = len(findings)

    print(
        f"\n[ Stage 2 ] Processing {total} findings from {ingest_result.source_file}",
        flush=True,
    )

    # ── Step 1: filter ────────────────────────────────────────────────
    included: list[ScubaFinding] = []
    excluded_count = 0

    for f in findings:
        include, reason = _should_include(f, config)
        if include:
            included.append(f)
        else:
            excluded_count += 1
            f.set_report_inclusion(
                ReportInclusion.EXCLUDED,
                stage="sg_process",
                reason=reason,
            )
            logger.debug("Excluded %s: %s", f.control_id, reason)

    print(
        f"  Filter: {len(included)} included, {excluded_count} excluded",
        flush=True,
    )

    # ── Step 2: dedup ─────────────────────────────────────────────────
    all_findings = _deduplicate(included + [f for f in findings if f not in included], warnings)
    active = [f for f in included if not f.is_duplicate]
    dup_count = len(included) - len(active)
    if dup_count:
        print(f"  Dedup: {dup_count} duplicate(s) removed", flush=True)

    # ── Step 3: build OutputGroups ────────────────────────────────────
    groups = [_build_output_group(f) for f in active]

    # ── Step 4: sort ──────────────────────────────────────────────────
    groups = _sort_groups(groups)

    # ── Step 5: assign ref numbers ────────────────────────────────────
    _assign_ref_numbers(groups)

    # Section summary
    section_counts: dict[str, int] = defaultdict(int)
    for g in groups:
        section_counts[g.output_section] += 1
    for section, count in section_counts.items():
        print(f"    {section}: {count} finding(s)", flush=True)

    print(
        f"  ✓ {len(groups)} OutputGroup(s) ready for grouping stage",
        flush=True,
    )

    return ProcessResult(
        run_id         = ingest_result.run_id,
        output_groups  = groups,
        all_findings   = findings,
        warnings       = warnings,
        config         = config,
        total_ingested = total,
        included_count = len(active),
        excluded_count = excluded_count,
        duplicate_count = dup_count,
    )