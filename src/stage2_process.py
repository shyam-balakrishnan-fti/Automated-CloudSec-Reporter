"""
stage2_process.py — Stage 2: Deterministic Processing Engine

Responsibilities (all sub-stages run in order):
    2A  Status filter      — keep only include_statuses from config; exclude rest
    2B  Deduplication      — resource-level, type-stratified, within-run
    2C  Output grouping    — collapse instances by check_id → one OutputGroup per check
    2D  Likelihood rating  — rule-based lookup from config [severity_rules]
    2E  Section assignment — map provider/service → output sheet section

Contract:
    process(ingest_result, config) -> ProcessResult

Determinism guarantee:
    Given the same IngestResult and the same config, this function always
    produces byte-identical output. No LLM, no randomness, no external calls.

What Stage 3 (LLM) receives:
    A list of OutputGroup objects, each carrying:
        - The representative CanonicalFinding (highest completeness score)
        - instance_count (number of affected resources)
        - affected_account_names (for scope language in narratives)
        - likelihood_rating (already computed — LLM is informed but cannot override)
        - All resource-level instance IDs (for audit trail)
"""

from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from models import (
    BlankCategory,
    CanonicalFinding,
    ReportInclusion,
    ScannerStatus,
)
from stage1_ingest import IngestResult

logger = logging.getLogger(__name__)

# ── Config loader ─────────────────────────────────────────────────────

def load_config(config_path: str | Path) -> dict[str, Any]:
    """
    Load and validate config.toml.
    Raises ValueError with a clear message if required keys are missing.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "rb") as f:
        cfg = tomllib.load(f)

    # Validate required sections
    required = ["processing", "severity_rules", "risk_matrix", "output"]
    for section in required:
        if section not in cfg:
            raise ValueError(
                f"config.toml is missing required section [{section}]. "
                f"Found sections: {list(cfg.keys())}"
            )

    # Validate include_statuses
    valid_statuses = {"FAIL", "MUTED(FAIL)", "MANUAL", "PASS", "MUTED(PASS)", "MUTED(MANUAL)"}
    for s in cfg["processing"].get("include_statuses", []):
        if s not in valid_statuses:
            raise ValueError(
                f"Unknown status '{s}' in [processing] include_statuses. "
                f"Valid values: {sorted(valid_statuses)}"
            )

    # Validate risk_matrix keys
    valid_likelihood = {"High", "Medium", "Low"}
    valid_consequence = {"Major", "Moderate", "Minor"}
    for key in cfg["risk_matrix"]:
        parts = key.split("_", 1)
        if len(parts) != 2 or parts[0] not in valid_likelihood or parts[1] not in valid_consequence:
            raise ValueError(
                f"Invalid risk_matrix key '{key}'. "
                f"Expected format: 'Likelihood_Consequence' "
                f"e.g. 'High_Major', 'Medium_Moderate', 'Low_Minor'"
            )

    return cfg


# ── OutputGroup ───────────────────────────────────────────────────────

@dataclass
class OutputGroup:
    """
    One row in the final output Excel sheet.

    Represents a CHECK_ID grouping: all instances of the same check type,
    collapsed into a single output row with a representative finding.

    The representative is the instance with the highest completeness_score().
    On tie, the first by source row order is used.
    """
    # Group identity
    check_id:               str
    output_section:         str         # "AWS" etc.
    output_group_key:       str         # "{check_id}:{output_section}"

    # Representative finding — drives LLM input and output content
    representative:         CanonicalFinding

    # All instance IDs in this group (for audit trail and canonical JSON)
    instance_ids:           list[str]   = field(default_factory=list)

    # Aggregate values across all instances
    instance_count:         int         = 1
    affected_account_names: list[str]   = field(default_factory=list)
    affected_account_uids:  list[str]   = field(default_factory=list)

    # Computed likelihood rating (set during Stage 2D)
    likelihood_rating:      Optional[str] = None

    @property
    def ref_id(self) -> str:
        """Ref ID is assigned at render time, not here."""
        return ""

    def to_llm_context(self) -> dict[str, Any]:
        """
        Assemble the context dict sent to the LLM.
        Contains only non-sensitive fields.
        STATUS_EXTENDED is included but must be scrubbed by the LLM stage.
        """
        ai = self.representative.to_ai_lane()
        ai["instance_count"] = self.instance_count
        ai["affected_account_names"] = self.affected_account_names
        ai["likelihood_rating"] = self.likelihood_rating
        return ai


# ── ProcessWarning ────────────────────────────────────────────────────

@dataclass
class ProcessWarning:
    code:       str
    message:    str
    check_id:   Optional[str] = None
    finding_id: Optional[str] = None


# ── ProcessResult ─────────────────────────────────────────────────────

@dataclass
class ProcessResult:
    """
    Output of Stage 2.

    all_findings:   Complete list of CanonicalFindings (INCLUDED + EXCLUDED).
                    This is what gets written to canonical JSON.
    output_groups:  Deduplicated, grouped findings ready for LLM enrichment.
                    One OutputGroup per distinct check_id in the working set.
    warnings:       Non-fatal issues encountered during processing.
    config:         The config dict used — recorded in the run manifest.
    """
    run_id:         str
    all_findings:   list[CanonicalFinding]
    output_groups:  list[OutputGroup]
    warnings:       list[ProcessWarning]
    config:         dict[str, Any]

    # Counts (convenience — derived from all_findings)
    @property
    def total_findings(self) -> int:
        return len(self.all_findings)

    @property
    def included_count(self) -> int:
        return sum(
            1 for f in self.all_findings
            if f.report_inclusion == ReportInclusion.INCLUDED
            and not f.is_duplicate
        )

    @property
    def excluded_count(self) -> int:
        # Only non-duplicate excluded findings.
        # Duplicates are always EXCLUDED too but counted separately.
        return sum(
            1 for f in self.all_findings
            if f.report_inclusion == ReportInclusion.EXCLUDED
            and not f.is_duplicate
        )

    @property
    def duplicate_count(self) -> int:
        return sum(1 for f in self.all_findings if f.is_duplicate)

    @property
    def group_count(self) -> int:
        return len(self.output_groups)


# ── 2A: Status filter ─────────────────────────────────────────────────

def _apply_status_filter(
    findings: list[CanonicalFinding],
    include_statuses: list[str],
    warnings: list[ProcessWarning],
) -> None:
    """
    Mark findings whose scanner_status is NOT in include_statuses as EXCLUDED.
    Mutates findings in-place — exclusions are recorded in each finding's audit trail.
    The finding is never deleted; it remains in all_findings for canonical JSON.
    """
    include_set = set(include_statuses)

    for f in findings:
        status_val = f.scanner_status.value
        if status_val not in include_set:
            f.set_report_inclusion(
                ReportInclusion.EXCLUDED,
                stage="stage2_status_filter",
                reason=(
                    f"scanner_status '{status_val}' not in "
                    f"include_statuses {include_statuses}"
                ),
            )

    included = sum(1 for f in findings if f.report_inclusion == ReportInclusion.INCLUDED)
    excluded = sum(1 for f in findings if f.report_inclusion == ReportInclusion.EXCLUDED)
    logger.info(
        "2A status filter: %d included, %d excluded (statuses: %s)",
        included, excluded, include_statuses,
    )


# ── 2B: Deduplication ────────────────────────────────────────────────

def _apply_deduplication(
    findings: list[CanonicalFinding],
    warnings: list[ProcessWarning],
) -> None:
    """
    Resource-level deduplication within a single run.

    Uses the dedup_key already built by Stage 1 (type-stratified):
        - AWS resource:    account_uid + check_id + resource_id + region
        - IAM/global:      account_uid + check_id + resource_id + "global"
        - Account singleton: account_uid + check_id  (no resource)

    On collision: keep the first instance (highest row order), mark
    subsequent instances as duplicates. The duplicate is excluded from
    the output but preserved in all_findings for audit.

    Only operates on INCLUDED findings — already-excluded findings are
    skipped (no point deduplicating what's already excluded).
    """
    seen: dict[str, str] = {}  # dedup_key → finding_instance_id of primary

    for f in findings:
        # Skip already-excluded findings
        if f.report_inclusion != ReportInclusion.INCLUDED:
            continue

        key = f.dedup_key
        if not key:
            # No dedup key — cannot safely deduplicate; flag for review
            f.flag_for_review(
                reason="Empty dedup_key — cannot deduplicate safely",
                stage="stage2_dedup",
            )
            warnings.append(ProcessWarning(
                code="EMPTY_DEDUP_KEY",
                message=f"Finding {f.finding_instance_id} ({f.raw_check_id}) has an empty dedup_key.",
                check_id=f.raw_check_id,
                finding_id=f.finding_instance_id,
            ))
            continue

        if key in seen:
            # Duplicate — mark and exclude
            primary_id = seen[key]
            f.is_duplicate = True
            f.duplicate_of = primary_id
            f.set_report_inclusion(
                ReportInclusion.EXCLUDED,
                stage="stage2_dedup",
                reason=f"Duplicate of finding_instance_id={primary_id} (same dedup_key)",
            )
            f.add_audit(
                stage="stage2_dedup",
                field="is_duplicate",
                old_value=False,
                new_value=True,
                reason=f"dedup_key='{key}' already seen; primary={primary_id}",
            )
            logger.debug(
                "Duplicate: check_id=%s resource=%s → primary=%s",
                f.raw_check_id, f.resource_uid_normalised, primary_id,
            )
        else:
            seen[key] = f.finding_instance_id

    dup_count = sum(1 for f in findings if f.is_duplicate)
    logger.info("2B deduplication: %d duplicates marked and excluded", dup_count)


# ── 2C: Output grouping ───────────────────────────────────────────────

_SECTION_MAP: dict[str, str] = {
    # Provider-level
    "aws": "AWS",
    # Service-level overrides (if needed for ScubaGear Phase 2)
    # These are not used for Prowler/AWS — everything goes to "AWS"
}

def _assign_section(provider: Optional[str], service_name: Optional[str]) -> str:
    """
    Map a finding to its output Excel section.
    For Phase 1 (Prowler/AWS), all findings → "AWS".
    Phase 2 will add Azure section logic here.
    """
    prov = (provider or "").lower().strip()
    if prov == "aws":
        return "AWS"
    # Fallback
    return "AWS"


def _build_output_groups(
    findings: list[CanonicalFinding],
    warnings: list[ProcessWarning],
) -> list[OutputGroup]:
    """
    Group INCLUDED, non-duplicate findings by (check_id, output_section).
    Within each group, select the representative instance by completeness score.

    Returns a list of OutputGroup objects sorted by:
        1. output_section
        2. severity (critical → high → medium → low → informational)
        3. check_id (alphabetical within same severity)
    """
    # Only group findings that are INCLUDED and not duplicates
    working = [
        f for f in findings
        if f.report_inclusion == ReportInclusion.INCLUDED
        and not f.is_duplicate
    ]

    # Assign output section to each finding
    for f in working:
        section = _assign_section(f.raw_provider, f.raw_service_name)
        f.output_section = section
        f.add_audit(
            stage="stage2_grouping",
            field="output_section",
            old_value="",
            new_value=section,
            reason=f"provider='{f.raw_provider}' service='{f.raw_service_name}' → section='{section}'",
        )

    # Group by (check_id, output_section)
    groups: dict[str, list[CanonicalFinding]] = {}
    for f in working:
        check_id = f.raw_check_id or "unknown"
        section  = f.output_section
        key      = f"{check_id}:{section}"
        groups.setdefault(key, []).append(f)

    # Build OutputGroup objects
    output_groups: list[OutputGroup] = []
    for group_key, group_findings in groups.items():
        check_id = group_findings[0].raw_check_id or "unknown"
        section  = group_findings[0].output_section

        # Select representative: highest completeness score, first on tie
        representative = max(
            group_findings,
            key=lambda f: (f.completeness_score(), -int(f.source_row_id.split("Row:")[-1])
                           if "Row:" in f.source_row_id else 0),
        )

        # Collect aggregate values
        account_names: list[str] = []
        account_uids:  list[str] = []
        instance_ids:  list[str] = []
        for f in group_findings:
            instance_ids.append(f.finding_instance_id)
            name = f.raw_account_name or ""
            uid  = f.raw_account_uid  or ""
            if name and name not in account_names:
                account_names.append(name)
            if uid and uid not in account_uids:
                account_uids.append(uid)

        # Stamp representative with group aggregates
        representative.instance_count          = len(group_findings)
        representative.representative_instance_id = representative.finding_instance_id

        representative.add_audit(
            stage="stage2_grouping",
            field="instance_count",
            old_value=1,
            new_value=len(group_findings),
            reason=(
                f"Grouped {len(group_findings)} instance(s) of check_id='{check_id}' "
                f"into one output row"
            ),
        )

        group = OutputGroup(
            check_id=check_id,
            output_section=section,
            output_group_key=group_key,
            representative=representative,
            instance_ids=instance_ids,
            instance_count=len(group_findings),
            affected_account_names=account_names,
            affected_account_uids=account_uids,
        )
        output_groups.append(group)

        logger.debug(
            "Group '%s': %d instance(s), representative row=%s, accounts=%s",
            group_key, len(group_findings),
            representative.source_row_id,
            account_names,
        )

    # Sort groups: by section, then severity order, then check_id
    _SEV_ORDER = {
        "critical":      0,
        "high":          1,
        "medium":        2,
        "low":           3,
        "informational": 4,
        None:            5,
    }

    def _sort_key(g: OutputGroup) -> tuple:
        sev = (g.representative.raw_severity or "").lower()
        return (
            g.output_section,
            _SEV_ORDER.get(sev, 5),
            g.check_id,
        )

    output_groups.sort(key=_sort_key)

    logger.info(
        "2C grouping: %d output groups from %d working findings",
        len(output_groups), len(working),
    )
    return output_groups


# ── 2D: Likelihood rating ─────────────────────────────────────────────

def _compute_likelihood(
    finding: CanonicalFinding,
    severity_rules: dict[str, Any],
    stage: str = "stage2_likelihood",
) -> str:
    """
    Compute the Likelihood Rating for a finding.

    Priority:
        1. Category override: if any value in categories_list appears in
           likelihood_high_if_categories → always "High"
        2. Base mapping from [severity_rules] by SEVERITY value.
        3. Default to "Medium" if severity is unknown.

    Returns: "High" | "Medium" | "Low"
    Records the rule that matched in the finding's audit trail.
    """
    # Base mapping from severity
    sev = (finding.raw_severity or "").lower().strip()
    base_mapping = {
        "critical":      severity_rules.get("critical", "High"),
        "high":          severity_rules.get("high", "High"),
        "medium":        severity_rules.get("medium", "Medium"),
        "low":           severity_rules.get("low", "Low"),
        "informational": severity_rules.get("informational", "Low"),
    }
    base_likelihood = base_mapping.get(sev, "Medium")

    # Category overrides
    override_categories = severity_rules.get("likelihood_high_if_categories", [])
    triggered_overrides = [
        cat for cat in finding.categories_list
        if cat in override_categories
    ]

    if triggered_overrides:
        likelihood = "High"
        reason = (
            f"Category override: '{triggered_overrides[0]}' in categories_list "
            f"forces Likelihood=High (base was {base_likelihood} from severity='{sev}')"
        )
    else:
        likelihood = base_likelihood
        reason = f"Severity mapping: severity='{sev}' → Likelihood='{likelihood}'"

    finding.likelihood_rating = likelihood
    finding.add_audit(
        stage=stage,
        field="likelihood_rating",
        old_value=None,
        new_value=likelihood,
        reason=reason,
    )

    return likelihood


def _apply_likelihood_ratings(
    output_groups: list[OutputGroup],
    severity_rules: dict[str, Any],
    warnings: list[ProcessWarning],
) -> None:
    """
    Compute and assign likelihood_rating for every OutputGroup.
    Uses the representative finding's severity and categories.
    """
    for group in output_groups:
        likelihood = _compute_likelihood(
            finding=group.representative,
            severity_rules=severity_rules,
        )
        group.likelihood_rating = likelihood

    logger.info(
        "2D likelihood: assigned to %d groups", len(output_groups)
    )


# ── Main entry point ──────────────────────────────────────────────────

def process(
    ingest_result: IngestResult,
    config: dict[str, Any],
) -> ProcessResult:
    """
    Stage 2 entry point. Runs all sub-stages in order.

    Args:
        ingest_result:  Output of Stage 1 ingest().
        config:         Loaded config dict from load_config().

    Returns:
        ProcessResult with all_findings (canonical) and output_groups (for LLM).

    This function is deterministic: same inputs → same outputs every time.
    """
    warnings: list[ProcessWarning] = []
    findings  = ingest_result.findings  # mutated in-place

    proc_cfg     = config["processing"]
    sev_rules    = config["severity_rules"]
    include_statuses = proc_cfg.get("include_statuses", ["FAIL", "MUTED(FAIL)"])

    logger.info(
        "Stage 2: processing %d findings (run_id=%s)",
        len(findings), ingest_result.run_id,
    )

    # ── 2A: Status filter ──
    _apply_status_filter(findings, include_statuses, warnings)

    # ── 2B: Deduplication ──
    _apply_deduplication(findings, warnings)

    # ── 2C: Output grouping ──
    output_groups = _build_output_groups(findings, warnings)

    # ── 2D: Likelihood ratings ──
    _apply_likelihood_ratings(output_groups, sev_rules, warnings)

    # ── 2E: Warn on empty working set ──
    if not output_groups:
        warnings.append(ProcessWarning(
            code="EMPTY_OUTPUT",
            message=(
                "No output groups produced. Either all findings were excluded "
                f"(include_statuses={include_statuses}) or the input had no findings."
            ),
        ))
        logger.warning("Stage 2: no output groups produced")

    logger.info(
        "Stage 2 complete: %d groups, %d included, %d excluded, %d duplicates, %d warnings",
        len(output_groups),
        sum(1 for f in findings if f.report_inclusion == ReportInclusion.INCLUDED and not f.is_duplicate),
        sum(1 for f in findings if f.report_inclusion == ReportInclusion.EXCLUDED and not f.is_duplicate),
        sum(1 for f in findings if f.is_duplicate),
        len(warnings),
    )

    return ProcessResult(
        run_id=ingest_result.run_id,
        all_findings=findings,
        output_groups=output_groups,
        warnings=warnings,
        config=config,
    )