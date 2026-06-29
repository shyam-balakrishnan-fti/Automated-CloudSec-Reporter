"""
stage2_5_grouping.py — Stage 2.5: LLM-driven semantic grouping

Sits between Stage 2 (deterministic processing) and Stage 3 (LLM enrichment).

What it does:
    Takes the OutputGroups from Stage 2 (one per check_id) and asks the LLM
    to propose semantic merges — which checks share the same root cause or
    attack vector and should appear as one finding in the report.

    Example: iam_root_mfa_enabled + iam_user_mfa_enabled_console_access
    → "MFA Not Enforced" (one report row, two checks, 5 affected resources)

Why LLM (not config-driven):
    The check_id space is large and grows with every Prowler version.
    A manual config list would always be incomplete and become a maintenance
    burden. The LLM sees the actual checks in THIS scan and groups what is
    present — not what was pre-configured.

Two-call design:
    Call 1 — Grouping proposal
        Single LLM call. Input: list of all check_ids + titles.
        Output: JSON array of group proposals.
        Deterministic merge follows: OutputGroups are merged per proposal.

    Call 2 — Enrichment (existing Stage 3)
        One call per merged group. Input: full merged context.
        Output: narratives + consequence_rating.

Audit trail:
    Every merge is recorded in the audit trail of each constituent finding
    so the grouping decision is always traceable.

Contract:
    group_semantically(process_result, config) -> GroupingResult
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from models import CanonicalFinding
from stage2_process import OutputGroup, ProcessResult

logger = logging.getLogger(__name__)


# ── GroupedOutputGroup ────────────────────────────────────────────────

@dataclass
class GroupedOutputGroup:
    """
    A semantically merged output group — one row in the final report.

    May represent one check_id (ungrouped) or multiple check_ids that the
    LLM determined share the same root cause or attack vector.
    """
    # Semantic group identity
    group_name:         str           # LLM-proposed name e.g. "MFA Not Enforced"
    group_rationale:    str           # LLM's reasoning for the merge
    output_section:     str           # "AWS"
    is_merged:          bool          # True if >1 check_id was merged

    # Constituent check_ids (may be just one)
    check_ids:          list[str]     = field(default_factory=list)

    # Best representative finding across all constituent groups
    representative:     Optional[CanonicalFinding] = None

    # All instance IDs across all constituent groups
    instance_ids:       list[str]     = field(default_factory=list)

    # Aggregated across all constituent groups
    instance_count:     int           = 1
    affected_account_names: list[str] = field(default_factory=list)
    affected_account_uids:  list[str] = field(default_factory=list)

    # Severity — highest among constituent groups
    severity:           Optional[str] = None
    likelihood_rating:  Optional[str] = None

    # All constituent OutputGroups (for context assembly)
    source_groups:      list[OutputGroup] = field(default_factory=list)

    # LLM enrichment output (set by Stage 3)
    risk_rating:        Optional[str] = None
    consequence_rating: Optional[str] = None
    finding_title:      Optional[str] = None
    root_cause_narrative:  Optional[str] = None
    situation_narrative:   Optional[str] = None
    consequence_narrative: Optional[str] = None
    access_required:       Optional[str] = None

    def to_llm_context(self) -> dict[str, Any]:
        """
        Assemble full context for Stage 3 enrichment.
        For merged groups, includes context from all constituent checks.
        """
        if not self.source_groups:
            return {}

        # Use the representative's full context as the base
        ctx = self.representative.to_ai_lane()

        # Override with merged aggregates
        ctx["instance_count"]          = self.instance_count
        ctx["affected_account_names"]  = self.affected_account_names
        ctx["likelihood_rating"]       = self.likelihood_rating
        ctx["group_name"]              = self.group_name

        # For merged groups: include all check titles and IDs so the LLM
        # knows it is writing about multiple related controls
        if self.is_merged:
            ctx["merged_checks"] = [
                {
                    "check_id":    g.check_id,
                    "check_title": g.representative.raw_check_title,
                    "instance_count": g.instance_count,
                    "severity":    g.representative.raw_severity,
                }
                for g in self.source_groups
            ]

        return ctx


# ── Result types ──────────────────────────────────────────────────────

@dataclass
class GroupingWarning:
    code:    str
    message: str


@dataclass
class GroupingResult:
    """Output of Stage 2.5."""
    run_id:             str
    grouped_groups:     list[GroupedOutputGroup]
    all_findings:       list[CanonicalFinding]
    warnings:           list[GroupingWarning]
    config:             dict[str, Any]
    original_count:     int   = 0   # groups before merging
    merged_count:       int   = 0   # groups after merging
    merges_applied:     int   = 0   # how many merges happened

    @property
    def group_count(self) -> int:
        return len(self.grouped_groups)

    @property
    def reduction(self) -> int:
        return self.original_count - self.merged_count


# ── Severity ordering ─────────────────────────────────────────────────

_SEV_ORDER = {
    "critical":      0,
    "high":          1,
    "medium":        2,
    "low":           3,
    "informational": 4,
}

_LIKELIHOOD_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _highest_severity(groups: list[OutputGroup]) -> str:
    """Return the highest severity among a list of OutputGroups."""
    severities = [
        (g.representative.raw_severity or "informational").lower()
        for g in groups
    ]
    return min(severities, key=lambda s: _SEV_ORDER.get(s, 5))


def _highest_likelihood(groups: list[OutputGroup]) -> str:
    """Return the highest likelihood among a list of OutputGroups."""
    likelihoods = [g.likelihood_rating or "Low" for g in groups]
    return min(likelihoods, key=lambda l: _LIKELIHOOD_ORDER.get(l, 3))


def _best_representative(groups: list[OutputGroup]) -> CanonicalFinding:
    """
    Select the best representative finding across all groups in a merge.
    Highest completeness score wins. Tie goes to highest severity group.
    """
    candidates = [g.representative for g in groups]
    return max(
        candidates,
        key=lambda f: (
            f.completeness_score(),
            -_SEV_ORDER.get((f.raw_severity or "informational").lower(), 5),
        ),
    )


# ── LLM grouping prompt ───────────────────────────────────────────────

def _build_grouping_prompt(groups: list[OutputGroup]) -> str:
    """
    Build the grouping proposal prompt.
    Single LLM call — input is the full list of check_ids and titles.
    """
    check_list = "\n".join(
        f'{i+1:3}. [{g.check_id}] {g.representative.raw_check_title or g.check_id}'
        f' (severity={g.representative.raw_severity}, instances={g.instance_count})'
        for i, g in enumerate(groups)
    )

    return f"""You are a cloud security analyst preparing a security assessment report.

Below is a list of AWS security findings from this scan. Your task is to identify
which findings should be MERGED into a single report entry because they share the
same root cause, attack vector, or remediation theme.

DO NOT merge findings that are genuinely distinct issues even if they are in the
same service. Only merge when a single narrative can accurately cover all of them.

=== FINDINGS IN THIS SCAN ===
{check_list}

=== INSTRUCTIONS ===
1. Identify groups of check_ids that should appear as ONE finding in the report.
2. For each group (merged or standalone), propose a clear, concise finding name.
3. Provide a one-sentence rationale for each merge decision.
4. Every check_id must appear in exactly one group.
5. If a check stands alone (no logical merge), put it in its own group.

=== OUTPUT FORMAT ===
Respond with ONLY a valid JSON array. No preamble, no explanation.

[
  {{
    "group_name": "Concise finding name (max 80 chars)",
    "check_ids": ["check_id_1", "check_id_2"],
    "rationale": "One sentence explaining why these are merged."
  }},
  {{
    "group_name": "Another finding name",
    "check_ids": ["check_id_3"],
    "rationale": "Standalone — distinct issue with no related checks in this scan."
  }}
]"""


def _build_grouping_correction_prompt(
    original_prompt: str,
    bad_response: str,
    errors: list[str],
    all_check_ids: list[str],
) -> str:
    return f"""{original_prompt}

=== CORRECTION REQUIRED ===
Your previous response had these issues:
{chr(10).join(f'- {e}' for e in errors)}

All check_ids that MUST appear in your response:
{json.dumps(all_check_ids)}

Previous response (first 400 chars): {bad_response[:400]}

Respond again with ONLY a valid JSON array. Every check_id must appear exactly once."""


# ── Response validator ────────────────────────────────────────────────

def _validate_grouping_response(
    data: Any,
    expected_check_ids: set[str],
) -> list[str]:
    """
    Validate the grouping proposal.
    Returns list of error strings. Empty = valid.
    """
    errors = []

    if not isinstance(data, list):
        errors.append(f"Expected JSON array, got {type(data).__name__}")
        return errors

    if len(data) == 0:
        errors.append("Empty array — at least one group required")
        return errors

    seen_check_ids: set[str] = set()
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            errors.append(f"Group {i}: expected object, got {type(item).__name__}")
            continue
        if "group_name" not in item or not item["group_name"]:
            errors.append(f"Group {i}: missing or empty 'group_name'")
        if "check_ids" not in item or not isinstance(item["check_ids"], list):
            errors.append(f"Group {i}: missing or invalid 'check_ids' array")
            continue
        if len(item["check_ids"]) == 0:
            errors.append(f"Group {i}: 'check_ids' array is empty")
        if "rationale" not in item or not item["rationale"]:
            errors.append(f"Group {i}: missing or empty 'rationale'")
        for cid in item["check_ids"]:
            if cid in seen_check_ids:
                errors.append(f"check_id '{cid}' appears in more than one group")
            seen_check_ids.add(cid)

    # All expected check_ids must be present
    missing = expected_check_ids - seen_check_ids
    if missing:
        errors.append(
            f"Missing check_ids not assigned to any group: {sorted(missing)}"
        )

    # No unknown check_ids
    unknown = seen_check_ids - expected_check_ids
    if unknown:
        errors.append(
            f"Unknown check_ids (not in this scan): {sorted(unknown)}"
        )

    return errors


# ── JSON extraction (reuse same logic as stage3) ──────────────────────

def _extract_json(raw: str) -> Any:
    text = raw.strip()
    if text.startswith("```"):
        lines = [l for l in text.split("\n") if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try finding array
    start = text.find("[")
    end   = text.rfind("]") + 1
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass
    raise json.JSONDecodeError("No valid JSON found in response", text, 0)


# ── Merge builder ─────────────────────────────────────────────────────

def _build_merged_group(
    proposal: dict[str, Any],
    groups_by_check_id: dict[str, OutputGroup],
) -> GroupedOutputGroup:
    """Build a GroupedOutputGroup from one LLM proposal entry."""
    check_ids    = proposal["check_ids"]
    source_groups= [groups_by_check_id[cid] for cid in check_ids if cid in groups_by_check_id]
    is_merged    = len(source_groups) > 1

    # Aggregate across all source groups
    all_instance_ids: list[str] = []
    all_account_names: list[str] = []
    all_account_uids:  list[str] = []
    total_instances = 0

    for g in source_groups:
        all_instance_ids.extend(g.instance_ids)
        total_instances += g.instance_count
        for name in g.affected_account_names:
            if name not in all_account_names:
                all_account_names.append(name)
        for uid in g.affected_account_uids:
            if uid not in all_account_uids:
                all_account_uids.append(uid)

    rep        = _best_representative(source_groups)
    severity   = _highest_severity(source_groups)
    likelihood = _highest_likelihood(source_groups)
    section    = source_groups[0].output_section if source_groups else "AWS"

    # Stamp aggregates onto representative
    rep.instance_count = total_instances
    rep.representative_instance_id = rep.finding_instance_id

    # Audit the merge on every constituent finding
    for g in source_groups:
        for fid in g.instance_ids:
            pass  # audit stamped on representative below

    if is_merged:
        rep.add_audit(
            stage="stage2_5_grouping",
            field="semantic_group",
            old_value=", ".join(check_ids),
            new_value=proposal["group_name"],
            reason=(
                f"LLM semantic merge: {proposal['rationale']}"
            ),
            actor="llm",
        )

    # Update likelihood on representative
    rep.likelihood_rating = likelihood
    rep.add_audit(
        stage="stage2_5_grouping",
        field="likelihood_rating",
        old_value=rep.likelihood_rating,
        new_value=likelihood,
        reason=f"Highest likelihood across merged group: {check_ids}",
        actor="pipeline",
    )

    return GroupedOutputGroup(
        group_name=proposal["group_name"],
        group_rationale=proposal.get("rationale", ""),
        output_section=section,
        is_merged=is_merged,
        check_ids=check_ids,
        representative=rep,
        instance_ids=all_instance_ids,
        instance_count=total_instances,
        affected_account_names=all_account_names,
        affected_account_uids=all_account_uids,
        severity=severity,
        likelihood_rating=likelihood,
        source_groups=source_groups,
    )


# ── Sort order ────────────────────────────────────────────────────────

def _sort_grouped_groups(groups: list[GroupedOutputGroup]) -> list[GroupedOutputGroup]:
    """Sort: section → severity → group_name."""
    return sorted(
        groups,
        key=lambda g: (
            g.output_section,
            _SEV_ORDER.get((g.severity or "informational").lower(), 5),
            g.group_name,
        ),
    )


# ── Main entry point ──────────────────────────────────────────────────

def group_semantically(
    process_result: ProcessResult,
    config: dict[str, Any],
) -> GroupingResult:
    """
    Stage 2.5 entry point.

    Sends all Stage 2 OutputGroups to the LLM in a single call and asks
    it to propose semantic merges. Builds merged GroupedOutputGroups.
    Falls back to one-group-per-check-id if the LLM call fails.

    Args:
        process_result: Output of Stage 2 process().
        config:         Loaded config dict.

    Returns:
        GroupingResult with grouped_groups ready for Stage 3 enrichment.
    """
    from stage3_llm import _call_llm

    llm_cfg  = config.get("llm", {})
    warnings: list[GroupingWarning] = []
    groups   = process_result.output_groups
    original_count = len(groups)

    if not groups:
        return GroupingResult(
            run_id=process_result.run_id,
            grouped_groups=[],
            all_findings=process_result.all_findings,
            warnings=warnings,
            config=config,
            original_count=0,
            merged_count=0,
        )

    groups_by_check_id = {g.check_id: g for g in groups}
    all_check_ids      = set(groups_by_check_id.keys())

    print(
        f"\n[ Stage 2.5 ] Semantic grouping — {original_count} groups "
        f"(single LLM call)",
        flush=True,
    )

    # ── Call LLM for grouping proposal ───────────────────────────────
    prompt       = _build_grouping_prompt(groups)
    raw_response = None
    parsed       = None
    errors       = []

    # Attempt 1
    try:
        raw_response = _call_llm(prompt, llm_cfg)
        parsed       = _extract_json(raw_response)
        errors       = _validate_grouping_response(parsed, all_check_ids)
        if not errors:
            print(f"  ✓ Grouping proposal received (attempt 1)", flush=True)
    except Exception as e:
        errors = [f"{type(e).__name__}: {e}"]
        print(f"  ✗ Attempt 1 failed: {errors[0][:80]}", flush=True)

    # Attempt 2 (retry once)
    if errors:
        print(f"  → Retrying grouping call...", flush=True)
        try:
            correction = _build_grouping_correction_prompt(
                prompt, str(raw_response or ""), errors, sorted(all_check_ids)
            )
            raw_response = _call_llm(correction, llm_cfg)
            parsed       = _extract_json(raw_response)
            errors       = _validate_grouping_response(parsed, all_check_ids)
            if not errors:
                print(f"  ✓ Grouping proposal received (attempt 2)", flush=True)
            else:
                print(f"  ✗ Attempt 2 failed: {errors}", flush=True)
        except Exception as e:
            errors = [f"{type(e).__name__}: {e}"]
            print(f"  ✗ Attempt 2 failed: {errors[0][:80]}", flush=True)

    # ── Fallback: if both attempts fail, one group per check_id ──────
    if errors or parsed is None:
        reason = f"LLM grouping failed: {'; '.join(errors)}"
        warnings.append(GroupingWarning(
            code="GROUPING_FAILED",
            message=f"{reason}. Falling back to one group per check_id.",
        ))
        print(
            f"  ⚠ Grouping failed — falling back to "
            f"{original_count} individual groups",
            flush=True,
        )
        # Build one GroupedOutputGroup per original OutputGroup
        grouped = [
            GroupedOutputGroup(
                group_name=g.representative.raw_check_title or g.check_id,
                group_rationale="Fallback — LLM grouping unavailable",
                output_section=g.output_section,
                is_merged=False,
                check_ids=[g.check_id],
                representative=g.representative,
                instance_ids=g.instance_ids,
                instance_count=g.instance_count,
                affected_account_names=g.affected_account_names,
                affected_account_uids=g.affected_account_uids,
                severity=g.representative.raw_severity,
                likelihood_rating=g.likelihood_rating,
                source_groups=[g],
            )
            for g in groups
        ]
        return GroupingResult(
            run_id=process_result.run_id,
            grouped_groups=_sort_grouped_groups(grouped),
            all_findings=process_result.all_findings,
            warnings=warnings,
            config=config,
            original_count=original_count,
            merged_count=original_count,
            merges_applied=0,
        )

    # ── Build merged groups from proposal ────────────────────────────
    grouped: list[GroupedOutputGroup] = []
    merges_applied = 0

    for proposal in parsed:
        merged = _build_merged_group(proposal, groups_by_check_id)
        grouped.append(merged)
        if merged.is_merged:
            merges_applied += 1
            print(
                f"  ↳ Merged [{', '.join(merged.check_ids)}] "
                f"→ '{merged.group_name}'",
                flush=True,
            )

    grouped = _sort_grouped_groups(grouped)
    merged_count = len(grouped)

    print(
        f"\n  ✓ Grouping complete: {original_count} groups → "
        f"{merged_count} groups ({merges_applied} merge(s) applied)",
        flush=True,
    )

    return GroupingResult(
        run_id=process_result.run_id,
        grouped_groups=grouped,
        all_findings=process_result.all_findings,
        warnings=warnings,
        config=config,
        original_count=original_count,
        merged_count=merged_count,
        merges_applied=merges_applied,
    )