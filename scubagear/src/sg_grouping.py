"""
sg_grouping.py — Stage 2.5: LLM-driven semantic grouping for ScubaGear

Architecture is identical to stage2_5_grouping.py (chunked + auto-consolidated).
Key M365-specific differences:
  - Sort key uses service_prefix (MS.AAD, MS.DEFENDER, ...) instead of
    categories_list + service_name, since ScubaGear has no categories column.
    Controls within the same service cluster naturally before the LLM runs.
  - Merge criteria are tightened for M365: controls should only merge when
    they share the SAME service AND root cause. Cross-service merges (e.g.
    "all authentication gaps") must not happen — each M365 service has a
    distinct team and remediation path.
  - instance_count is tenant-level, not per-resource, so resource-level
    context is replaced with tenant-level scope in the group data.

This module knows nothing about narrative enrichment — sg_grouping only
proposes WHICH controls belong together. sg_enrich runs after approval.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from sg_models import ScubaFinding, SECTION_ORDER
from sg_process import OutputGroup, ProcessResult

logger = logging.getLogger(__name__)

# ── Tunables ──────────────────────────────────────────────────────────

DEFAULT_CHUNK_SIZE = 15
MAX_CHUNK_SIZE     = 20
MIN_CHUNK_SIZE     = 8

# ── Severity ordering ─────────────────────────────────────────────────

_SEV_ORDER        = {"high": 0, "medium": 1, "low": 2}
_LIKELIHOOD_ORDER = {"High": 0, "Medium": 1, "Low": 2}
_SECTION_ORDER    = {s: i for i, s in enumerate(SECTION_ORDER)}


# ── GroupedOutputGroup ─────────────────────────────────────────────────

@dataclass
class GroupedOutputGroup:
    """
    One semantically merged group — one row in the final report.
    May represent one control_id (standalone) or multiple that share a root cause.
    """
    group_name:      str
    group_rationale: str
    output_section:  str
    is_merged:       bool

    check_ids:       list[str]          = field(default_factory=list)
    representative:  Optional[ScubaFinding] = None
    instance_ids:    list[str]          = field(default_factory=list)
    instance_count:  int                = 1
    affected_tenant_ids: list[str]      = field(default_factory=list)
    severity:        Optional[str]      = None
    likelihood_rating: Optional[str]    = None
    source_groups:   list[OutputGroup]  = field(default_factory=list)

    # Enrichment output (set by sg_enrich after analyst approval)
    risk_rating:           Optional[str] = None
    consequence_rating:    Optional[str] = None
    finding_title:         Optional[str] = None
    root_cause_narrative:  Optional[str] = None
    situation_narrative:   Optional[str] = None
    consequence_narrative: Optional[str] = None
    access_required:       Optional[str] = None

    def to_llm_context(self) -> dict[str, Any]:
        """Full context dict for sg_enrich enrichment (runs after approval)."""
        if not self.source_groups:
            return {}
        ctx = self.representative.to_ai_lane()
        ctx["instance_count"]          = self.instance_count
        ctx["affected_account_names"]  = self.affected_tenant_ids
        ctx["likelihood_rating"]       = self.likelihood_rating
        ctx["group_name"]              = self.group_name
        ctx["group_rationale"]         = self.group_rationale
        if self.is_merged:
            ctx["merged_controls"] = [
                {
                    "control_id":    g.check_id,
                    "check_title":   g.representative.check_title,
                    "instance_count": g.instance_count,
                    "severity":      g.severity,
                }
                for g in self.source_groups
            ]
        return ctx

    def affected_resources(self) -> list[dict[str, str]]:
        """
        Tenant-level context for the review UI. ScubaGear has no per-resource
        ARNs — returns one entry per source control with its Details text.
        """
        resources: list[dict[str, str]] = []
        seen: set[str] = set()
        for sg in self.source_groups:
            f = sg.representative
            detail = f.raw_details or ""
            if not detail or detail in seen:
                continue
            seen.add(detail)
            resources.append({
                "resource":      f.control_id,
                "resource_name": f.check_title[:80] if f.check_title else "",
                "resource_type": f.service_name,
                "account_name":  f.tenant_id or "",
                "account_uid":   f.tenant_id or "",
                "region":        "global",
                "check_id":      sg.check_id,
            })
        return resources


# ── Result types ──────────────────────────────────────────────────────

@dataclass
class GroupingWarning:
    code:    str
    message: str


@dataclass
class GroupingResult:
    run_id:         str
    grouped_groups: list[GroupedOutputGroup]
    all_findings:   list[ScubaFinding]
    warnings:       list[GroupingWarning]
    config:         dict[str, Any]
    original_count: int  = 0
    merged_count:   int  = 0
    merges_applied: int  = 0
    chunks_used:    int  = 0
    consolidation_applied: bool = False

    @property
    def group_count(self) -> int:
        return len(self.grouped_groups)

    @property
    def reduction(self) -> int:
        return self.original_count - self.merged_count


# ── Representative selection helpers ─────────────────────────────────

def _highest_severity(groups: list[OutputGroup]) -> str:
    sevs = [(g.severity or "low").lower() for g in groups]
    return min(sevs, key=lambda s: _SEV_ORDER.get(s, 5))


def _highest_likelihood(groups: list[OutputGroup]) -> str:
    likelihoods = [g.likelihood_rating or "Low" for g in groups]
    return min(likelihoods, key=lambda l: _LIKELIHOOD_ORDER.get(l, 3))


def _best_representative(groups: list[OutputGroup]) -> ScubaFinding:
    candidates = [g.representative for g in groups]
    return max(
        candidates,
        key=lambda f: (
            f.completeness_score(),
            -_SEV_ORDER.get((f.severity or "low").lower(), 5),
        ),
    )


# ── Sorting: service_prefix before chunking ───────────────────────────

def _sort_key_for_chunking(g: OutputGroup) -> tuple:
    """
    Primary: section order (groups same-service controls together).
    Secondary: severity (most severe first within each section).
    Tertiary: control_id for determinism.
    This maximises same-chunk clustering for same-service controls,
    which is where merges are both valid and useful for M365.
    """
    section_idx = _SECTION_ORDER.get(g.output_section, 99)
    sev_idx     = _SEV_ORDER.get((g.severity or "low").lower(), 5)
    return (section_idx, sev_idx, g.check_id)


def _sort_for_chunking(groups: list[OutputGroup]) -> list[OutputGroup]:
    return sorted(groups, key=_sort_key_for_chunking)


def _chunk_size_for(total: int) -> int:
    if total <= MAX_CHUNK_SIZE:
        return total
    return DEFAULT_CHUNK_SIZE


def _make_chunks(groups: list[OutputGroup], chunk_size: int) -> list[list[OutputGroup]]:
    return [groups[i:i + chunk_size] for i in range(0, len(groups), chunk_size)]


# ── Token/timeout scaling (copied from stage2_5_grouping.py) ─────────

def _scaled_llm_cfg(llm_cfg: dict[str, Any], n_items: int, mode: str = "chunk") -> dict[str, Any]:
    cfg = dict(llm_cfg)
    if mode == "regroup":
        cfg["max_tokens"] = max(
            llm_cfg.get("max_tokens", 1000),
            min(800 + (n_items * 80), 8000),
        )
        cfg["timeout_seconds"] = max(
            llm_cfg.get("timeout_seconds", 60),
            90 + (n_items * 3),
        )
    else:
        cfg["max_tokens"] = max(
            llm_cfg.get("max_tokens", 1000),
            min(300 + (n_items * 90), 4000),
        )
        cfg["timeout_seconds"] = max(
            llm_cfg.get("timeout_seconds", 60),
            60 + (n_items * 3),
        )
    return cfg


# ── JSON extraction ───────────────────────────────────────────────────

def _extract_json(raw: str) -> Any:
    text = raw.strip()
    if text.startswith("```"):
        lines = [l for l in text.split("\n") if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("[")
    end   = text.rfind("]") + 1
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass
    raise json.JSONDecodeError("No valid JSON array found", text, 0)


# ── Response validation ───────────────────────────────────────────────

def _validate_chunk_response(data: Any, expected_check_ids: set[str]) -> list[str]:
    errors = []
    if not isinstance(data, list):
        return [f"Expected JSON array, got {type(data).__name__}"]
    if not data:
        return ["Empty array — at least one group required"]

    seen: set[str] = set()
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            errors.append(f"Group {i}: expected object")
            continue
        if not item.get("group_name"):
            errors.append(f"Group {i}: missing group_name")
        if not isinstance(item.get("check_ids"), list) or not item["check_ids"]:
            errors.append(f"Group {i}: missing or empty check_ids")
            continue
        if not item.get("rationale"):
            errors.append(f"Group {i}: missing rationale")
        for cid in item["check_ids"]:
            if cid in seen:
                errors.append(f"check_id '{cid}' appears in more than one group")
            seen.add(cid)

    missing = expected_check_ids - seen
    if missing:
        errors.append(f"Missing check_ids: {sorted(missing)}")
    unknown = seen - expected_check_ids
    if unknown:
        errors.append(f"Unknown check_ids (not in this chunk): {sorted(unknown)}")
    return errors


# ── Chunk prompt (M365-specific merge criteria) ───────────────────────

def _build_chunk_prompt(
    chunk: list[OutputGroup],
    chunk_num: int,
    total_chunks: int,
    existing_group_names: list[str],
) -> str:
    check_list = "\n".join(
        f'{i+1:3}. [{g.check_id}] {g.representative.check_title or g.check_id}'
        f' (severity={g.severity}, service={g.representative.service_name},'
        f' criticality={g.representative.criticality_raw})'
        for i, g in enumerate(chunk)
    )

    existing_block = ""
    if existing_group_names:
        existing_block = (
            "\n=== GROUPS ALREADY PROPOSED IN EARLIER CHUNKS ===\n"
            "If a control below clearly belongs to an existing theme, "
            "REUSE the exact group name rather than creating a near-duplicate:\n"
            + "\n".join(f"  - {n}" for n in existing_group_names) + "\n"
        )

    return f"""You are a Microsoft 365 security analyst preparing a security assessment report.

This is chunk {chunk_num} of {total_chunks}. Identify which of the CISA SCuBA baseline
controls below should be MERGED into a single report finding because they share the
same root cause, attack vector, or remediation theme.
{existing_block}
=== CONTROLS IN THIS CHUNK ===
{check_list}

=== MERGE CRITERIA (apply strictly) ===
Only merge controls into one group when ALL of the following are true:
  a) They affect the SAME M365 service (e.g. all MS.AAD checks, or all
     MS.EXCHANGE checks). Do NOT merge controls across different services
     even if they share a broad theme like "authentication gaps" — each
     service has a separate remediation team and different admin steps.
  b) They share the SAME root cause (e.g. both result from missing
     Conditional Access policy, or both from a disabled security default).
  c) A single engineer could remediate all of them in one session following
     the same admin steps in the same M365 admin portal.

Controls that merely share a theme but differ in service, admin portal,
or responsible team MUST stay separate.

=== INSTRUCTIONS ===
1. Apply the merge criteria above. When in doubt, keep controls separate.
2. Every check_id in this chunk must appear in exactly one group.
3. Name groups specifically — include the service and control theme
   (e.g. "Entra ID MFA Policy Gaps", not "Authentication Issues").
4. Provide a rationale of AT LEAST 2 sentences per group explaining the
   shared root cause and why one narrative can accurately cover all controls.

=== OUTPUT FORMAT ===
Respond with ONLY a valid JSON array. No preamble, no explanation.

[
  {{
    "group_name": "Concise, specific M365 finding name (max 80 chars)",
    "check_ids": ["control_id_1", "control_id_2"],
    "rationale": "Two or more sentences explaining the shared root cause."
  }}
]"""


def _build_chunk_correction_prompt(
    original_prompt: str,
    bad_response: str,
    errors: list[str],
    expected_ids: list[str],
) -> str:
    return f"""{original_prompt}

=== CORRECTION REQUIRED ===
{chr(10).join(f'- {e}' for e in errors)}

All check_ids that MUST appear in your response: {json.dumps(expected_ids)}

Previous response (first 400 chars): {bad_response[:400]}

Respond again with ONLY a valid JSON array. Every check_id must appear exactly once."""


# ── Consolidation prompt (M365-specific) ─────────────────────────────

def _build_consolidation_prompt(proposals: list[dict]) -> str:
    group_list = "\n".join(
        f'{i+1:3}. "{p["group_name"]}" — check_ids={p["check_ids"]} — {p.get("rationale","")[:150]}'
        for i, p in enumerate(proposals)
    )
    return f"""You are a Microsoft 365 security analyst doing a final consistency pass on
proposed security finding groups from separate chunks.

=== CURRENT GROUPS ===
{group_list}

=== MERGE CRITERIA (conservative — when in doubt, do NOT merge) ===
Only merge two groups if ALL of the following are true:
  a) They affect the EXACT same M365 service. Do NOT merge across services
     (e.g. MS.AAD and MS.EXCHANGE must stay separate — different admin
     portals, different teams, different remediation paths).
  b) The specific remediation action is the same or nearly the same.
  c) They were almost certainly split by the chunking boundary — not because
     they are genuinely distinct controls.

The bar for merging is HIGH. A shorter report is not automatically better.

=== INSTRUCTIONS ===
1. Apply the criteria conservatively. Most groups should be UNCHANGED.
2. Only merge groups that are clear same-service, same-fix duplicates.
3. Every check_id from every input group must appear in exactly one output group.
4. For any merged group, write a new rationale (2+ sentences).
   For unchanged groups, copy the original rationale exactly.

=== OUTPUT FORMAT ===
Respond with ONLY a valid JSON array.

[
  {{"group_name": "...", "check_ids": [...], "rationale": "..."}}
]"""


def _build_consolidation_correction_prompt(
    original_prompt: str,
    bad_response: str,
    errors: list[str],
    expected_ids: list[str],
) -> str:
    return f"""{original_prompt}

=== CORRECTION REQUIRED ===
{chr(10).join(f'- {e}' for e in errors)}

All check_ids that MUST appear exactly once: {json.dumps(expected_ids)}

Previous response (first 400 chars): {bad_response[:400]}

Respond again with ONLY a valid JSON array."""


# ── Chunk runner ──────────────────────────────────────────────────────

def _run_one_chunk(
    chunk: list[OutputGroup],
    chunk_num: int,
    total_chunks: int,
    existing_group_names: list[str],
    llm_cfg: dict[str, Any],
    warnings: list[GroupingWarning],
) -> list[dict]:
    from sg_enrich import _call_llm

    expected_ids = {g.check_id for g in chunk}
    scaled_cfg   = _scaled_llm_cfg(llm_cfg, len(chunk))
    prompt       = _build_chunk_prompt(chunk, chunk_num, total_chunks, existing_group_names)

    raw_response = None
    parsed       = None
    errors: list[str] = []

    try:
        raw_response = _call_llm(prompt, scaled_cfg)
        if not raw_response or not raw_response.strip():
            raise ValueError("LLM returned empty response")
        parsed = _extract_json(raw_response)
        errors = _validate_chunk_response(parsed, expected_ids)
    except Exception as e:
        errors = [f"{type(e).__name__}: {e}"]

    if errors:
        try:
            correction   = _build_chunk_correction_prompt(prompt, str(raw_response or ""), errors, sorted(expected_ids))
            raw_response = _call_llm(correction, scaled_cfg)
            if not raw_response or not raw_response.strip():
                raise ValueError("LLM returned empty response")
            parsed = _extract_json(raw_response)
            errors = _validate_chunk_response(parsed, expected_ids)
        except Exception as e:
            errors = [f"{type(e).__name__}: {e}"]

    if errors or parsed is None:
        warnings.append(GroupingWarning(
            code="CHUNK_GROUPING_FAILED",
            message=(
                f"Chunk {chunk_num}/{total_chunks} failed after retry: "
                f"{'; '.join(errors)}. Checks in this chunk fall back to standalone groups."
            ),
        ))
        return [
            {
                "group_name": g.representative.check_title or g.check_id,
                "check_ids":  [g.check_id],
                "rationale":  "Standalone — chunk grouping call failed, no merge attempted.",
            }
            for g in chunk
        ]

    return parsed


# ── Consolidation runner ──────────────────────────────────────────────

def _run_consolidation_pass(
    proposals: list[dict],
    llm_cfg: dict[str, Any],
    warnings: list[GroupingWarning],
) -> tuple[list[dict], bool]:
    from sg_enrich import _call_llm

    if len(proposals) <= 1:
        return proposals, True

    expected_ids = {cid for p in proposals for cid in p["check_ids"]}
    scaled_cfg   = _scaled_llm_cfg(llm_cfg, len(proposals))
    prompt       = _build_consolidation_prompt(proposals)

    raw_response = None
    parsed       = None
    errors: list[str] = []

    try:
        raw_response = _call_llm(prompt, scaled_cfg)
        if not raw_response or not raw_response.strip():
            raise ValueError("LLM returned empty response")
        parsed = _extract_json(raw_response)
        errors = _validate_chunk_response(parsed, expected_ids)
    except Exception as e:
        errors = [f"{type(e).__name__}: {e}"]

    if errors:
        try:
            correction   = _build_consolidation_correction_prompt(prompt, str(raw_response or ""), errors, sorted(expected_ids))
            raw_response = _call_llm(correction, scaled_cfg)
            if not raw_response or not raw_response.strip():
                raise ValueError("LLM returned empty response")
            parsed = _extract_json(raw_response)
            errors = _validate_chunk_response(parsed, expected_ids)
        except Exception as e:
            errors = [f"{type(e).__name__}: {e}"]

    if errors or parsed is None:
        warnings.append(GroupingWarning(
            code="CONSOLIDATION_FAILED",
            message=(
                f"Consolidation pass failed: {'; '.join(errors)}. "
                f"Using chunked proposals without cross-chunk merging."
            ),
        ))
        return proposals, False

    return parsed, True


# ── Build GroupedOutputGroup objects ──────────────────────────────────

def _build_merged_group(
    proposal: dict[str, Any],
    groups_by_check_id: dict[str, OutputGroup],
) -> Optional[GroupedOutputGroup]:
    check_ids     = proposal["check_ids"]
    source_groups = [groups_by_check_id[cid] for cid in check_ids if cid in groups_by_check_id]
    if not source_groups:
        return None

    is_merged = len(source_groups) > 1

    all_instance_ids:    list[str] = []
    all_tenant_ids:      list[str] = []
    total_instances = 0

    for g in source_groups:
        all_instance_ids.extend(g.instance_ids)
        total_instances += g.instance_count
        for tid in g.affected_tenant_ids:
            if tid not in all_tenant_ids:
                all_tenant_ids.append(tid)

    rep        = _best_representative(source_groups)
    severity   = _highest_severity(source_groups)
    likelihood = _highest_likelihood(source_groups)
    section    = source_groups[0].output_section if source_groups else "Azure Resources"

    rep.instance_count    = total_instances
    rep.likelihood_rating = likelihood

    if is_merged:
        rep.add_audit(
            stage="sg_grouping", field="semantic_group",
            old_value=", ".join(check_ids), new_value=proposal["group_name"],
            reason=f"LLM semantic merge: {proposal.get('rationale', '')}",
            actor="llm",
        )

    rep.add_audit(
        stage="sg_grouping", field="likelihood_rating",
        old_value=rep.likelihood_rating, new_value=likelihood,
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
        affected_tenant_ids=all_tenant_ids,
        severity=severity,
        likelihood_rating=likelihood,
        source_groups=source_groups,
    )


def _sort_grouped_groups(groups: list[GroupedOutputGroup]) -> list[GroupedOutputGroup]:
    return sorted(
        groups,
        key=lambda g: (
            _SECTION_ORDER.get(g.output_section, 99),
            _SEV_ORDER.get((g.severity or "low").lower(), 5),
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

    1. Sort by section (service) + severity
    2. Sequential chunking with running group-name list
    3. Automatic consolidation pass
    4. Build final GroupedOutputGroup objects

    Never raises — LLM failures degrade to standalone groups.
    """
    llm_cfg  = config.get("llm", {})
    warnings: list[GroupingWarning] = []
    groups   = process_result.output_groups
    original_count = len(groups)

    if not groups:
        return GroupingResult(
            run_id=process_result.run_id, grouped_groups=[],
            all_findings=process_result.all_findings, warnings=warnings,
            config=config, original_count=0, merged_count=0,
        )

    groups_by_check_id = {g.check_id: g for g in groups}
    sorted_groups      = _sort_for_chunking(groups)
    chunk_size         = _chunk_size_for(len(sorted_groups))
    chunks             = _make_chunks(sorted_groups, chunk_size)

    print(
        f"\n[ Stage 2.5 ] Semantic grouping — {original_count} controls, "
        f"{len(chunks)} chunk(s) of ~{chunk_size}",
        flush=True,
    )

    all_proposals: list[dict] = []
    running_group_names: list[str] = []

    for i, chunk in enumerate(chunks, 1):
        print(f"  [chunk {i}/{len(chunks)}] {len(chunk)} controls...", flush=True)
        chunk_proposals = _run_one_chunk(
            chunk, i, len(chunks), running_group_names, llm_cfg, warnings,
        )
        all_proposals.extend(chunk_proposals)
        for p in chunk_proposals:
            name = p.get("group_name", "")
            if name and name not in running_group_names:
                running_group_names.append(name)
        print(f"    → {len(chunk_proposals)} group(s) proposed", flush=True)

    print(
        f"  [consolidation] checking {len(all_proposals)} proposed groups "
        f"for cross-chunk overlap...",
        flush=True,
    )
    consolidated, consolidation_ok = _run_consolidation_pass(all_proposals, llm_cfg, warnings)
    if consolidation_ok:
        reduction = len(all_proposals) - len(consolidated)
        if reduction > 0:
            print(
                f"    ✓ Consolidation merged {reduction} duplicate(s): "
                f"{len(all_proposals)} → {len(consolidated)} groups",
                flush=True,
            )
        else:
            print(f"    ✓ No cross-chunk duplicates found", flush=True)
    else:
        print(f"    ⚠ Consolidation pass failed — using un-consolidated proposals", flush=True)

    grouped: list[GroupedOutputGroup] = []
    merges_applied = 0

    for proposal in consolidated:
        built = _build_merged_group(proposal, groups_by_check_id)
        if built is None:
            continue
        grouped.append(built)
        if built.is_merged:
            merges_applied += 1

    grouped = _sort_grouped_groups(grouped)
    merged_count = len(grouped)

    print(
        f"\n  ✓ Grouping complete: {original_count} controls → "
        f"{merged_count} groups ({merges_applied} merge(s), "
        f"{len(chunks)} chunk(s), consolidation={'ok' if consolidation_ok else 'skipped'})",
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
        chunks_used=len(chunks),
        consolidation_applied=consolidation_ok,
    )