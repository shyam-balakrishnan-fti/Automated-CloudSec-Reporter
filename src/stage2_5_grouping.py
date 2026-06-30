"""
stage2_5_grouping.py — Stage 2.5: LLM-driven semantic grouping

Sits between Stage 2 (deterministic processing) and Stage 3 (LLM enrichment).

ARCHITECTURE (chunked + auto-consolidated):

    1. Sort checks by categories_list (primary) then service_name (secondary)
       — checks sharing a theme (e.g. "internet-exposed") or a service
       (e.g. all S3 checks) cluster together before any LLM call happens.

    2. Split into sequential chunks (default ~15 checks/chunk). Each chunk
       call receives the running list of group names already proposed by
       earlier chunks, so it can re-use an existing group instead of
       creating a near-duplicate. This must run sequentially (not
       parallel) because each chunk depends on the previous chunk's
       output.

    3. AUTOMATIC consolidation pass — runs unconditionally after all
       chunks finish, with zero analyst involvement. Operates on the
       resulting N groups (typically 10-25), not the original full list,
       so it is small, fast, and has full simultaneous visibility across
       every group — exactly what individual chunks lack. This is the
       primary accuracy mechanism: chunking produces a fast first draft,
       consolidation produces a globally consistent result.

    4. Fallback: if a chunk's LLM call fails after retry, that chunk's
       checks become standalone groups — never blocks other chunks or
       crashes the run.

This module knows nothing about narrative enrichment — group_semantically()
only proposes WHICH checks belong together and WHY. Stage 3 (per-group
enrichment) happens after the analyst approves grouping in the review UI.
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

# ── Tunables ──────────────────────────────────────────────────────────

DEFAULT_CHUNK_SIZE = 15   # checks per chunking LLM call
MAX_CHUNK_SIZE     = 20
MIN_CHUNK_SIZE     = 8


# ── GroupedOutputGroup ────────────────────────────────────────────────

@dataclass
class GroupedOutputGroup:
    """
    A semantically merged output group — one row in the final report.

    May represent one check_id (ungrouped) or multiple check_ids that the
    LLM determined share the same root cause or attack vector.
    """
    group_name:         str
    group_rationale:    str
    output_section:     str
    is_merged:          bool

    check_ids:          list[str]     = field(default_factory=list)
    representative:     Optional[CanonicalFinding] = None
    instance_ids:       list[str]     = field(default_factory=list)
    instance_count:     int           = 1
    affected_account_names: list[str] = field(default_factory=list)
    affected_account_uids:  list[str] = field(default_factory=list)
    severity:           Optional[str] = None
    likelihood_rating:  Optional[str] = None
    source_groups:      list[OutputGroup] = field(default_factory=list)

    # Enrichment output (set by Stage 3, after analyst approves grouping)
    risk_rating:        Optional[str] = None
    consequence_rating: Optional[str] = None
    finding_title:      Optional[str] = None
    root_cause_narrative:  Optional[str] = None
    situation_narrative:   Optional[str] = None
    consequence_narrative: Optional[str] = None
    access_required:       Optional[str] = None

    def affected_resources(self) -> list[dict[str, str]]:
        """
        Resource-level context for this group — pulled directly from raw
        findings, zero LLM cost. This is what the review UI displays on
        every group card regardless of enrichment state.
        """
        resources: list[dict[str, str]] = []
        seen: set[str] = set()
        for sg in self.source_groups:
            for f in [sg.representative]:
                res = f.resource_uid_normalised or f.raw_resource_uid or f.raw_resource_name or ""
                if not res or res in seen:
                    continue
                seen.add(res)
                resources.append({
                    "resource":      res,
                    "resource_name": f.raw_resource_name or "",
                    "resource_type": f.raw_resource_type or "",
                    "account_name":  f.raw_account_name or "",
                    "account_uid":   f.raw_account_uid or "",
                    "region":        f.region_normalised or "",
                    "check_id":      sg.check_id,
                })
        return resources

    def to_llm_context(self) -> dict[str, Any]:
        """Assemble full context for Stage 3 enrichment (runs after approval)."""
        if not self.source_groups:
            return {}
        ctx = self.representative.to_ai_lane()
        ctx["instance_count"]         = self.instance_count
        ctx["affected_account_names"] = self.affected_account_names
        ctx["likelihood_rating"]      = self.likelihood_rating
        ctx["group_name"]             = self.group_name
        ctx["group_rationale"]        = self.group_rationale
        ctx["affected_resources"]     = self.affected_resources()
        if self.is_merged:
            ctx["merged_checks"] = [
                {
                    "check_id":       g.check_id,
                    "check_title":    g.representative.raw_check_title,
                    "instance_count": g.instance_count,
                    "severity":       g.representative.raw_severity,
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
    run_id:         str
    grouped_groups: list[GroupedOutputGroup]
    all_findings:   list[CanonicalFinding]
    warnings:       list[GroupingWarning]
    config:         dict[str, Any]
    original_count: int = 0
    merged_count:   int = 0
    merges_applied: int = 0
    chunks_used:    int = 0
    consolidation_applied: bool = False

    @property
    def group_count(self) -> int:
        return len(self.grouped_groups)

    @property
    def reduction(self) -> int:
        return self.original_count - self.merged_count


# ── Severity / likelihood helpers ──────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
_LIKELIHOOD_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _highest_severity(groups: list[OutputGroup]) -> str:
    severities = [(g.representative.raw_severity or "informational").lower() for g in groups]
    return min(severities, key=lambda s: _SEV_ORDER.get(s, 5))


def _highest_likelihood(groups: list[OutputGroup]) -> str:
    likelihoods = [g.likelihood_rating or "Low" for g in groups]
    return min(likelihoods, key=lambda l: _LIKELIHOOD_ORDER.get(l, 3))


def _best_representative(groups: list[OutputGroup]) -> CanonicalFinding:
    candidates = [g.representative for g in groups]
    return max(
        candidates,
        key=lambda f: (
            f.completeness_score(),
            -_SEV_ORDER.get((f.raw_severity or "informational").lower(), 5),
        ),
    )


# ── Sorting: category + service before chunking ────────────────────────

def _sort_key_for_chunking(g: OutputGroup) -> tuple:
    """
    Primary sort: first category alphabetically (groups by shared theme
    like 'internet-exposed', 'encryption', 'identity-management').
    Secondary sort: service_name (groups by AWS service as tiebreaker).
    Tertiary: check_id for determinism.

    This maximises same-chunk clustering for both same-theme and
    same-service checks BEFORE any LLM call happens — the cheapest and
    most reliable accuracy lever available.
    """
    cats = sorted(g.representative.categories_list or ["zzz_none"])
    primary_cat = cats[0] if cats else "zzz_none"
    service = (g.representative.raw_service_name or "zzz_none").lower()
    return (primary_cat, service, g.check_id)


def _sort_for_chunking(groups: list[OutputGroup]) -> list[OutputGroup]:
    return sorted(groups, key=_sort_key_for_chunking)


def _chunk_size_for(total: int) -> int:
    """Pick a chunk size that keeps each call comfortably within token/timeout limits."""
    if total <= MAX_CHUNK_SIZE:
        return total  # small scans: one chunk, no chunking overhead
    return DEFAULT_CHUNK_SIZE


def _make_chunks(groups: list[OutputGroup], chunk_size: int) -> list[list[OutputGroup]]:
    return [groups[i:i + chunk_size] for i in range(0, len(groups), chunk_size)]


# ── Token/timeout scaling (per individual LLM call, not the whole run) ──

def _scaled_llm_cfg(llm_cfg: dict[str, Any], n_items: int) -> dict[str, Any]:
    """
    Scale max_tokens and timeout_seconds for a single LLM call handling
    n_items (checks in a chunk, or groups in the consolidation pass).
    Kept deliberately conservative since each individual call is now
    small (<=20 items) regardless of total scan size.
    """
    cfg = dict(llm_cfg)
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
    raise json.JSONDecodeError("No valid JSON found in response", text, 0)


# ── Chunk-level prompt (sees running group list from earlier chunks) ───

def _build_chunk_prompt(
    chunk: list[OutputGroup],
    chunk_num: int,
    total_chunks: int,
    existing_group_names: list[str],
) -> str:
    check_list = "\n".join(
        f'{i+1:3}. [{g.check_id}] {g.representative.raw_check_title or g.check_id}'
        f' (severity={g.representative.raw_severity}, instances={g.instance_count}, '
        f'categories={g.representative.categories_list or []})'
        for i, g in enumerate(chunk)
    )

    existing_block = ""
    if existing_group_names:
        existing_block = (
            "\n=== GROUPS ALREADY PROPOSED IN EARLIER CHUNKS ===\n"
            "If any check below clearly belongs to one of these existing themes, "
            "REUSE the exact group name rather than creating a near-duplicate:\n"
            + "\n".join(f"  - {n}" for n in existing_group_names) + "\n"
        )

    return f"""You are a cloud security analyst preparing a security assessment report.

This is chunk {chunk_num} of {total_chunks} from a larger scan. Identify which of
the checks below should be MERGED into a single report entry because they share
the same root cause, attack vector, or remediation theme. Only merge when a
single narrative can accurately cover all of them.
{existing_block}
=== CHECKS IN THIS CHUNK ===
{check_list}

=== INSTRUCTIONS ===
1. Identify groups of check_ids that should appear as ONE finding in the report.
2. Every check_id in this chunk must appear in exactly one group.
3. Name groups GENERICALLY (e.g. "Public Network Exposure", not "S3 Public Access")
   so that if related checks appear in a different chunk, they can be merged
   into this same theme later — do not over-specify to just what you see here.
4. Provide a rationale of AT LEAST 2 sentences per group explaining the shared
   root cause and why grouping aids the reader. For standalone checks, explain
   why this issue is distinct enough to warrant its own line item.

=== OUTPUT FORMAT ===
Respond with ONLY a valid JSON array. No preamble, no explanation.

[
  {{
    "group_name": "Concise, generic finding name (max 80 chars)",
    "check_ids": ["check_id_1", "check_id_2"],
    "rationale": "Two or more sentences explaining the shared root cause."
  }}
]"""


def _build_chunk_correction_prompt(
    original_prompt: str, bad_response: str, errors: list[str], expected_ids: list[str],
) -> str:
    return f"""{original_prompt}

=== CORRECTION REQUIRED ===
Your previous response had these issues:
{chr(10).join(f'- {e}' for e in errors)}

All check_ids that MUST appear in your response: {json.dumps(expected_ids)}

Previous response (first 400 chars): {bad_response[:400]}

Respond again with ONLY a valid JSON array. Every check_id must appear exactly once."""


def _validate_chunk_response(data: Any, expected_check_ids: set[str]) -> list[str]:
    errors = []
    if not isinstance(data, list):
        return [f"Expected JSON array, got {type(data).__name__}"]
    if len(data) == 0:
        return ["Empty array — at least one group required"]

    seen: set[str] = set()
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            errors.append(f"Group {i}: expected object, got {type(item).__name__}")
            continue
        if not item.get("group_name"):
            errors.append(f"Group {i}: missing or empty 'group_name'")
        if not isinstance(item.get("check_ids"), list) or not item["check_ids"]:
            errors.append(f"Group {i}: missing or empty 'check_ids' array")
            continue
        if not item.get("rationale"):
            errors.append(f"Group {i}: missing or empty 'rationale'")
        for cid in item["check_ids"]:
            if cid in seen:
                errors.append(f"check_id '{cid}' appears in more than one group")
            seen.add(cid)

    missing = expected_check_ids - seen
    if missing:
        errors.append(f"Missing check_ids not assigned to any group: {sorted(missing)}")
    unknown = seen - expected_check_ids
    if unknown:
        errors.append(f"Unknown check_ids (not in this chunk): {sorted(unknown)}")
    return errors


def _run_one_chunk(
    chunk: list[OutputGroup],
    chunk_num: int,
    total_chunks: int,
    existing_group_names: list[str],
    llm_cfg: dict[str, Any],
    warnings: list[GroupingWarning],
) -> list[dict]:
    """
    Run one chunking LLM call. Returns a list of proposal dicts.
    On failure after retry: returns one standalone-group dict per check_id
    in this chunk — never raises, never blocks other chunks.
    """
    from stage3_llm import _call_llm

    expected_ids = {g.check_id for g in chunk}
    scaled_cfg   = _scaled_llm_cfg(llm_cfg, len(chunk))
    prompt       = _build_chunk_prompt(chunk, chunk_num, total_chunks, existing_group_names)

    raw_response = None
    parsed       = None
    errors: list[str] = []

    try:
        raw_response = _call_llm(prompt, scaled_cfg)
        if not raw_response or not raw_response.strip():
            raise ValueError("LLM returned an empty response")
        parsed = _extract_json(raw_response)
        errors = _validate_chunk_response(parsed, expected_ids)
    except Exception as e:
        errors = [f"{type(e).__name__}: {e}"]

    if errors:
        try:
            correction   = _build_chunk_correction_prompt(prompt, str(raw_response or ""), errors, sorted(expected_ids))
            raw_response = _call_llm(correction, scaled_cfg)
            if not raw_response or not raw_response.strip():
                raise ValueError("LLM returned an empty response")
            parsed = _extract_json(raw_response)
            errors = _validate_chunk_response(parsed, expected_ids)
        except Exception as e:
            errors = [f"{type(e).__name__}: {e}"]

    if errors or parsed is None:
        warnings.append(GroupingWarning(
            code="CHUNK_GROUPING_FAILED",
            message=(
                f"Chunk {chunk_num}/{total_chunks} failed after retry: "
                f"{'; '.join(errors)}. Checks in this chunk fall back to "
                f"standalone groups."
            ),
        ))
        return [
            {"group_name": g.representative.raw_check_title or g.check_id,
             "check_ids": [g.check_id],
             "rationale": "Standalone — chunk grouping call failed, no merge attempted."}
            for g in chunk
        ]

    return parsed


# ── Consolidation pass (automatic, full visibility, no analyst step) ──

def _build_consolidation_prompt(proposals: list[dict]) -> str:
    group_list = "\n".join(
        f'{i+1:3}. "{p["group_name"]}" — check_ids={p["check_ids"]} — {p.get("rationale","")[:150]}'
        for i, p in enumerate(proposals)
    )
    return f"""You are a cloud security analyst doing a final consistency pass on
proposed security finding groups. These groups were proposed independently
in separate batches and may contain near-duplicates or overlapping themes
that should be merged into one.

=== CURRENT GROUPS ===
{group_list}

=== INSTRUCTIONS ===
1. Identify any groups above that represent the SAME underlying theme and
   should be merged into one group (e.g. two separately-named groups that
   both cover public network exposure, or two groups that both cover
   encryption-at-rest gaps).
2. Do NOT merge groups that are genuinely distinct, even if superficially
   similar — only merge when one coherent narrative could cover both.
3. Every check_id from every input group must appear in exactly one output
   group. Preserve groups that have no merge candidate exactly as given.
4. For any group you merge, write a NEW rationale (2+ sentences) describing
   the combined theme. For unchanged groups, keep the original rationale.

=== OUTPUT FORMAT ===
Respond with ONLY a valid JSON array, same structure as input.

[
  {{"group_name": "...", "check_ids": [...], "rationale": "..."}}
]"""


def _build_consolidation_correction_prompt(
    original_prompt: str, bad_response: str, errors: list[str], expected_ids: list[str],
) -> str:
    return f"""{original_prompt}

=== CORRECTION REQUIRED ===
{chr(10).join(f'- {e}' for e in errors)}

All check_ids that MUST appear exactly once: {json.dumps(expected_ids)}

Previous response (first 400 chars): {bad_response[:400]}

Respond again with ONLY a valid JSON array."""


def _run_consolidation_pass(
    proposals: list[dict],
    llm_cfg: dict[str, Any],
    warnings: list[GroupingWarning],
) -> tuple[list[dict], bool]:
    """
    Runs automatically after all chunks finish — no analyst trigger needed.
    Operates on the N already-formed groups (not the original full check
    list), so it is fast and has full simultaneous visibility across every
    group, which individual chunks structurally cannot have.

    Returns (consolidated_proposals, applied_successfully).
    On failure: returns the original chunked proposals unchanged — the
    pipeline never blocks on this step.
    """
    from stage3_llm import _call_llm

    if len(proposals) <= 1:
        return proposals, True  # nothing to consolidate

    expected_ids = {cid for p in proposals for cid in p["check_ids"]}
    scaled_cfg   = _scaled_llm_cfg(llm_cfg, len(proposals))
    prompt       = _build_consolidation_prompt(proposals)

    raw_response = None
    parsed       = None
    errors: list[str] = []

    try:
        raw_response = _call_llm(prompt, scaled_cfg)
        if not raw_response or not raw_response.strip():
            raise ValueError("LLM returned an empty response")
        parsed = _extract_json(raw_response)
        errors = _validate_chunk_response(parsed, expected_ids)
    except Exception as e:
        errors = [f"{type(e).__name__}: {e}"]

    if errors:
        try:
            correction   = _build_consolidation_correction_prompt(prompt, str(raw_response or ""), errors, sorted(expected_ids))
            raw_response = _call_llm(correction, scaled_cfg)
            if not raw_response or not raw_response.strip():
                raise ValueError("LLM returned an empty response")
            parsed = _extract_json(raw_response)
            errors = _validate_chunk_response(parsed, expected_ids)
        except Exception as e:
            errors = [f"{type(e).__name__}: {e}"]

    if errors or parsed is None:
        warnings.append(GroupingWarning(
            code="CONSOLIDATION_FAILED",
            message=(
                f"Automatic consolidation pass failed: {'; '.join(errors)}. "
                f"Using chunked proposals without cross-chunk merging."
            ),
        ))
        return proposals, False

    return parsed, True


# ── Build final GroupedOutputGroup objects ─────────────────────────────

def _build_merged_group(
    proposal: dict[str, Any],
    groups_by_check_id: dict[str, OutputGroup],
) -> GroupedOutputGroup:
    check_ids     = proposal["check_ids"]
    source_groups = [groups_by_check_id[cid] for cid in check_ids if cid in groups_by_check_id]
    is_merged     = len(source_groups) > 1

    if not source_groups:
        # Defensive — should not happen given validation, but never crash
        return None

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

    rep.instance_count = total_instances
    rep.representative_instance_id = rep.finding_instance_id

    if is_merged:
        rep.add_audit(
            stage="stage2_5_grouping",
            field="semantic_group",
            old_value=", ".join(check_ids),
            new_value=proposal["group_name"],
            reason=f"LLM semantic merge: {proposal.get('rationale','')}",
            actor="llm",
        )

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


def _sort_grouped_groups(groups: list[GroupedOutputGroup]) -> list[GroupedOutputGroup]:
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

    1. Sort by category+service
    2. Sequential chunking with running group-name list
    3. Automatic consolidation pass across all resulting groups
    4. Build final GroupedOutputGroup objects

    Returns GroupingResult ready for the review UI. group_semantically()
    never raises — any LLM failure degrades to standalone groups for the
    affected checks, never blocking the rest of the pipeline.
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

    # ── Step 1: sort by category then service ────────────────────────
    sorted_groups = _sort_for_chunking(groups)

    # ── Step 2: sequential chunking with running group-name list ──────
    chunk_size = _chunk_size_for(len(sorted_groups))
    chunks     = _make_chunks(sorted_groups, chunk_size)

    print(
        f"\n[ Stage 2.5 ] Semantic grouping — {original_count} checks, "
        f"{len(chunks)} chunk(s) of ~{chunk_size}",
        flush=True,
    )

    all_proposals: list[dict] = []
    running_group_names: list[str] = []

    for i, chunk in enumerate(chunks, 1):
        print(f"  [chunk {i}/{len(chunks)}] {len(chunk)} checks...", flush=True)
        chunk_proposals = _run_one_chunk(
            chunk, i, len(chunks), running_group_names, llm_cfg, warnings,
        )
        all_proposals.extend(chunk_proposals)
        for p in chunk_proposals:
            name = p.get("group_name", "")
            if name and name not in running_group_names:
                running_group_names.append(name)
        print(f"    → {len(chunk_proposals)} group(s) proposed", flush=True)

    # ── Step 3: automatic consolidation pass (no analyst trigger) ─────
    print(
        f"  [consolidation] checking {len(all_proposals)} proposed groups "
        f"for cross-chunk overlap...",
        flush=True,
    )
    consolidated, consolidation_ok = _run_consolidation_pass(
        all_proposals, llm_cfg, warnings,
    )
    if consolidation_ok:
        reduction = len(all_proposals) - len(consolidated)
        if reduction > 0:
            print(
                f"    ✓ Consolidation merged {reduction} duplicate theme(s) "
                f"across chunks: {len(all_proposals)} → {len(consolidated)} groups",
                flush=True,
            )
        else:
            print(f"    ✓ No cross-chunk duplicates found", flush=True)
    else:
        print(f"    ⚠ Consolidation pass failed — using un-consolidated proposals", flush=True)

    # ── Step 4: build final GroupedOutputGroup objects ────────────────
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
        f"\n  ✓ Grouping complete: {original_count} checks → "
        f"{merged_count} groups ({merges_applied} merge(s) applied, "
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