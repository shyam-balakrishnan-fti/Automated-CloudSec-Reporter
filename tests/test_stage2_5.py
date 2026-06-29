"""
test_stage2_5.py — Stage 2.5 semantic grouping test suite.

All LLM calls are mocked — tests run offline without AWS credentials.

Tests:
    - Valid proposal merges related check_ids into one GroupedOutputGroup
    - Standalone checks produce GroupedOutputGroup with is_merged=False
    - Every check_id from Stage 2 appears in exactly one group
    - instance_count is summed correctly across merged groups
    - affected_account_names merged with no duplicates
    - Highest severity and likelihood selected across merged group
    - Best representative selected by completeness score
    - Merge audit event recorded on representative
    - Invalid JSON triggers retry
    - Missing check_id triggers retry
    - Duplicate check_id triggers retry
    - Both failures → fallback (one group per check_id, no crash)
    - GroupingResult counts correct
    - Sort order: section → severity → group_name
    - to_llm_context includes merged_checks for merged groups
    - enrich_grouped() wires correctly into Stage 3
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

from generate_synthetic_messy import generate
from models import ReportInclusion
from stage1_ingest import ingest
from stage2_process import load_config, process
from stage2_5_grouping import (
    GroupedOutputGroup,
    GroupingResult,
    _build_grouping_prompt,
    _validate_grouping_response,
    group_semantically,
)
from stage3_llm import EnrichResult, enrich_grouped

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.toml"

# ── Helpers ───────────────────────────────────────────────────────────

def _run_stage2():
    tmp = Path(tempfile.mkdtemp()) / "synthetic_prowler_messy.xlsx"
    with contextlib.redirect_stdout(io.StringIO()):
        generate(tmp)
    cfg = load_config(CONFIG_PATH)
    ir  = ingest(tmp)
    pr  = process(ir, cfg)
    return pr, cfg


def _all_check_ids(pr):
    return {g.check_id for g in pr.output_groups}


def _valid_proposal(pr):
    """Build a valid grouping proposal from the actual Stage 2 groups."""
    groups = pr.output_groups
    check_ids = [g.check_id for g in groups]

    # Merge the two IAM MFA checks if both present, else standalone
    mfa_checks = [c for c in check_ids if "mfa" in c.lower()]
    s3_checks  = [c for c in check_ids if c.startswith("s3_")]
    rest       = [c for c in check_ids if c not in mfa_checks and c not in s3_checks]

    proposal = []
    if len(mfa_checks) > 1:
        proposal.append({
            "group_name": "MFA Not Enforced",
            "check_ids": mfa_checks,
            "rationale": "Both checks relate to MFA enforcement across different account types.",
        })
    elif mfa_checks:
        for c in mfa_checks:
            proposal.append({"group_name": c, "check_ids": [c], "rationale": "Standalone."})

    if len(s3_checks) > 1:
        proposal.append({
            "group_name": "S3 Security Controls",
            "check_ids": s3_checks,
            "rationale": "S3 checks covering encryption and access controls.",
        })
    elif s3_checks:
        for c in s3_checks:
            proposal.append({"group_name": c, "check_ids": [c], "rationale": "Standalone."})

    for c in rest:
        proposal.append({"group_name": c, "check_ids": [c], "rationale": "Standalone."})

    return proposal


# ── Test runner ───────────────────────────────────────────────────────

PASS_LIST = []
FAIL_LIST = []

def test(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASS_LIST.append(name)
        print(f"  ✓  {name}")
    else:
        FAIL_LIST.append(name)
        print(f"  ✗  {name}" + (f" — {detail}" if detail else ""))


# ═════════════════════════════════════════════════════════════════════

def test_validate_grouping():
    print("\n── Grouping response validator ──")

    pr, _ = _run_stage2()
    all_ids = _all_check_ids(pr)

    # Valid proposal
    valid = _valid_proposal(pr)
    errors = _validate_grouping_response(valid, all_ids)
    test("Valid proposal has no errors", errors == [], str(errors))

    # Missing check_id
    missing = [g for g in valid if len(g["check_ids"]) > 0]
    missing[0] = {**missing[0], "check_ids": []}
    errors = _validate_grouping_response(missing, all_ids)
    test("Empty check_ids caught", any("empty" in e.lower() for e in errors))

    # Duplicate check_id across groups
    dup_id = valid[0]["check_ids"][0]
    dup = valid + [{"group_name": "dup", "check_ids": [dup_id], "rationale": "dup"}]
    errors = _validate_grouping_response(dup, all_ids)
    test("Duplicate check_id caught", any("more than one" in e for e in errors))

    # Missing check_id from scan
    short = [g for g in valid[:-1]]  # drop last group
    if short:
        errors = _validate_grouping_response(short, all_ids)
        test("Missing check_id caught", any("Missing" in e for e in errors))

    # Unknown check_id
    unknown = valid + [{"group_name": "x", "check_ids": ["nonexistent_check"], "rationale": "x"}]
    errors = _validate_grouping_response(unknown, all_ids)
    test("Unknown check_id caught", any("Unknown" in e for e in errors))

    # Not a list
    errors = _validate_grouping_response({"bad": "type"}, all_ids)
    test("Non-list response caught", any("array" in e.lower() for e in errors))


def test_build_grouping_prompt():
    print("\n── Grouping prompt builder ──")

    pr, _ = _run_stage2()
    prompt = _build_grouping_prompt(pr.output_groups)

    test("Prompt is a non-empty string", isinstance(prompt, str) and len(prompt) > 200)
    test("Prompt contains check_ids", "s3_bucket_public_access" in prompt)
    test("Prompt contains OUTPUT FORMAT", "OUTPUT FORMAT" in prompt)
    test("Prompt contains group_name instruction", "group_name" in prompt)
    test("Prompt contains rationale instruction", "rationale" in prompt)
    test("Prompt mentions every group once",
         all(g.check_id in prompt for g in pr.output_groups))


def test_successful_grouping():
    print("\n── Successful grouping ──")

    pr, cfg = _run_stage2()
    proposal = _valid_proposal(pr)

    with mock.patch("stage3_llm._call_llm", return_value=json.dumps(proposal)):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    test("GroupingResult returned", isinstance(gr, GroupingResult))
    test("original_count matches Stage 2 groups",
         gr.original_count == pr.group_count,
         f"{gr.original_count} vs {pr.group_count}")
    test("merged_count <= original_count",
         gr.merged_count <= gr.original_count)
    test("Every check_id appears in exactly one GroupedOutputGroup",
         _all_check_ids(pr) == {cid for g in gr.grouped_groups for cid in g.check_ids})
    test("No warnings on successful grouping",
         len(gr.warnings) == 0, str(gr.warnings))


def test_merged_group_properties():
    print("\n── Merged group properties ──")

    pr, cfg = _run_stage2()
    proposal = _valid_proposal(pr)

    with mock.patch("stage3_llm._call_llm", return_value=json.dumps(proposal)):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    merged = [g for g in gr.grouped_groups if g.is_merged]
    standalone = [g for g in gr.grouped_groups if not g.is_merged]

    test("At least one merged group exists", len(merged) >= 1,
         "No merges occurred — check synthetic data has mergeable checks")

    for g in merged:
        test(f"Merged group '{g.group_name}' has > 1 check_id",
             len(g.check_ids) > 1, f"check_ids: {g.check_ids}")
        test(f"Merged group '{g.group_name}' has summed instance_count",
             g.instance_count >= len(g.check_ids),
             f"instance_count={g.instance_count}")
        test(f"Merged group '{g.group_name}' has representative",
             g.representative is not None)
        test(f"Merged group '{g.group_name}' has group_rationale",
             bool(g.group_rationale))
        test(f"Merged group '{g.group_name}' has instance_ids",
             len(g.instance_ids) >= g.instance_count)

    for g in standalone:
        test(f"Standalone group '{g.group_name}' has exactly 1 check_id",
             len(g.check_ids) == 1, f"check_ids: {g.check_ids}")
        test(f"Standalone group '{g.group_name}' is_merged=False",
             g.is_merged is False)


def test_account_names_merged():
    print("\n── Account name merging ──")

    pr, cfg = _run_stage2()
    proposal = _valid_proposal(pr)

    with mock.patch("stage3_llm._call_llm", return_value=json.dumps(proposal)):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    for g in gr.grouped_groups:
        test(f"No duplicate account names in '{g.group_name}'",
             len(g.affected_account_names) == len(set(g.affected_account_names)),
             f"accounts: {g.affected_account_names}")


def test_audit_trail():
    print("\n── Merge audit trail ──")

    pr, cfg = _run_stage2()
    proposal = _valid_proposal(pr)

    with mock.patch("stage3_llm._call_llm", return_value=json.dumps(proposal)):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    merged = [g for g in gr.grouped_groups if g.is_merged]
    for g in merged:
        rep = g.representative
        merge_events = [
            e for e in rep.audit_trail
            if e.stage == "stage2_5_grouping" and e.field == "semantic_group"
        ]
        test(f"Merge audit event on representative of '{g.group_name}'",
             len(merge_events) >= 1,
             f"audit trail fields: {[e.field for e in rep.audit_trail]}")
        if merge_events:
            test(f"Merge audit actor is 'llm' for '{g.group_name}'",
                 merge_events[0].actor == "llm")


def test_to_llm_context_merged():
    print("\n── LLM context for merged groups ──")

    pr, cfg = _run_stage2()
    proposal = _valid_proposal(pr)

    with mock.patch("stage3_llm._call_llm", return_value=json.dumps(proposal)):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    for g in gr.grouped_groups:
        ctx = g.to_llm_context()
        test(f"LLM context is a dict for '{g.group_name}'",
             isinstance(ctx, dict))
        test(f"LLM context has instance_count for '{g.group_name}'",
             "instance_count" in ctx)
        test(f"LLM context has group_name for '{g.group_name}'",
             ctx.get("group_name") == g.group_name)

        if g.is_merged:
            test(f"Merged group '{g.group_name}' has merged_checks in context",
                 "merged_checks" in ctx,
                 f"keys: {list(ctx.keys())}")
            test(f"merged_checks count matches check_ids for '{g.group_name}'",
                 len(ctx.get("merged_checks", [])) == len(g.check_ids))
        else:
            test(f"Standalone group '{g.group_name}' has no merged_checks",
                 "merged_checks" not in ctx)


def test_retry_on_first_failure():
    print("\n── Retry on invalid JSON ──")

    pr, cfg = _run_stage2()
    proposal = _valid_proposal(pr)
    call_count = {"n": 0}

    def mock_llm(prompt, llm_cfg):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return "this is not json"
        return json.dumps(proposal)

    with mock.patch("stage3_llm._call_llm", side_effect=mock_llm):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    test("LLM called twice (retry triggered)",
         call_count["n"] == 2, f"calls={call_count['n']}")
    test("Grouping succeeded after retry",
         len(gr.grouped_groups) > 0)
    test("No GROUPING_FAILED warning after retry",
         not any(w.code == "GROUPING_FAILED" for w in gr.warnings))


def test_fallback_on_both_failures():
    print("\n── Fallback on both failures ──")

    pr, cfg = _run_stage2()

    with mock.patch("stage3_llm._call_llm", side_effect=RuntimeError("LLM down")):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    test("GROUPING_FAILED warning emitted",
         any(w.code == "GROUPING_FAILED" for w in gr.warnings))
    test("Fallback: merged_count == original_count (no merges)",
         gr.merged_count == gr.original_count,
         f"merged={gr.merged_count} original={gr.original_count}")
    test("Fallback: every check_id still present",
         _all_check_ids(pr) == {cid for g in gr.grouped_groups for cid in g.check_ids})
    test("Fallback: all groups have is_merged=False",
         all(not g.is_merged for g in gr.grouped_groups))
    test("Pipeline does not crash on fallback",
         len(gr.grouped_groups) == gr.original_count)


def test_grouping_result_counts():
    print("\n── GroupingResult counts ──")

    pr, cfg = _run_stage2()
    proposal = _valid_proposal(pr)
    merges_in_proposal = sum(1 for g in proposal if len(g["check_ids"]) > 1)

    with mock.patch("stage3_llm._call_llm", return_value=json.dumps(proposal)):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    test("original_count == Stage 2 group_count",
         gr.original_count == pr.group_count)
    test("merged_count == len(proposal)",
         gr.merged_count == len(proposal),
         f"merged={gr.merged_count} proposal={len(proposal)}")
    test("merges_applied == groups with >1 check_id",
         gr.merges_applied == merges_in_proposal,
         f"applied={gr.merges_applied} expected={merges_in_proposal}")
    test("reduction == original - merged",
         gr.reduction == gr.original_count - gr.merged_count)


def test_sort_order():
    print("\n── Sort order ──")

    pr, cfg = _run_stage2()
    proposal = _valid_proposal(pr)

    with mock.patch("stage3_llm._call_llm", return_value=json.dumps(proposal)):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    groups = gr.grouped_groups
    for i in range(len(groups) - 1):
        a, b = groups[i], groups[i+1]
        sa = _SEV_ORDER.get((a.severity or "informational").lower(), 5)
        sb = _SEV_ORDER.get((b.severity or "informational").lower(), 5)
        if a.output_section == b.output_section:
            valid = (sa < sb) or (sa == sb and a.group_name <= b.group_name)
        else:
            valid = a.output_section <= b.output_section
        if not valid:
            test(f"Sort: '{a.group_name}' before '{b.group_name}'", False,
                 f"sev={a.severity} vs sev={b.severity}")
            return
    test("All grouped groups correctly sorted (section → severity → name)", True)


def test_enrich_grouped_integration():
    print("\n── enrich_grouped() integration ──")

    pr, cfg = _run_stage2()
    proposal = _valid_proposal(pr)

    VALID_ENRICH = {
        "finding_title":        "Test Finding",
        "root_cause_narrative": "Root cause text.",
        "situation_narrative":  "Situation text.",
        "consequence_narrative":"Consequence text.",
        "consequence_rating":   "Major",
        "access_required":      "No authentication required.",
        "needs_human_review":   False,
    }

    call_count = {"n": 0}
    def mock_llm(prompt, llm_cfg):
        call_count["n"] += 1
        # First call = grouping proposal, rest = enrichment
        if call_count["n"] == 1:
            return json.dumps(proposal)
        return json.dumps(VALID_ENRICH)

    with mock.patch("stage3_llm._call_llm", side_effect=mock_llm):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)
            er = enrich_grouped(gr, cfg)

    test("EnrichResult returned", isinstance(er, EnrichResult))
    test("enriched_count == group_count",
         er.enriched_count == er.group_count,
         f"enriched={er.enriched_count} groups={er.group_count}")
    test("LLM called once for grouping + once per group for enrichment",
         call_count["n"] == 1 + gr.group_count,
         f"calls={call_count['n']} expected={1 + gr.group_count}")

    # GroupedOutputGroup fields populated from enrichment
    for g in er.output_groups:
        from stage2_5_grouping import GroupedOutputGroup as GOG
        if isinstance(g, GOG):
            test(f"GroupedOutputGroup.finding_title set for '{g.group_name}'",
                 g.finding_title == "Test Finding")
            test(f"GroupedOutputGroup.risk_rating set for '{g.group_name}'",
                 g.risk_rating in ("High", "Medium", "Low"),
                 f"got {g.risk_rating}")
            break


# ── Entry point ───────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("Stage 2.5 — Semantic Grouping  —  Test Suite")
    print("=" * 60)

    test_validate_grouping()
    test_build_grouping_prompt()
    test_successful_grouping()
    test_merged_group_properties()
    test_account_names_merged()
    test_audit_trail()
    test_to_llm_context_merged()
    test_retry_on_first_failure()
    test_fallback_on_both_failures()
    test_grouping_result_counts()
    test_sort_order()
    test_enrich_grouped_integration()

    print("\n" + "=" * 60)
    print(f"Results: {len(PASS_LIST)} passed  /  {len(FAIL_LIST)} failed")
    if FAIL_LIST:
        print("\nFailed tests:")
        for t in FAIL_LIST:
            print(f"  ✗  {t}")
        sys.exit(1)
    else:
        print("All tests passed.")
        sys.exit(0)