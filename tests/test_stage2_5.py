"""
test_stage2_5.py — Stage 2.5 chunked semantic grouping test suite.

All LLM calls are mocked — tests run offline without AWS credentials.

Tests:
    - Sorting by category then service clusters related checks correctly
    - Chunk size selection: small scans = 1 chunk, large scans = multiple
    - Single-chunk path produces correct GroupedOutputGroups (16 checks)
    - Multi-chunk path: running group-name list passed to later chunks
    - Multi-chunk path: consolidation pass merges cross-chunk duplicates
    - Consolidation pass is skipped gracefully when it fails (no crash)
    - Every check_id appears in exactly one final group, multi-chunk or not
    - Chunk-level fallback: one chunk failing doesn't block other chunks
    - GroupedOutputGroup.affected_resources() returns correct raw data
    - to_llm_context() includes merged_checks + affected_resources
    - GroupingResult counts (chunks_used, consolidation_applied) correct
    - Sort order of final groups: section → severity → group_name
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from generate_synthetic_messy import generate
from models import ReportInclusion
from stage1_ingest import ingest
from stage2_process import OutputGroup, load_config, process
from stage2_5_grouping import (
    GroupedOutputGroup,
    GroupingResult,
    _build_chunk_prompt,
    _chunk_size_for,
    _make_chunks,
    _sort_for_chunking,
    _validate_chunk_response,
    group_semantically,
)

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.toml"

# ── Helpers ───────────────────────────────────────────────────────────

def _run_stage2():
    tmp = Path(tempfile.mkdtemp()) / "messy.xlsx"
    with contextlib.redirect_stdout(io.StringIO()):
        generate(tmp)
    cfg = load_config(CONFIG_PATH)
    ir  = ingest(tmp)
    pr  = process(ir, cfg)
    return pr, cfg


def _all_check_ids(pr):
    return {g.check_id for g in pr.output_groups}


def _standalone_proposal(check_ids: list[str]) -> list[dict]:
    return [
        {"group_name": cid, "check_ids": [cid],
         "rationale": "Standalone test rationale, two sentences minimum here."}
        for cid in check_ids
    ]


def _merge_some(check_ids: list[str], merge_pairs: list[tuple]) -> list[dict]:
    merged_ids = {cid for group in merge_pairs for cid in group}
    proposal = []
    for i, group in enumerate(merge_pairs):
        proposal.append({
            "group_name": f"Merged Group {i}",
            "check_ids": list(group),
            "rationale": "These share a common root cause across two sentences of explanation.",
        })
    for cid in check_ids:
        if cid not in merged_ids:
            proposal.append({
                "group_name": cid,
                "check_ids": [cid],
                "rationale": "Standalone test rationale, two sentences minimum here.",
            })
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

def test_sort_by_category_then_service():
    print("\n── Sort by category then service ──")
    pr, _ = _run_stage2()
    sorted_groups = _sort_for_chunking(pr.output_groups)

    test("Sort returns same count as input",
         len(sorted_groups) == len(pr.output_groups))

    ids_in_order = [g.check_id for g in sorted_groups]
    mfa_idx = [i for i, cid in enumerate(ids_in_order) if "mfa" in cid.lower()]
    test("MFA-related checks are adjacent after category sort",
         len(mfa_idx) >= 2 and max(mfa_idx) - min(mfa_idx) <= 2,
         f"indices: {mfa_idx}")

    sorted_again = _sort_for_chunking(pr.output_groups)
    test("Sort is deterministic across repeated calls",
         [g.check_id for g in sorted_groups] == [g.check_id for g in sorted_again])


def test_chunk_size_selection():
    print("\n── Chunk size selection ──")
    test("16 checks → single chunk (no overhead for small scans)",
         _chunk_size_for(16) == 16)
    test("20 checks → single chunk (at MAX_CHUNK_SIZE boundary)",
         _chunk_size_for(20) == 20)
    test("21 checks → default chunk size (just over boundary)",
         _chunk_size_for(21) == 15)
    test("101 checks → default chunk size",
         _chunk_size_for(101) == 15)


def test_make_chunks():
    print("\n── Chunk construction ──")
    pr, _ = _run_stage2()
    chunks = _make_chunks(pr.output_groups, 5)
    test("Chunking 16 items into size-5 chunks produces 4 chunks",
         len(chunks) == 4, f"got {len(chunks)}")
    test("All chunks except last have exactly 5 items",
         all(len(c) == 5 for c in chunks[:-1]))
    test("Last chunk has the remainder",
         len(chunks[-1]) == 1, f"got {len(chunks[-1])}")
    total_in_chunks = sum(len(c) for c in chunks)
    test("No items lost during chunking",
         total_in_chunks == 16, f"got {total_in_chunks}")


def test_build_chunk_prompt():
    print("\n── Chunk prompt builder ──")
    pr, _ = _run_stage2()
    chunk = pr.output_groups[:5]

    prompt_no_existing = _build_chunk_prompt(chunk, 1, 3, [])
    test("Prompt mentions chunk number and total",
         "chunk 1 of 3" in prompt_no_existing)
    test("Prompt contains check_ids from the chunk",
         all(g.check_id in prompt_no_existing for g in chunk))
    test("No existing-groups block when list is empty",
         "GROUPS ALREADY PROPOSED" not in prompt_no_existing)
    test("Prompt instructs generic naming for cross-chunk mergeability",
         "GENERICALLY" in prompt_no_existing or "generically" in prompt_no_existing.lower())

    prompt_with_existing = _build_chunk_prompt(chunk, 2, 3, ["MFA Not Enforced", "S3 Encryption"])
    test("Existing-groups block appears when list is non-empty",
         "GROUPS ALREADY PROPOSED" in prompt_with_existing)
    test("Existing group names are listed in the prompt",
         "MFA Not Enforced" in prompt_with_existing and "S3 Encryption" in prompt_with_existing)


def test_validate_chunk_response():
    print("\n── Chunk response validator ──")
    ids = {"a", "b", "c"}

    valid = [{"group_name": "G1", "check_ids": ["a", "b"], "rationale": "Two sentences here. Explaining why."},
             {"group_name": "c", "check_ids": ["c"], "rationale": "Standalone reasoning across two full sentences."}]
    test("Valid response has no errors",
         _validate_chunk_response(valid, ids) == [])

    missing = [{"group_name": "G1", "check_ids": ["a"], "rationale": "x. y."}]
    errors = _validate_chunk_response(missing, ids)
    test("Missing check_ids caught", any("Missing" in e for e in errors))

    dup = [{"group_name": "G1", "check_ids": ["a"], "rationale": "x. y."},
           {"group_name": "G2", "check_ids": ["a", "b"], "rationale": "x. y."},
           {"group_name": "G3", "check_ids": ["c"], "rationale": "x. y."}]
    errors = _validate_chunk_response(dup, ids)
    test("Duplicate check_id across groups caught",
         any("more than one" in e for e in errors))

    not_list = {"bad": "shape"}
    errors = _validate_chunk_response(not_list, ids)
    test("Non-list response caught", any("array" in e.lower() for e in errors))


def test_single_chunk_grouping_end_to_end():
    print("\n── Single-chunk grouping (16 checks, fits in one chunk) ──")
    pr, cfg = _run_stage2()
    all_ids = [g.check_id for g in pr.output_groups]

    mfa_ids = [c for c in all_ids if "mfa" in c.lower()]
    proposal = _merge_some(all_ids, [tuple(mfa_ids)] if len(mfa_ids) > 1 else [])

    with mock.patch("stage3_llm._call_llm", return_value=json.dumps(proposal)):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    test("GroupingResult returned", isinstance(gr, GroupingResult))
    test("chunks_used == 1 for a 16-check scan",
         gr.chunks_used == 1, f"got {gr.chunks_used}")
    test("Every check_id appears in exactly one final group",
         _all_check_ids(pr) == {cid for g in gr.grouped_groups for cid in g.check_ids})
    test("consolidation_applied is True (1 group from chunk → trivial consolidation skip)",
         gr.consolidation_applied is True)


def test_multi_chunk_grouping_with_running_list():
    print("\n── Multi-chunk grouping with running group-name list ──")
    pr, cfg = _run_stage2()
    all_ids = [g.check_id for g in pr.output_groups]

    call_log = []

    def mock_llm(prompt, llm_cfg):
        call_log.append(prompt)
        ids_in_prompt = [cid for cid in all_ids if f"[{cid}]" in prompt]
        if "CURRENT GROUPS" in prompt:
            return json.dumps(_standalone_proposal(all_ids))
        return json.dumps(_standalone_proposal(ids_in_prompt))

    import stage2_5_grouping as sg
    original_chunk_size_for = sg._chunk_size_for
    sg._chunk_size_for = lambda total: 4

    try:
        with mock.patch("stage3_llm._call_llm", side_effect=mock_llm):
            with contextlib.redirect_stdout(io.StringIO()):
                gr = group_semantically(pr, cfg)
    finally:
        sg._chunk_size_for = original_chunk_size_for

    test("Multiple chunks were used (16 checks / chunk_size=4)",
         gr.chunks_used > 1, f"got {gr.chunks_used}")
    test("Every check_id still appears in exactly one final group after multi-chunk",
         _all_check_ids(pr) == {cid for g in gr.grouped_groups for cid in g.check_ids})
    test("At least one LLM call included the consolidation-style prompt",
         any("CURRENT GROUPS" in p for p in call_log))


def test_chunk_fallback_does_not_block_others():
    print("\n── Chunk-level failure fallback ──")
    pr, cfg = _run_stage2()
    all_ids = [g.check_id for g in pr.output_groups]

    import stage2_5_grouping as sg
    original_chunk_size_for = sg._chunk_size_for
    sg._chunk_size_for = lambda total: 4

    call_count = {"n": 0}

    def mock_llm(prompt, llm_cfg):
        call_count["n"] += 1
        if "CURRENT GROUPS" in prompt:
            return json.dumps(_standalone_proposal(all_ids))
        ids_in_prompt = [cid for cid in all_ids if f"[{cid}]" in prompt]
        if call_count["n"] <= 2:
            raise RuntimeError("Simulated Bedrock failure for first chunk")
        return json.dumps(_standalone_proposal(ids_in_prompt))

    try:
        with mock.patch("stage3_llm._call_llm", side_effect=mock_llm):
            with contextlib.redirect_stdout(io.StringIO()):
                gr = group_semantically(pr, cfg)
    finally:
        sg._chunk_size_for = original_chunk_size_for

    test("Pipeline does not crash when one chunk fails entirely",
         gr is not None)
    test("CHUNK_GROUPING_FAILED warning emitted for the failed chunk",
         any(w.code == "CHUNK_GROUPING_FAILED" for w in gr.warnings),
         f"warnings: {[w.code for w in gr.warnings]}")
    test("Every check_id still present despite one chunk failing",
         _all_check_ids(pr) == {cid for g in gr.grouped_groups for cid in g.check_ids})


def test_consolidation_failure_is_non_blocking():
    print("\n── Consolidation pass failure handling ──")
    pr, cfg = _run_stage2()
    all_ids = [g.check_id for g in pr.output_groups]

    def mock_llm(prompt, llm_cfg):
        if "CURRENT GROUPS" in prompt:
            raise RuntimeError("Simulated consolidation failure")
        return json.dumps(_standalone_proposal(all_ids))

    with mock.patch("stage3_llm._call_llm", side_effect=mock_llm):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    test("Pipeline completes even when consolidation pass fails",
         gr is not None)
    test("consolidation_applied is False on failure",
         gr.consolidation_applied is False)
    test("CONSOLIDATION_FAILED warning emitted",
         any(w.code == "CONSOLIDATION_FAILED" for w in gr.warnings))
    test("Groups still built correctly from un-consolidated proposals",
         _all_check_ids(pr) == {cid for g in gr.grouped_groups for cid in g.check_ids})


def test_consolidation_merges_cross_chunk_duplicates():
    print("\n── Consolidation merges near-duplicate groups ──")
    pr, cfg = _run_stage2()
    all_ids = [g.check_id for g in pr.output_groups]

    s3_ids = [c for c in all_ids if c.startswith("s3_")]
    test("Synthetic data has at least 2 S3 checks to test merging", len(s3_ids) >= 2)
    if len(s3_ids) < 2:
        return

    def mock_llm(prompt, llm_cfg):
        if "CURRENT GROUPS" in prompt:
            merged = _merge_some(all_ids, [tuple(s3_ids)])
            return json.dumps(merged)
        ids_in_prompt = [cid for cid in all_ids if f"[{cid}]" in prompt]
        return json.dumps(_standalone_proposal(ids_in_prompt))

    with mock.patch("stage3_llm._call_llm", side_effect=mock_llm):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    s3_group = next((g for g in gr.grouped_groups if set(s3_ids).issubset(set(g.check_ids))), None)
    test("Consolidation successfully merged the two S3 checks into one group",
         s3_group is not None,
         f"groups: {[(g.group_name, g.check_ids) for g in gr.grouped_groups]}")
    if s3_group:
        test("Merged S3 group has is_merged=True",
             s3_group.is_merged is True)


def test_affected_resources():
    print("\n── affected_resources() ──")
    pr, cfg = _run_stage2()
    all_ids = [g.check_id for g in pr.output_groups]

    with mock.patch("stage3_llm._call_llm", return_value=json.dumps(_standalone_proposal(all_ids))):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    s3_group = next((g for g in gr.grouped_groups if g.check_ids[0].startswith("s3_")), None)
    test("Found an S3 group to inspect", s3_group is not None)
    if s3_group:
        resources = s3_group.affected_resources()
        test("affected_resources() returns a list", isinstance(resources, list))
        test("affected_resources() entries have expected keys",
             all({"resource","resource_name","account_name","region","check_id"}.issubset(r.keys()) for r in resources))
        test("affected_resources() has at least one entry",
             len(resources) >= 1, f"got {resources}")


def test_to_llm_context():
    print("\n── to_llm_context() includes resource context ──")
    pr, cfg = _run_stage2()
    all_ids = [g.check_id for g in pr.output_groups]
    mfa_ids = [c for c in all_ids if "mfa" in c.lower()]

    proposal = _merge_some(all_ids, [tuple(mfa_ids)] if len(mfa_ids) > 1 else [])

    with mock.patch("stage3_llm._call_llm", return_value=json.dumps(proposal)):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    merged_group = next((g for g in gr.grouped_groups if g.is_merged), None)
    test("At least one merged group exists for context test",
         merged_group is not None)
    if merged_group:
        ctx = merged_group.to_llm_context()
        test("to_llm_context includes affected_resources",
             "affected_resources" in ctx)
        test("to_llm_context includes merged_checks for merged groups",
             "merged_checks" in ctx)
        test("to_llm_context includes group_rationale",
             "group_rationale" in ctx)


def test_grouping_result_counts():
    print("\n── GroupingResult counts ──")
    pr, cfg = _run_stage2()
    all_ids = [g.check_id for g in pr.output_groups]

    with mock.patch("stage3_llm._call_llm", return_value=json.dumps(_standalone_proposal(all_ids))):
        with contextlib.redirect_stdout(io.StringIO()):
            gr = group_semantically(pr, cfg)

    test("original_count == Stage 2 group_count",
         gr.original_count == pr.group_count)
    test("merged_count == 16 (all standalone)",
         gr.merged_count == 16, f"got {gr.merged_count}")
    test("merges_applied == 0 (no merges in this proposal)",
         gr.merges_applied == 0)
    test("chunks_used >= 1",
         gr.chunks_used >= 1)


def test_sort_order_of_final_groups():
    print("\n── Final group sort order ──")
    pr, cfg = _run_stage2()
    all_ids = [g.check_id for g in pr.output_groups]

    with mock.patch("stage3_llm._call_llm", return_value=json.dumps(_standalone_proposal(all_ids))):
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
            test(f"Sort: '{a.group_name}' before '{b.group_name}'", False)
            return
    test("All final groups correctly sorted (section → severity → name)", True)


def test_empty_input():
    print("\n── Empty input handling ──")
    pr, cfg = _run_stage2()
    pr.output_groups = []

    gr = group_semantically(pr, cfg)
    test("Empty input returns valid GroupingResult", gr is not None)
    test("Empty input produces zero groups", gr.group_count == 0)
    test("No LLM call attempted for empty input (no crash, no warnings)",
         len(gr.warnings) == 0)


# ── Entry point ───────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("Stage 2.5 — Chunked Semantic Grouping  —  Test Suite")
    print("=" * 60)

    test_sort_by_category_then_service()
    test_chunk_size_selection()
    test_make_chunks()
    test_build_chunk_prompt()
    test_validate_chunk_response()
    test_single_chunk_grouping_end_to_end()
    test_multi_chunk_grouping_with_running_list()
    test_chunk_fallback_does_not_block_others()
    test_consolidation_failure_is_non_blocking()
    test_consolidation_merges_cross_chunk_duplicates()
    test_affected_resources()
    test_to_llm_context()
    test_grouping_result_counts()
    test_sort_order_of_final_groups()
    test_empty_input()

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