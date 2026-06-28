"""
test_pipeline_full.py — Full pipeline test: Stage 1 + 2 + 3 on synthetic data.

Runs the complete pipeline against the messy synthetic dataset,
calls real Bedrock for LLM enrichment, and prints a detailed
report of every output group with all generated narratives.

Usage (from cloud-tool/):
    python3 src/test_pipeline_full.py

Prerequisites:
    export BEDROCK_API_KEY=your_key
    python3 src/generate_synthetic_messy.py   # if not already done

Outputs written to data/output/:
    canonical_findings.json
    output_groups.json
    enriched_groups.json
    run_manifest.json
    stage1_summary.txt
    stage2_summary.txt
    pipeline_test_report.txt   ← human-readable full report
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_synthetic_messy import generate
from models import ReportInclusion
from stage1_ingest import ingest
from stage2_process import load_config, process
from stage3_llm import EnrichResult, enrich

CONFIG_PATH  = Path(__file__).resolve().parent.parent / "config" / "config.toml"
SYNTHETIC    = Path(__file__).resolve().parent.parent / "data" / "synthetic" / "synthetic_prowler_messy.xlsx"
OUTPUT_DIR   = Path(__file__).resolve().parent.parent / "data" / "output"


# ── Helpers ───────────────────────────────────────────────────────────

def _finding_to_dict(f) -> dict:
    return {
        "finding_instance_id":      f.finding_instance_id,
        "stable_finding_key":       f.stable_finding_key,
        "dedup_key":                f.dedup_key,
        "source_row_id":            f.source_row_id,
        "run_id":                   f.run_id,
        "source_file_hash":         f.source_file_hash,
        "scanner_status":           f.scanner_status.value,
        "report_inclusion":         f.report_inclusion.value,
        "is_duplicate":             f.is_duplicate,
        "duplicate_of":             f.duplicate_of,
        "human_review_required":    f.human_review_required,
        "review_reason":            f.review_reason,
        "muted_reconciled":         f.muted_reconciled,
        "blank_description":        f.blank_description.value,
        "blank_risk":               f.blank_risk.value,
        "blank_remediation":        f.blank_remediation.value,
        "blank_region":             f.blank_region.value,
        "region_normalised":        f.region_normalised,
        "resource_uid_normalised":  f.resource_uid_normalised,
        "arn_fallback_used":        f.arn_fallback_used,
        "categories_list":          f.categories_list,
        "compliance_values":        f.compliance_values,
        "output_section":           f.output_section,
        "likelihood_rating":        f.likelihood_rating,
        "consequence_rating":       f.consequence_rating,
        "risk_rating":              f.risk_rating,
        "finding_title":            f.finding_title,
        "root_cause_narrative":     f.root_cause_narrative,
        "situation_narrative":      f.situation_narrative,
        "consequence_narrative":    f.consequence_narrative,
        "access_required":          f.access_required,
        "ai_enriched":              f.ai_enriched,
        "llm_enrichment_failed":    f.llm_enrichment_failed,
        "instance_count":           f.instance_count,
        "raw": {
            "check_id":             f.raw_check_id,
            "check_title":          f.raw_check_title,
            "severity":             f.raw_severity,
            "status":               f.raw_status,
            "service_name":         f.raw_service_name,
            "resource_uid":         f.raw_resource_uid,
            "resource_name":        f.raw_resource_name,
            "account_uid":          f.raw_account_uid,
            "account_name":         f.raw_account_name,
            "region":               f.raw_region,
            "description":          f.raw_description,
            "risk":                 f.raw_risk,
            "remediation_text":     f.raw_remediation_recommendation_text,
        },
        "audit_trail": [
            {
                "timestamp": e.timestamp.isoformat(),
                "stage":     e.stage,
                "field":     e.field,
                "old_value": str(e.old_value)[:100],
                "new_value": str(e.new_value)[:100],
                "reason":    e.reason[:200],
                "actor":     e.actor,
            }
            for e in f.audit_trail
        ],
    }


def _group_to_dict(g) -> dict:
    rep = g.representative
    return {
        "output_group_key":         g.output_group_key,
        "check_id":                 g.check_id,
        "output_section":           g.output_section,
        "instance_count":           g.instance_count,
        "likelihood_rating":        g.likelihood_rating,
        "risk_rating":              rep.risk_rating,
        "consequence_rating":       rep.consequence_rating,
        "affected_account_names":   g.affected_account_names,
        "instance_ids":             g.instance_ids,
        "ai_enriched":              rep.ai_enriched,
        "llm_enrichment_failed":    rep.llm_enrichment_failed,
        "human_review_required":    rep.human_review_required,
        "finding_title":            rep.finding_title,
        "root_cause_narrative":     rep.root_cause_narrative,
        "situation_narrative":      rep.situation_narrative,
        "consequence_narrative":    rep.consequence_narrative,
        "access_required":          rep.access_required,
        "representative": {
            "finding_instance_id":  rep.finding_instance_id,
            "source_row_id":        rep.source_row_id,
            "check_title":          rep.raw_check_title,
            "severity":             rep.raw_severity,
            "completeness_score":   rep.completeness_score(),
        },
    }


def _write_stage1_summary(ir, path: Path) -> None:
    from collections import Counter
    from models import BlankCategory
    lines = []
    a = lines.append
    a("=" * 70)
    a("STAGE 1 — INGEST & PARSE")
    a("=" * 70)
    a(f"Run ID          : {ir.run_id}")
    a(f"Source file     : {ir.source_file}")
    a(f"SHA-256         : {ir.source_file_hash}")
    a(f"Scanner         : {ir.scanner} v{ir.scanner_version}")
    a(f"Sheet           : {ir.sheet_name}")
    a(f"Rows read       : {ir.total_rows_read}")
    a(f"Findings parsed : {ir.finding_count}")
    a("")
    a("STATUS BREAKDOWN:")
    for s, c in sorted(Counter(f.scanner_status.value for f in ir.findings).items()):
        a(f"  {s:25s}: {c}")
    a("")
    a("BLANK VALUE CLASSIFICATIONS:")
    a(f"  Category 2 — DESCRIPTION blank     : {sum(1 for f in ir.findings if f.blank_description  == BlankCategory.DATA_QUALITY)}")
    a(f"  Category 2 — RISK blank            : {sum(1 for f in ir.findings if f.blank_risk         == BlankCategory.DATA_QUALITY)}")
    a(f"  Category 2 — REMEDIATION blank     : {sum(1 for f in ir.findings if f.blank_remediation  == BlankCategory.DATA_QUALITY)}")
    a(f"  Category 1 — REGION blank (global) : {sum(1 for f in ir.findings if f.blank_region       == BlankCategory.STRUCTURAL)}")
    a("")
    a("MUTED RECONCILIATIONS:")
    for f in ir.findings:
        if f.muted_reconciled:
            a(f"  {f.source_row_id}: {f.raw_check_id} — STATUS='{f.raw_status}' + MUTED=True → {f.scanner_status.value}")
    a("")
    a(f"WARNINGS ({len(ir.warnings)}):")
    for code, count in sorted(Counter(w.code for w in ir.warnings).items()):
        a(f"  {code:35s}: {count}")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_stage2_summary(pr, path: Path) -> None:
    lines = []
    a = lines.append
    a("=" * 70)
    a("STAGE 2 — DETERMINISTIC PROCESS")
    a("=" * 70)
    a(f"Total findings in  : {pr.total_findings}")
    a(f"Included (working) : {pr.included_count}")
    a(f"Excluded (filtered): {pr.excluded_count}")
    a(f"Duplicates removed : {pr.duplicate_count}")
    a(f"Output groups      : {pr.group_count}")
    a("")
    a("EXCLUDED FINDINGS:")
    for f in pr.all_findings:
        if f.report_inclusion == ReportInclusion.EXCLUDED and not f.is_duplicate:
            reason = next(
                (e.reason for e in reversed(f.audit_trail) if e.field == "report_inclusion"),
                "unknown"
            )
            a(f"  {f.raw_check_id} | {f.raw_account_name} | {f.scanner_status.value}")
            a(f"    {reason[:100]}")
    a("")
    a("DUPLICATES:")
    for f in pr.all_findings:
        if f.is_duplicate:
            a(f"  {f.raw_check_id} | {f.resource_uid_normalised[:60]}")
    a("")
    a("OUTPUT GROUPS:")
    a(f"  {'#':<3} {'Severity':<14} {'Likelihood':<12} {'Inst':>4}  Check ID")
    a(f"  {'-'*3} {'-'*14} {'-'*12} {'-'*4}  {'-'*40}")
    for i, g in enumerate(pr.output_groups, 1):
        rep = g.representative
        a(f"  {i:<3} {(rep.raw_severity or '?'):<14} {(g.likelihood_rating or '?'):<12} {g.instance_count:>4}  {g.check_id}")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_pipeline_report(er: EnrichResult, path: Path) -> None:
    lines = []
    a = lines.append
    a("=" * 70)
    a("PIPELINE TEST REPORT — STAGES 1 + 2 + 3")
    a(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    a("=" * 70)
    a("")
    a(f"Run ID          : {er.run_id}")
    a(f"Groups enriched : {er.enriched_count}/{er.group_count}")
    a(f"LLM failures    : {er.failed_count}")
    a("")
    a("RISK DISTRIBUTION:")
    rc = er.risk_rating_counts
    a(f"  High   : {rc.get('High',   0)}")
    a(f"  Medium : {rc.get('Medium', 0)}")
    a(f"  Low    : {rc.get('Low',    0)}")
    a("")
    a("=" * 70)
    a("ENRICHED FINDINGS — FULL DETAIL")
    a("=" * 70)
    for i, g in enumerate(er.output_groups, 1):
        rep = g.representative
        a("")
        a(f"── [{i}/{er.group_count}] {g.check_id} ──")
        a(f"  Section          : {g.output_section}")
        a(f"  Severity         : {rep.raw_severity}")
        a(f"  Likelihood       : {g.likelihood_rating}")
        a(f"  Consequence      : {rep.consequence_rating}")
        a(f"  Risk Rating      : {rep.risk_rating}")
        a(f"  Instance count   : {g.instance_count}")
        a(f"  Accounts         : {g.affected_account_names}")
        a(f"  AI enriched      : {rep.ai_enriched}")
        a(f"  LLM failed       : {rep.llm_enrichment_failed}")
        a(f"  Needs review     : {rep.human_review_required}")
        a("")
        a(f"  FINDING TITLE:")
        a(f"    {rep.finding_title or '[not set]'}")
        a("")
        a(f"  ROOT CAUSE:")
        a(f"    {rep.root_cause_narrative or '[not set]'}")
        a("")
        a(f"  SITUATION:")
        a(f"    {rep.situation_narrative or '[not set]'}")
        a("")
        a(f"  CONSEQUENCE:")
        a(f"    {rep.consequence_narrative or '[not set]'}")
        a("")
        a(f"  ACCESS REQUIRED:")
        a(f"    {rep.access_required or '[not set]'}")
        if rep.llm_enrichment_failed:
            a("")
            a(f"  ⚠ LLM FAILURE — REASON:")
            # Find the failure reason in audit trail
            failure_event = next(
                (e for e in rep.audit_trail if e.field == "llm_enrichment_failed"),
                None,
            )
            if failure_event:
                a(f"    {failure_event.reason}")
    a("")
    a("=" * 70)
    if er.failed_count == 0:
        a("✓ ALL GROUPS ENRICHED SUCCESSFULLY")
    else:
        a(f"⚠ {er.failed_count} GROUP(S) NEED HUMAN REVIEW")
    a("=" * 70)
    path.write_text("\n".join(lines), encoding="utf-8")


# ── Main ──────────────────────────────────────────────────────────────

def run() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print()
    print("=" * 65)
    print("Full Pipeline Test — Stages 1 + 2 + 3")
    print("Synthetic data → Bedrock mantle → Enriched output")
    print("=" * 65)

    # ── Generate synthetic data if needed ────────────────────────────
    if not SYNTHETIC.exists():
        print("\n[ Pre ] Generating synthetic messy dataset...")
        with contextlib.redirect_stdout(io.StringIO()):
            generate(SYNTHETIC)
        print(f"  ✓ Created: {SYNTHETIC.name}")
    else:
        print(f"\n[ Pre ] Using existing: {SYNTHETIC.name}")

    # ── Load config ──────────────────────────────────────────────────
    print("\n[ Config ] Loading config.toml...")
    cfg     = load_config(CONFIG_PATH)
    llm_cfg = cfg.get("llm", {})
    print(f"  Provider   : {llm_cfg.get('provider')}")
    print(f"  Model      : {llm_cfg.get('deployment_name')}")
    print(f"  Region     : {llm_cfg.get('aws_region')}")
    print(f"  store=false: zero retention enforced per request")

    # ── Stage 1 ──────────────────────────────────────────────────────
    print("\n[ Stage 1 ] Ingesting and parsing...")
    t0 = time.time()
    ir = ingest(SYNTHETIC)
    t1 = time.time()

    print(f"  ✓ SHA-256         : {ir.source_file_hash[:16]}...")
    print(f"  ✓ Rows read       : {ir.total_rows_read}")
    print(f"  ✓ Findings parsed : {ir.finding_count}")
    print(f"  ✓ Scanner version : {ir.scanner} v{ir.scanner_version}")
    print(f"  ✓ Time            : {t1-t0:.2f}s")
    if ir.warnings:
        from collections import Counter
        for code, count in Counter(w.code for w in ir.warnings).items():
            print(f"  ⚠ Warning [{code}]: {count}")

    # ── Stage 2 ──────────────────────────────────────────────────────
    print("\n[ Stage 2 ] Processing...")
    t0 = time.time()
    pr = process(ir, cfg)
    t1 = time.time()

    print(f"  ✓ Included     : {pr.included_count}")
    print(f"  ✓ Excluded     : {pr.excluded_count}")
    print(f"  ✓ Duplicates   : {pr.duplicate_count}")
    print(f"  ✓ Output groups: {pr.group_count}")
    print(f"  ✓ Time         : {t1-t0:.2f}s")

    from collections import Counter as C
    lc = C(g.likelihood_rating for g in pr.output_groups)
    print(f"  ✓ Likelihood   : High={lc.get('High',0)}  Medium={lc.get('Medium',0)}  Low={lc.get('Low',0)}")

    # ── Stage 3 ──────────────────────────────────────────────────────
    print(f"\n[ Stage 3 ] LLM enrichment ({pr.group_count} groups)...")
    print(f"  Endpoint : bedrock-mantle.{llm_cfg.get('aws_region')}.api.aws")
    print(f"  store    : false (zero retention per request)")
    print()

    t0 = time.time()
    er = enrich(pr, cfg)
    t1 = time.time()

    print()
    print(f"  ✓ Enriched : {er.enriched_count}/{er.group_count}")
    print(f"  ✓ Failed   : {er.failed_count}")
    print(f"  ✓ Time     : {t1-t0:.1f}s ({(t1-t0)/pr.group_count:.1f}s/group avg)")

    rc = er.risk_rating_counts
    print(f"  ✓ Risk     : High={rc.get('High',0)}  Medium={rc.get('Medium',0)}  Low={rc.get('Low',0)}")

    # ── Write outputs ─────────────────────────────────────────────────
    print("\n[ Writing outputs ]")

    # canonical_findings.json
    canon_path = OUTPUT_DIR / "canonical_findings.json"
    with open(canon_path, "w", encoding="utf-8") as fh:
        json.dump({
            "run_id":           er.run_id,
            "source_file":      ir.source_file,
            "source_file_hash": ir.source_file_hash,
            "scanner":          ir.scanner,
            "scanner_version":  ir.scanner_version,
            "generated_at":     datetime.now(timezone.utc).isoformat(),
            "total_findings":   pr.total_findings,
            "included":         pr.included_count,
            "excluded":         pr.excluded_count,
            "duplicates":       pr.duplicate_count,
            "findings":         [_finding_to_dict(f) for f in pr.all_findings],
        }, fh, indent=2, default=str, ensure_ascii=False)
    print(f"  ✓ canonical_findings.json    ({canon_path.stat().st_size // 1024} KB)")

    # enriched_groups.json
    groups_path = OUTPUT_DIR / "enriched_groups.json"
    with open(groups_path, "w", encoding="utf-8") as fh:
        json.dump({
            "run_id":       er.run_id,
            "group_count":  er.group_count,
            "enriched":     er.enriched_count,
            "failed":       er.failed_count,
            "risk_ratings": er.risk_rating_counts,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "groups":       [_group_to_dict(g) for g in er.output_groups],
        }, fh, indent=2, default=str, ensure_ascii=False)
    print(f"  ✓ enriched_groups.json       ({groups_path.stat().st_size // 1024} KB)")

    # run_manifest.json
    manifest_path = OUTPUT_DIR / "run_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump({
            "run_id":           er.run_id,
            "source_file":      ir.source_file,
            "source_file_hash": ir.source_file_hash,
            "scanner":          ir.scanner,
            "scanner_version":  ir.scanner_version,
            "schema_version":   "1.0.0",
            "generated_at":     datetime.now(timezone.utc).isoformat(),
            "llm": {
                "provider":      llm_cfg.get("provider"),
                "model":         llm_cfg.get("deployment_name"),
                "region":        llm_cfg.get("aws_region"),
                "endpoint":      f"bedrock-mantle.{llm_cfg.get('aws_region')}.api.aws",
                "store":         False,
                "data_retained": False,
            },
            "counts": {
                "total_rows_read": ir.total_rows_read,
                "total_findings":  pr.total_findings,
                "included":        pr.included_count,
                "excluded":        pr.excluded_count,
                "duplicates":      pr.duplicate_count,
                "output_groups":   pr.group_count,
                "enriched":        er.enriched_count,
                "llm_failed":      er.failed_count,
            },
            "risk_ratings":    er.risk_rating_counts,
            "config": {
                "include_statuses": cfg["processing"]["include_statuses"],
                "severity_rules":   cfg["severity_rules"],
                "risk_matrix":      cfg["risk_matrix"],
            },
            "stage1_warnings": [{"code": w.code, "message": w.message} for w in ir.warnings],
            "stage2_warnings": [{"code": w.code, "message": w.message} for w in pr.warnings],
            "stage3_warnings": [{"code": w.code, "message": w.message} for w in er.warnings],
        }, fh, indent=2, default=str, ensure_ascii=False)
    print(f"  ✓ run_manifest.json          ({manifest_path.stat().st_size // 1024} KB)")

    # stage1_summary.txt
    s1_path = OUTPUT_DIR / "stage1_summary.txt"
    _write_stage1_summary(ir, s1_path)
    print(f"  ✓ stage1_summary.txt")

    # stage2_summary.txt
    s2_path = OUTPUT_DIR / "stage2_summary.txt"
    _write_stage2_summary(pr, s2_path)
    print(f"  ✓ stage2_summary.txt")

    # pipeline_test_report.txt
    report_path = OUTPUT_DIR / "pipeline_test_report.txt"
    _write_pipeline_report(er, report_path)
    print(f"  ✓ pipeline_test_report.txt")

    # ── Final summary ─────────────────────────────────────────────────
    print()
    print("=" * 65)
    if er.failed_count == 0:
        print("✓ ALL STAGES PASSED — PIPELINE READY FOR STAGE 4")
    else:
        print(f"⚠ PIPELINE COMPLETE — {er.failed_count} GROUP(S) NEED HUMAN REVIEW")
    print("=" * 65)
    print(f"  Groups enriched  : {er.enriched_count}/{er.group_count}")
    print(f"  Risk distribution: High={rc.get('High',0)}  Medium={rc.get('Medium',0)}  Low={rc.get('Low',0)}")
    print()
    print("  Review these files:")
    print(f"    pipeline_test_report.txt  ← start here — all narratives")
    print(f"    enriched_groups.json      ← structured LLM output per group")
    print(f"    canonical_findings.json   ← full audit trail")
    print(f"    run_manifest.json         ← run metadata + data residency")
    print()
    print(f"  Output dir: {OUTPUT_DIR.resolve()}")
    print()

    if er.failed_count > 0:
        print("  Failed groups (need human review):")
        for g in er.output_groups:
            if g.representative.llm_enrichment_failed:
                print(f"    ⚠ {g.check_id}")
        print()


if __name__ == "__main__":
    run()