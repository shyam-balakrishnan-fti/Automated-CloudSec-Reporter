"""
run_pipeline.py — Full pipeline runner

Flow:
    Stage 1   Ingest & parse raw Prowler output
    Stage 2   Deterministic filter → dedup → group → likelihood
    Stage 2.5 Chunked + auto-consolidated semantic grouping (LLM)
    Review    Analyst reviews/edits grouping in browser UI — drag chips,
              per-group AI instructions, global AI instructions. NO
              individual enrichment happens before this step.
    Stage 3   Enrich ONLY the final approved groups (not every individual
              check) — situation/consequence/root-cause narratives.
    Stage 5   Render the client-facing Excel report.

Usage (from your project root):
    python src/run_pipeline.py --input data/synthetic/synthetic_prowler_messy.xlsx
    python src/run_pipeline.py --input your_real_prowler_file.json --format json

Outputs written to --output-dir/{client_name}/ :
    canonical_findings.json     — every finding, full fields, all audit events
    output_groups.json          — Stage 2 output (pre-grouping)
    grouping_proposal.json      — AI's chunked + consolidated grouping proposal
    grouping_approved.json      — analyst's final approved grouping
    enriched_groups.json        — final groups with LLM narratives
    run_manifest.json           — run metadata, counts, warnings
    stage1_summary.txt          — human-readable Stage 1 summary
    stage2_summary.txt          — human-readable Stage 2 summary
    SecurityReport_*.xlsx       — final client-facing report
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from models import BlankCategory, ReportInclusion, ScannerStatus
from stage1_ingest import IngestResult, ingest
from stage2_process import OutputGroup, ProcessResult, load_config, process
from stage2_5_grouping import group_semantically
from stage_reviewer import (
    ApprovedGrouping,
    apply_approved_grouping,
    load_approved_grouping,
    start_review_server,
)
from stage3_llm import EnrichResult, EnrichWarning, enrich_grouped
from stage5_render_excel import render_excel


# ── Serialisation helpers ─────────────────────────────────────────────

def _finding_to_dict(f) -> dict:
    """Serialize a CanonicalFinding to a clean dict for JSON output."""
    return {
        # ── Identity ──
        "finding_instance_id":      f.finding_instance_id,
        "stable_finding_key":       f.stable_finding_key,
        "dedup_key":                f.dedup_key,
        "source_row_id":            f.source_row_id,
        "run_id":                   f.run_id,
        "source_file_hash":         f.source_file_hash,

        # ── Processing state ──
        "scanner_status":           f.scanner_status.value,
        "report_inclusion":         f.report_inclusion.value,
        "is_duplicate":             f.is_duplicate,
        "duplicate_of":             f.duplicate_of,
        "human_review_required":    f.human_review_required,
        "review_reason":            f.review_reason,
        "muted_reconciled":         f.muted_reconciled,

        # ── Blank classifications ──
        "blank_description":        f.blank_description.value,
        "blank_risk":               f.blank_risk.value,
        "blank_remediation":        f.blank_remediation.value,
        "blank_region":             f.blank_region.value,

        # ── Normalised fields ──
        "scanner_status_normalised": f.scanner_status.value,
        "region_normalised":        f.region_normalised,
        "resource_uid_normalised":  f.resource_uid_normalised,
        "arn_fallback_used":        f.arn_fallback_used,
        "categories_list":          f.categories_list,
        "compliance_values":        f.compliance_values,
        "compliance_parsed":        f.compliance_parsed,
        "account_tags_parsed":      f.account_tags_parsed,
        "resource_tags_parsed":     f.resource_tags_parsed,

        # ── Output fields (set by Stage 2) ──
        "output_section":           f.output_section,
        "likelihood_rating":        f.likelihood_rating,
        "instance_count":           f.instance_count,
        "representative_instance_id": f.representative_instance_id,

        # ── Raw fields (all 41 Prowler columns) ──
        "raw": {
            "auth_method":          f.raw_auth_method,
            "timestamp":            f.raw_timestamp,
            "account_uid":          f.raw_account_uid,
            "account_name":         f.raw_account_name,
            "account_email":        f.raw_account_email,
            "account_org_uid":      f.raw_account_organization_uid,
            "account_org_name":     f.raw_account_organization_name,
            "account_tags":         f.raw_account_tags,
            "finding_uid":          f.raw_finding_uid,
            "provider":             f.raw_provider,
            "check_id":             f.raw_check_id,
            "check_title":          f.raw_check_title,
            "check_type":           f.raw_check_type,
            "status":               f.raw_status,
            "status_extended":      f.raw_status_extended,
            "muted":                f.raw_muted,
            "service_name":         f.raw_service_name,
            "subservice_name":      f.raw_subservice_name,
            "severity":             f.raw_severity,
            "resource_type":        f.raw_resource_type,
            "resource_uid":         f.raw_resource_uid,
            "resource_name":        f.raw_resource_name,
            "resource_details":     f.raw_resource_details,
            "resource_tags":        f.raw_resource_tags,
            "partition":            f.raw_partition,
            "region":               f.raw_region,
            "description":          f.raw_description,
            "risk":                 f.raw_risk,
            "related_url":          f.raw_related_url,
            "remediation_text":     f.raw_remediation_recommendation_text,
            "remediation_url":      f.raw_remediation_recommendation_url,
            "remediation_nativeiac":f.raw_remediation_code_nativeiac,
            "remediation_terraform":f.raw_remediation_code_terraform,
            "remediation_cli":      f.raw_remediation_code_cli,
            "remediation_other":    f.raw_remediation_code_other,
            "compliance":           f.raw_compliance,
            "categories":           f.raw_categories,
            "depends_on":           f.raw_depends_on,
            "related_to":           f.raw_related_to,
            "notes":                f.raw_notes,
            "prowler_version":      f.raw_prowler_version,
        },

        # ── Extra/unknown columns ──
        "extra_fields": f.extra_fields,

        # ── Audit trail ──
        "audit_trail": [
            {
                "timestamp": e.timestamp.isoformat(),
                "stage":     e.stage,
                "field":     e.field,
                "old_value": e.old_value,
                "new_value": e.new_value,
                "reason":    e.reason,
                "actor":     e.actor,
            }
            for e in f.audit_trail
        ],
    }


def _group_to_dict(g: OutputGroup) -> dict:
    """Serialize an OutputGroup to a clean dict for JSON output."""
    rep = g.representative
    return {
        "output_group_key":         g.output_group_key,
        "check_id":                 g.check_id,
        "output_section":           g.output_section,
        "instance_count":           g.instance_count,
        "likelihood_rating":        g.likelihood_rating,
        "affected_account_names":   g.affected_account_names,
        "affected_account_uids":    g.affected_account_uids,
        "instance_ids":             g.instance_ids,

        # Representative finding summary
        "representative": {
            "finding_instance_id":  rep.finding_instance_id,
            "source_row_id":        rep.source_row_id,
            "check_id":             rep.raw_check_id,
            "check_title":          rep.raw_check_title,
            "severity":             rep.raw_severity,
            "service_name":         rep.raw_service_name,
            "resource_type":        rep.raw_resource_type,
            "region":               rep.region_normalised,
            "completeness_score":   rep.completeness_score(),
            "has_description":      rep.raw_description is not None,
            "has_risk":             rep.raw_risk is not None,
            "has_remediation":      rep.raw_remediation_recommendation_text is not None,
            "human_review_required":rep.human_review_required,
        },

        # What will be sent to Stage 3 (LLM) — non-sensitive fields only
        "llm_context": g.to_llm_context(),
    }


# ── Summary writers ───────────────────────────────────────────────────

def _write_stage1_summary(ir: IngestResult, path: Path) -> None:
    lines = []
    a = lines.append

    a("=" * 70)
    a("STAGE 1 — INGEST & PARSE SUMMARY")
    a("=" * 70)
    a(f"Run ID           : {ir.run_id}")
    a(f"Source file      : {ir.source_file}")
    a(f"SHA-256          : {ir.source_file_hash}")
    a(f"Scanner          : {ir.scanner} v{ir.scanner_version}")
    a(f"Sheet detected   : {ir.sheet_name}")
    a(f"Rows read        : {ir.total_rows_read}")
    a(f"Findings parsed  : {ir.finding_count}")
    a(f"Unknown columns  : {ir.unknown_columns or 'none'}")
    a(f"Ingested at      : {ir.ingested_at.isoformat()}")
    a("")

    # Status breakdown
    from collections import Counter
    status_counts = Counter(f.scanner_status.value for f in ir.findings)
    a("STATUS BREAKDOWN:")
    for s, c in sorted(status_counts.items()):
        a(f"  {s:25s}: {c}")
    a("")

    # Blank value breakdown
    d2_desc  = sum(1 for f in ir.findings if f.blank_description  == BlankCategory.DATA_QUALITY)
    d2_risk  = sum(1 for f in ir.findings if f.blank_risk         == BlankCategory.DATA_QUALITY)
    d2_remed = sum(1 for f in ir.findings if f.blank_remediation  == BlankCategory.DATA_QUALITY)
    d1_reg   = sum(1 for f in ir.findings if f.blank_region       == BlankCategory.STRUCTURAL)
    a("BLANK VALUE CLASSIFICATIONS:")
    a(f"  Category 2 — DESCRIPTION blank      : {d2_desc}")
    a(f"  Category 2 — RISK blank              : {d2_risk}")
    a(f"  Category 2 — REMEDIATION_TEXT blank  : {d2_remed}")
    a(f"  Category 1 — REGION blank (global)   : {d1_reg}")
    a("")

    # MUTED reconciliation
    reconciled = [f for f in ir.findings if f.muted_reconciled]
    a(f"MUTED RECONCILIATIONS: {len(reconciled)}")
    for f in reconciled:
        a(f"  Row {f.source_row_id}: {f.raw_check_id} — STATUS='{f.raw_status}' + MUTED=True → {f.scanner_status.value}")
    a("")

    # ARN fallbacks
    fallbacks = [f for f in ir.findings if f.arn_fallback_used and f.resource_uid_normalised]
    a(f"ARN FALLBACKS (name used instead of ARN): {len(fallbacks)}")
    for f in fallbacks[:5]:
        a(f"  {f.raw_check_id}: resource='{f.resource_uid_normalised}'")
    if len(fallbacks) > 5:
        a(f"  ... and {len(fallbacks)-5} more")
    a("")

    # Human review flags
    review = [f for f in ir.findings if f.human_review_required]
    a(f"FLAGGED FOR HUMAN REVIEW: {len(review)}")
    for f in review[:10]:
        a(f"  {f.source_row_id}: {f.raw_check_id} — {f.review_reason}")
    if len(review) > 10:
        a(f"  ... and {len(review)-10} more")
    a("")

    # Warnings
    a(f"WARNINGS ({len(ir.warnings)}):")
    from collections import Counter as C2
    warn_counts = C2(w.code for w in ir.warnings)
    for code, count in sorted(warn_counts.items()):
        a(f"  {code:35s}: {count}")
    a("")

    path.write_text("\n".join(lines), encoding="utf-8")


def _write_stage2_summary(pr: ProcessResult, path: Path) -> None:
    lines = []
    a = lines.append

    a("=" * 70)
    a("STAGE 2 — DETERMINISTIC PROCESS SUMMARY")
    a("=" * 70)
    a(f"Run ID              : {pr.run_id}")
    a(f"Total findings in   : {pr.total_findings}")
    a(f"Included (working)  : {pr.included_count}")
    a(f"Excluded (filtered) : {pr.excluded_count}")
    a(f"Duplicates removed  : {pr.duplicate_count}")
    a(f"Output groups       : {pr.group_count}")
    a("")

    # Exclusion reasons
    excluded = [
        f for f in pr.all_findings
        if f.report_inclusion == ReportInclusion.EXCLUDED and not f.is_duplicate
    ]
    a(f"EXCLUDED FINDINGS ({len(excluded)}) — preserved in canonical JSON:")
    for f in excluded:
        reason = next(
            (e.reason for e in reversed(f.audit_trail) if e.field == "report_inclusion"),
            "unknown"
        )
        a(f"  {f.raw_check_id} | {f.raw_account_name} | {f.scanner_status.value}")
        a(f"    Reason: {reason[:100]}")
    a("")

    # Duplicates
    dups = [f for f in pr.all_findings if f.is_duplicate]
    a(f"DUPLICATES ({len(dups)}) — preserved in canonical JSON:")
    for f in dups:
        a(f"  {f.raw_check_id} | {f.raw_account_name} | resource={f.resource_uid_normalised[:60]}")
        a(f"    Duplicate of: {f.duplicate_of}")
    a("")

    # Output groups — the core output of Stage 2
    a(f"OUTPUT GROUPS ({pr.group_count}) — one row per check in the final report:")
    a(f"  {'#':<3} {'Section':<8} {'Severity':<14} {'Likelihood':<12} {'Inst':>4}  Check ID")
    a(f"  {'-'*3} {'-'*8} {'-'*14} {'-'*12} {'-'*4}  {'-'*40}")
    for i, g in enumerate(pr.output_groups, 1):
        rep = g.representative
        sev = (rep.raw_severity or "?").ljust(13)
        lik = (g.likelihood_rating or "?").ljust(11)
        a(f"  {i:<3} {g.output_section:<8} {sev} {lik} {g.instance_count:>4}  {g.check_id}")
    a("")

    # Per-group detail
    a("GROUP DETAIL:")
    for g in pr.output_groups:
        rep = g.representative
        a(f"  ── {g.check_id} ──")
        a(f"     Instances       : {g.instance_count}")
        a(f"     Accounts        : {g.affected_account_names}")
        a(f"     Likelihood      : {g.likelihood_rating}")
        a(f"     Severity        : {rep.raw_severity}")
        a(f"     Representative  : {rep.source_row_id}")
        a(f"     Completeness    : {rep.completeness_score()}/5")
        a(f"     Has description : {rep.raw_description is not None}")
        a(f"     Has risk        : {rep.raw_risk is not None}")
        a(f"     Has remediation : {rep.raw_remediation_recommendation_text is not None}")
        a(f"     Human review    : {rep.human_review_required}")
        if rep.human_review_required:
            a(f"     Review reason   : {rep.review_reason}")
        a("")

    # Warnings
    a(f"WARNINGS ({len(pr.warnings)}):")
    if pr.warnings:
        for w in pr.warnings:
            a(f"  [{w.code}] {w.message}")
    else:
        a("  None")

    path.write_text("\n".join(lines), encoding="utf-8")


# ── Main runner ───────────────────────────────────────────────────────

def run(input_file: str, output_dir: str, config_path: str, fmt: str = "auto",
        skip_llm: bool = False, skip_review: bool = False,
        force_review: bool = False, no_browser: bool = False) -> None:
    input_path   = Path(input_file)
    cfg          = load_config(config_path)
    client_slug  = (
        cfg.get("engagement", {}).get("client_name", "")
        .lower().strip()
        .replace(" ", "_")
        .replace("/", "_")[:40]
    ) or "default"
    output_path  = Path(output_dir) / client_slug
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*70}")
    print("SECURITY SCANNER PIPELINE")
    print(f"{'='*70}")
    print(f"Input  : {input_path}")
    print(f"Config : {config_path}")
    print(f"Output : {output_path}")
    print()

    # ── Stage 1 ──────────────────────────────────────────────────────
    print("[ Stage 1 ] Ingesting and parsing...")
    ir = ingest(input_path, fmt=fmt)

    print(f"  ✓ SHA-256          : {ir.source_file_hash}")
    print(f"  ✓ Rows read        : {ir.total_rows_read}")
    print(f"  ✓ Findings parsed  : {ir.finding_count}")
    print(f"  ✓ Scanner version  : {ir.scanner} v{ir.scanner_version}")
    if ir.warnings:
        print(f"  ⚠ Warnings         : {len(ir.warnings)}")
        from collections import Counter
        for code, count in Counter(w.code for w in ir.warnings).items():
            print(f"      {code}: {count}")
    print()

    # ── Stage 2 ──────────────────────────────────────────────────────
    print("[ Stage 2 ] Processing (filter → dedup → group → likelihood)...")
    pr = process(ir, cfg)

    print(f"  ✓ Included         : {pr.included_count}")
    print(f"  ✓ Excluded         : {pr.excluded_count}")
    print(f"  ✓ Duplicates       : {pr.duplicate_count}")
    print(f"  ✓ Output groups    : {pr.group_count}")

    from collections import Counter
    lik_counts = Counter(g.likelihood_rating for g in pr.output_groups)
    print(f"  ✓ Likelihood dist  : High={lik_counts.get('High',0)}  Medium={lik_counts.get('Medium',0)}  Low={lik_counts.get('Low',0)}")
    if pr.warnings:
        print(f"  ⚠ Warnings         : {len(pr.warnings)}")
        for w in pr.warnings:
            print(f"      [{w.code}] {w.message[:80]}")
    print()

    # ── Write Stage 1+2 outputs ────────────────────────────────────────
    print("[ Writing Stage 1+2 outputs ]")

    canon_path = output_path / "canonical_findings.json"
    canon_data = {
        "run_id":           pr.run_id,
        "source_file":      ir.source_file,
        "source_file_hash": ir.source_file_hash,
        "scanner":          ir.scanner,
        "scanner_version":  ir.scanner_version,
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "total_findings":   pr.total_findings,
        "included":         pr.included_count,
        "excluded":         pr.excluded_count,
        "duplicates":       pr.duplicate_count,
        "findings": [_finding_to_dict(f) for f in pr.all_findings],
    }
    with open(canon_path, "w", encoding="utf-8") as fh:
        json.dump(canon_data, fh, indent=2, default=str, ensure_ascii=False)
    print(f"  ✓ canonical_findings.json  ({canon_path.stat().st_size // 1024} KB)")

    groups_path = output_path / "output_groups.json"
    groups_data = {
        "run_id":       pr.run_id,
        "group_count":  pr.group_count,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "groups": [_group_to_dict(g) for g in pr.output_groups],
    }
    with open(groups_path, "w", encoding="utf-8") as fh:
        json.dump(groups_data, fh, indent=2, default=str, ensure_ascii=False)
    print(f"  ✓ output_groups.json       ({groups_path.stat().st_size // 1024} KB)")

    manifest_path = output_path / "run_manifest.json"
    manifest = {
        "run_id":               pr.run_id,
        "source_file":          ir.source_file,
        "source_file_hash":     ir.source_file_hash,
        "scanner":              ir.scanner,
        "scanner_version":      ir.scanner_version,
        "schema_version":       "1.0.0",
        "generated_at":         datetime.now(timezone.utc).isoformat(),
        "config": {
            "include_statuses": cfg["processing"]["include_statuses"],
            "severity_rules":   cfg["severity_rules"],
            "risk_matrix":      cfg["risk_matrix"],
        },
        "counts": {
            "total_rows_read":  ir.total_rows_read,
            "total_findings":   pr.total_findings,
            "included":         pr.included_count,
            "excluded":         pr.excluded_count,
            "duplicates":       pr.duplicate_count,
            "output_groups":    pr.group_count,
        },
        "stage1_warnings": [{"code": w.code, "message": w.message} for w in ir.warnings],
        "stage2_warnings": [{"code": w.code, "message": w.message, "check_id": w.check_id} for w in pr.warnings],
    }
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, default=str, ensure_ascii=False)
    print(f"  ✓ run_manifest.json        ({manifest_path.stat().st_size // 1024} KB)")

    s1_path = output_path / "stage1_summary.txt"
    _write_stage1_summary(ir, s1_path)
    print(f"  ✓ stage1_summary.txt")

    s2_path = output_path / "stage2_summary.txt"
    _write_stage2_summary(pr, s2_path)
    print(f"  ✓ stage2_summary.txt")

    if skip_llm:
        print()
        print(f"{'='*70}")
        print("STAGE 2.5 + 3 SKIPPED (--skip-llm flag set)")
        print(f"  Output groups ready: {pr.group_count}")
        print(f"{'='*70}")
        print()
        print(f"  Output written to: {output_path.resolve()}")
        print()
        return

    # ── Stage 2.5: chunked + auto-consolidated grouping ────────────────
    gr = group_semantically(pr, cfg)

    grouping_path = output_path / "grouping_proposal.json"
    with open(grouping_path, "w", encoding="utf-8") as fh:
        json.dump({
            "run_id":           gr.run_id,
            "original_count":   gr.original_count,
            "merged_count":     gr.merged_count,
            "merges_applied":   gr.merges_applied,
            "chunks_used":      gr.chunks_used,
            "consolidation_applied": gr.consolidation_applied,
            "warnings":         [{"code": w.code, "message": w.message} for w in gr.warnings],
            "groups": [
                {
                    "group_name": g.group_name,
                    "check_ids":  g.check_ids,
                    "rationale":  g.group_rationale,
                    "is_merged":  g.is_merged,
                    "instance_count": g.instance_count,
                    "affected_accounts": g.affected_account_names,
                    "affected_resources": g.affected_resources(),
                }
                for g in gr.grouped_groups
            ],
        }, fh, indent=2, default=str, ensure_ascii=False)
    print(f"  ✓ grouping_proposal.json   ({grouping_path.stat().st_size // 1024} KB)")

    # ── Review UI — grouping only, no individual enrichment ────────────
    approved_path = output_path / "grouping_approved.json"
    client_name   = cfg.get("engagement", {}).get("client_name", "")

    if skip_review:
        print()
        print("  ℹ --skip-review: using AI grouping proposal directly", flush=True)
    elif approved_path.exists() and not force_review:
        print()
        print(f"  ✓ Found existing grouping_approved.json — applying", flush=True)
        approved = load_approved_grouping(approved_path)
        gr = apply_approved_grouping(approved, gr)
        print(f"  ✓ Applied analyst grouping: {gr.group_count} groups", flush=True)
    else:
        approved = start_review_server(
            grouping_result=gr,
            output_dir=output_path,
            config=cfg,
            client_name=client_name,
            open_browser=not no_browser,
        )
        gr = apply_approved_grouping(approved, gr)
        print(f"  ✓ Applied analyst grouping: {gr.group_count} groups", flush=True)

    # ── Apply analyst risk rating overrides before enrichment ────────────
    # If the analyst set a risk_rating_override on any group in the review UI,
    # write it to the representative finding now so Stage 3's enrichment
    # call sees it. Stage 3 skips the risk matrix computation if risk_rating
    # is already set on the representative finding.
    _override_count = 0
    if hasattr(approved, "groups"):
        _override_map = {
            ap.group_name: ap.risk_rating_override
            for ap in approved.groups
            if ap.risk_rating_override
        }
        for g in gr.grouped_groups:
            override = _override_map.get(g.group_name, "")
            if override:
                g.representative.risk_rating = override
                g.representative.add_audit(
                    stage="analyst_review",
                    field="risk_rating",
                    old_value="pending_enrichment",
                    new_value=override,
                    reason="Analyst override in review UI",
                    actor="human",
                )
                _override_count += 1
    if _override_count:
        print(f"  ✓ Applied {_override_count} analyst risk rating override(s)", flush=True)

    # ── Stage 3: enrich ONLY the final approved groups ──────────────────
    print()
    print(f"[ Stage 3 ] Enriching {gr.group_count} final group(s) "
          f"(not {gr.original_count} individual checks)...")
    er = enrich_grouped(gr, cfg)

    # ── Resource detail for output JSON ─────────────────────────────────
    fmap = {f.finding_instance_id: f for f in er.all_findings}
    def _res_detail(iids):
        out = []
        for fid in iids:
            f = fmap.get(fid)
            if not f:
                continue
            out.append({
                "resource_uid":    f.resource_uid_normalised or f.raw_resource_uid or "",
                "resource_name":   f.raw_resource_name or "",
                "account_uid":     f.raw_account_uid or "",
                "account_name":    f.raw_account_name or "",
                "region":          f.region_normalised or "",
                "resource_type":   f.raw_resource_type or "",
                "status_extended": f.raw_status_extended or "",
            })
        return out

    enriched_path = output_path / "enriched_groups.json"
    enriched_data = {
        "run_id":        er.run_id,
        "group_count":   er.group_count,
        "enriched":      er.enriched_count,
        "failed":        er.failed_count,
        "risk_ratings":  er.risk_rating_counts,
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "groups": [
            {
                "group_name":           getattr(g, "group_name", getattr(g, "check_id", "")),
                "check_ids":            getattr(g, "check_ids", [getattr(g, "check_id", "")]),
                "output_section":       g.output_section,
                "instance_count":       g.instance_count,
                "affected_accounts":    g.affected_account_names,
                "likelihood_rating":    g.likelihood_rating,
                "risk_rating":          g.representative.risk_rating,
                "consequence_rating":   g.representative.consequence_rating,
                "finding_title":        g.representative.finding_title,
                "root_cause_narrative": g.representative.root_cause_narrative,
                "situation_narrative":  g.representative.situation_narrative,
                "consequence_narrative":g.representative.consequence_narrative,
                "access_required":      g.representative.access_required,
                "recommendations":      g.representative.raw_remediation_recommendation_text,
                "ai_enriched":          g.representative.ai_enriched,
                "llm_failed":           g.representative.llm_enrichment_failed,
                "human_review_required":g.representative.human_review_required,
                "affected_resources":   _res_detail(g.instance_ids),
            }
            for g in er.output_groups
        ],
    }
    with open(enriched_path, "w", encoding="utf-8") as fh:
        json.dump(enriched_data, fh, indent=2, default=str, ensure_ascii=False)

    print()
    print("[ Writing Stage 3 outputs ]")
    print(f"  ✓ enriched_groups.json     ({enriched_path.stat().st_size // 1024} KB)")
    if er.warnings:
        print(f"  ⚠ LLM failures: {er.failed_count}")
        for w in er.warnings:
            print(f"      [{w.code}] {w.message[:80]}")

    # ── Stage 5: Excel renderer ────────────────────────────────────────
    print()
    print("[ Stage 5 ] Rendering Excel report...")
    tmpl = None
    cfg_tmpl = cfg.get("output", {}).get("template_path", "")
    if cfg_tmpl:
        p = Path(cfg_tmpl)
        if not p.is_absolute():
            p = Path(__file__).resolve().parent.parent / cfg_tmpl
        if p.exists():
            tmpl = p
    excel_path = render_excel(er, cfg, output_path, template_path=tmpl)

    # ── Final summary ──────────────────────────────────────────────────
    print()
    print(f"{'='*70}")
    rc = er.risk_rating_counts
    print("PIPELINE COMPLETE")
    print(f"{'='*70}")
    print(f"  Checks → Groups   : {gr.original_count} → {gr.group_count} "
          f"({gr.merges_applied} merge(s), {gr.chunks_used} chunk(s))")
    print(f"  Groups enriched   : {er.enriched_count}/{er.group_count}")
    print(f"  Risk distribution : High={rc.get('High',0)}  Medium={rc.get('Medium',0)}  Low={rc.get('Low',0)}")
    if er.failed_count:
        print(f"  ⚠ LLM failures    : {er.failed_count} — needs human review before final output")
    print()
    print(f"  Output written to: {output_path.resolve()}")
    print()


# ── Entry point ───────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run the security scanner pipeline end to end.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--input", "-i", required=True, help="Path to Prowler CSV/XLSX/JSON file")
    parser.add_argument("--output-dir", "-o", default="data/output", help="Directory for output files (default: data/output)")
    parser.add_argument("--config", "-c", default="config/config.toml", help="Path to config.toml")
    parser.add_argument("--format", "-f", choices=["auto", "csv", "xlsx", "json"], default="auto", help="Force input format")
    parser.add_argument("--skip-llm", action="store_true", default=False, help="Skip Stage 2.5+3 (Stage 1+2 only)")
    parser.add_argument("--skip-review", action="store_true", default=False, help="Skip grouping review UI — use AI proposal directly")
    parser.add_argument("--force-review", action="store_true", default=False, help="Force review even if grouping_approved.json exists")
    parser.add_argument("--no-browser", action="store_true", default=False, help="Do not auto-open browser (use over SSH)")

    args = parser.parse_args()
    run(args.input, args.output_dir, args.config, args.format,
        args.skip_llm, args.skip_review, args.force_review, args.no_browser)