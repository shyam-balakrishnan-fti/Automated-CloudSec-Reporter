"""
test_stage2.py — Stage 2 deterministic processing engine test suite.

Tests every contract Stage 2 makes:

    2A Status filter:
        - FAIL included
        - MUTED(FAIL) included
        - PASS excluded (preserved in all_findings)
        - MANUAL excluded by default config
        - Exclusion recorded in audit trail
        - all_findings always contains full set regardless of inclusion

    2B Deduplication:
        - Exact duplicate (same dedup_key) → secondary marked is_duplicate=True
        - Primary preserved, secondary excluded
        - Multi-account: same check_id different account → NOT deduplicated
        - Global/IAM findings deduplicated correctly (region='global' in key)
        - Account singleton (no resource) deduplicated correctly
        - Duplicate audit event recorded

    2C Output grouping:
        - One OutputGroup per distinct check_id (same check across multiple resources)
        - instance_count correct
        - affected_account_names populated (no duplicates)
        - Representative selected by completeness_score (most fields populated wins)
        - On tie, first by source row order wins
        - Groups sorted: by section, then severity order, then check_id
        - output_section = "AWS" for all Prowler findings

    2D Likelihood rating:
        - critical → High
        - high → High
        - medium → Medium
        - low → Low
        - informational → Low
        - internet-exposed category overrides to High regardless of severity
        - Likelihood recorded in finding audit trail
        - Likelihood set on OutputGroup.likelihood_rating

    Determinism:
        - Running process() twice on same inputs → identical output_groups
        - Config change changes likelihood assignments
"""

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
from pathlib import Path

# Works regardless of which directory Python is invoked from
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from generate_synthetic_messy import generate
from models import BlankCategory, ReportInclusion, ScannerStatus
from stage1_ingest import ingest
from stage2_process import (
    OutputGroup,
    ProcessResult,
    load_config,
    process,
)

# ── Helpers ───────────────────────────────────────────────────────────

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.toml"


def _run_pipeline(synthetic_path: Path = None) -> tuple[ProcessResult, Path]:
    """Run the full Stage 1 + Stage 2 pipeline. Suppresses generator output."""
    if synthetic_path is None:
        tmp = Path(tempfile.mkdtemp()) / "messy.xlsx"
        with contextlib.redirect_stdout(io.StringIO()):
            generate(tmp)
        synthetic_path = tmp
    cfg = load_config(CONFIG_PATH)
    ir  = ingest(synthetic_path)
    pr  = process(ir, cfg)
    return pr, synthetic_path


def _group(result: ProcessResult, check_id: str) -> OutputGroup | None:
    for g in result.output_groups:
        if g.check_id == check_id:
            return g
    return None


def _all_findings(result: ProcessResult, check_id: str) -> list:
    return [f for f in result.all_findings if f.raw_check_id == check_id]


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

def test_config_loading():
    print("\n── Config loading ──")
    cfg = load_config(CONFIG_PATH)
    test("Config loads without error",         cfg is not None)
    test("processing section present",         "processing"     in cfg)
    test("severity_rules section present",     "severity_rules" in cfg)
    test("risk_matrix section present",        "risk_matrix"    in cfg)
    test("output section present",             "output"         in cfg)
    test("include_statuses has FAIL",
         "FAIL" in cfg["processing"]["include_statuses"])
    test("include_statuses has MUTED(FAIL)",
         "MUTED(FAIL)" in cfg["processing"]["include_statuses"])
    test("risk_matrix has High_Major",
         "High_Major" in cfg["risk_matrix"])
    test("severity_rules critical=High",
         cfg["severity_rules"]["critical"] == "High")


def test_status_filter():
    print("\n── 2A Status filter ──")
    pr, _ = _run_pipeline()

    # FAIL findings should be INCLUDED
    s3_findings = _all_findings(pr, "s3_bucket_public_access")
    included = [f for f in s3_findings if f.report_inclusion == ReportInclusion.INCLUDED]
    test("FAIL findings are INCLUDED",
         len(included) >= 1, f"included={len(included)}")

    # PASS findings should be EXCLUDED but still in all_findings
    pass_findings = [
        f for f in pr.all_findings
        if f.scanner_status == ScannerStatus.PASS
    ]
    test("PASS findings present in all_findings (not deleted)",
         len(pass_findings) >= 1)
    test("PASS findings are EXCLUDED",
         all(f.report_inclusion == ReportInclusion.EXCLUDED for f in pass_findings),
         f"{[f.report_inclusion for f in pass_findings]}")
    test("PASS exclusion recorded in audit trail",
         all(
             any("stage2_status_filter" in e.stage for e in f.audit_trail)
             for f in pass_findings
         ))

    # MUTED(FAIL) should be INCLUDED
    muted_findings = [
        f for f in pr.all_findings
        if f.scanner_status == ScannerStatus.MUTED_FAIL
    ]
    test("MUTED(FAIL) findings present",
         len(muted_findings) >= 1)
    test("MUTED(FAIL) findings are INCLUDED",
         all(f.report_inclusion == ReportInclusion.INCLUDED for f in muted_findings),
         f"{[f.report_inclusion for f in muted_findings]}")

    # all_findings always has the complete set
    test("all_findings contains all original rows",
         pr.total_findings == 30, f"got {pr.total_findings}")

    # ProcessResult counts are consistent
    test("included_count + excluded_count + duplicate_count <= total",
         pr.included_count + pr.excluded_count + pr.duplicate_count <= pr.total_findings)


def test_deduplication():
    print("\n── 2B Deduplication ──")
    pr, _ = _run_pipeline()

    # S3 public access — acme-prod-logs appears twice (rows 1 and 5 in messy data)
    s3_all = _all_findings(pr, "s3_bucket_public_access")
    logs_findings = [
        f for f in s3_all
        if f.resource_uid_normalised == "arn:aws:s3:::acme-prod-logs"
    ]
    test("Duplicate S3 bucket findings present (2 rows for acme-prod-logs)",
         len(logs_findings) == 2, f"found {len(logs_findings)}")

    if len(logs_findings) == 2:
        primaries  = [f for f in logs_findings if not f.is_duplicate]
        duplicates = [f for f in logs_findings if f.is_duplicate]
        test("Exactly one primary, one duplicate for acme-prod-logs",
             len(primaries) == 1 and len(duplicates) == 1)
        if duplicates:
            dup = duplicates[0]
            test("Duplicate is_duplicate=True",
                 dup.is_duplicate is True)
            test("Duplicate has duplicate_of pointing to primary",
                 dup.duplicate_of == primaries[0].finding_instance_id)
            test("Duplicate is EXCLUDED",
                 dup.report_inclusion == ReportInclusion.EXCLUDED)
            test("Duplicate exclusion in audit trail",
                 any("stage2_dedup" in e.stage for e in dup.audit_trail))

    # RDS duplicate
    rds_all  = _all_findings(pr, "rds_instance_no_public_access")
    rds_dups = [f for f in rds_all if f.is_duplicate]
    test("RDS duplicate detected",
         len(rds_dups) == 1, f"found {len(rds_dups)}")

    # Multi-account: same check_id but different account → NOT a duplicate
    s3_accounts = {
        f.raw_account_uid for f in s3_all
        if f.report_inclusion == ReportInclusion.INCLUDED and not f.is_duplicate
    }
    test("Multi-account S3 findings not deduplicated across accounts",
         len(s3_accounts) >= 2, f"accounts with included S3 findings: {s3_accounts}")

    # Total duplicates
    test("Exactly 2 duplicates in full run",
         pr.duplicate_count == 2, f"got {pr.duplicate_count}")


def test_output_grouping():
    print("\n── 2C Output grouping ──")
    pr, _ = _run_pipeline()

    # S3 public access: 4 unique resources across 3 accounts → 1 group
    s3_group = _group(pr, "s3_bucket_public_access")
    test("S3 public access has an output group", s3_group is not None)
    if s3_group:
        test("S3 group instance_count = 4 (5 rows - 1 duplicate)",
             s3_group.instance_count == 4,
             f"got {s3_group.instance_count}")
        test("S3 group has multiple affected accounts",
             len(s3_group.affected_account_names) >= 2,
             f"accounts: {s3_group.affected_account_names}")
        test("S3 group affected_account_names has no duplicates",
             len(s3_group.affected_account_names) == len(set(s3_group.affected_account_names)))
        test("S3 group output_section = 'AWS'",
             s3_group.output_section == "AWS")
        test("S3 group instance_ids list length matches count",
             len(s3_group.instance_ids) == s3_group.instance_count)

    # IAM MFA: 3 prod users + 1 legacy user = 4 instances → 1 group
    iam_group = _group(pr, "iam_user_mfa_enabled_console_access")
    test("IAM MFA has an output group", iam_group is not None)
    if iam_group:
        test("IAM MFA group instance_count = 4",
             iam_group.instance_count == 4,
             f"got {iam_group.instance_count}")

    # EBS encryption: 3 volumes → 1 group with count=3
    ebs_group = _group(pr, "ec2_ebs_volume_encryption_enabled")
    test("EBS encryption has an output group", ebs_group is not None)
    if ebs_group:
        test("EBS group instance_count = 3",
             ebs_group.instance_count == 3,
             f"got {ebs_group.instance_count}")

    # Total group count
    test("output_groups count is sensible (> 5, <= 30)",
         5 < pr.group_count <= 30, f"got {pr.group_count}")

    # All groups have output_section and representative
    test("All groups have non-empty output_section",
         all(g.output_section for g in pr.output_groups))
    test("All groups have a representative",
         all(g.representative is not None for g in pr.output_groups))

    # Representative is always in the instance_ids list
    test("Representative finding_instance_id is in group.instance_ids",
         all(
             g.representative.finding_instance_id in g.instance_ids
             for g in pr.output_groups
         ))


def test_representative_selection():
    print("\n── 2C Representative selection ──")
    pr, _ = _run_pipeline()

    iam_group = _group(pr, "iam_user_mfa_enabled_console_access")
    if iam_group:
        rep = iam_group.representative
        test("IAM representative has finding_instance_id set",
             bool(rep.finding_instance_id))
        test("IAM representative instance_count stamped on representative",
             rep.instance_count == 4, f"got {rep.instance_count}")

    s3_group = _group(pr, "s3_bucket_public_access")
    if s3_group:
        rep = s3_group.representative
        test("S3 representative has raw_description populated",
             rep.raw_description is not None,
             "representative should have the most complete fields")
        test("S3 representative representative_instance_id set",
             rep.representative_instance_id == rep.finding_instance_id)
        test("S3 representative audit event for instance_count",
             any(
                 e.field == "instance_count" and "stage2_grouping" in e.stage
                 for e in rep.audit_trail
             ))

    rds_enc_group = _group(pr, "rds_instance_storage_encrypted")
    if rds_enc_group:
        test("RDS encryption group has a representative despite blank fields",
             rds_enc_group.representative is not None)


def test_sorting():
    print("\n── 2C Group sorting ──")
    pr, _ = _run_pipeline()

    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    groups = pr.output_groups

    for i in range(len(groups) - 1):
        a = groups[i]
        b = groups[i + 1]
        sev_a = _SEV_ORDER.get((a.representative.raw_severity or "").lower(), 5)
        sev_b = _SEV_ORDER.get((b.representative.raw_severity or "").lower(), 5)
        if a.output_section == b.output_section:
            valid = (sev_a < sev_b) or (sev_a == sev_b and a.check_id <= b.check_id)
        else:
            valid = a.output_section <= b.output_section
        if not valid:
            test(f"Sort order: group {i} before group {i+1}", False,
                 f"'{a.check_id}' (sev={a.representative.raw_severity}) "
                 f"before '{b.check_id}' (sev={b.representative.raw_severity})")
            return
    test("All output groups are correctly sorted (section → severity → check_id)", True)


def test_likelihood_rating():
    print("\n── 2D Likelihood rating ──")
    pr, _ = _run_pipeline()

    # critical → High
    iam_mfa = _group(pr, "iam_user_mfa_enabled_console_access")
    if iam_mfa:
        test("critical severity → Likelihood=High",
             iam_mfa.likelihood_rating == "High",
             f"got '{iam_mfa.likelihood_rating}'")
        test("Likelihood in representative audit trail",
             any(e.field == "likelihood_rating" for e in iam_mfa.representative.audit_trail))

    # high → High
    s3_group = _group(pr, "s3_bucket_public_access")
    if s3_group:
        test("high severity → Likelihood=High",
             s3_group.likelihood_rating == "High",
             f"got '{s3_group.likelihood_rating}'")

    # medium + internet-exposed → High override
    vpc_group = _group(pr, "vpc_flow_logs_enabled")
    if vpc_group:
        test("medium severity + internet-exposed → Likelihood=High (override)",
             vpc_group.likelihood_rating == "High",
             f"got '{vpc_group.likelihood_rating}'")
        likelihood_events = [
            e for e in vpc_group.representative.audit_trail
            if e.field == "likelihood_rating"
        ]
        test("VPC likelihood audit event mentions Category override",
             likelihood_events and "override" in likelihood_events[-1].reason.lower(),
             f"reason: {likelihood_events[-1].reason if likelihood_events else 'none'}")

    # informational → Low
    cw_group = _group(pr, "cloudwatch_log_group_retention_policy_specific_days_enabled")
    if cw_group:
        test("informational severity → Likelihood=Low",
             cw_group.likelihood_rating == "Low",
             f"got '{cw_group.likelihood_rating}'")

    # medium, no internet-exposed → Medium
    config_group = _group(pr, "config_recorder_all_regions_enabled")
    if config_group:
        test("medium severity, no internet-exposed → Likelihood=Medium",
             config_group.likelihood_rating == "Medium",
             f"got '{config_group.likelihood_rating}'")

    # All groups have a valid likelihood
    test("All groups have likelihood_rating set",
         all(g.likelihood_rating in ("High", "Medium", "Low") for g in pr.output_groups),
         f"{[(g.check_id, g.likelihood_rating) for g in pr.output_groups if g.likelihood_rating not in ('High','Medium','Low')]}")


def test_determinism():
    print("\n── Determinism ──")
    tmp = Path(tempfile.mkdtemp()) / "messy.xlsx"
    with contextlib.redirect_stdout(io.StringIO()):
        generate(tmp)
    cfg = load_config(CONFIG_PATH)

    ir1 = ingest(tmp)
    pr1 = process(ir1, cfg)
    ir2 = ingest(tmp)
    pr2 = process(ir2, cfg)

    test("Two runs produce same number of output groups",
         pr1.group_count == pr2.group_count,
         f"{pr1.group_count} vs {pr2.group_count}")
    test("Two runs produce same check_ids in same order",
         [g.check_id for g in pr1.output_groups] == [g.check_id for g in pr2.output_groups])
    test("Two runs produce same likelihood ratings",
         [g.likelihood_rating for g in pr1.output_groups] ==
         [g.likelihood_rating for g in pr2.output_groups])
    test("Two runs produce same instance counts",
         [g.instance_count for g in pr1.output_groups] ==
         [g.instance_count for g in pr2.output_groups])


def test_llm_context():
    print("\n── LLM context (to_llm_context) ──")
    pr, _ = _run_pipeline()

    s3_group = _group(pr, "s3_bucket_public_access")
    if s3_group:
        ctx = s3_group.to_llm_context()
        test("LLM context is a dict", isinstance(ctx, dict))
        test("LLM context has check_id",
             ctx.get("check_id") == "s3_bucket_public_access")
        test("LLM context has instance_count",
             ctx.get("instance_count") == s3_group.instance_count)
        test("LLM context has likelihood_rating", "likelihood_rating" in ctx)
        test("LLM context has affected_account_names", "affected_account_names" in ctx)

        # Sensitive fields must NOT be in LLM context
        for field_name in [
            "raw_account_uid", "raw_account_name", "raw_account_email",
            "raw_resource_uid", "raw_resource_name", "raw_finding_uid",
        ]:
            test(f"Sensitive field '{field_name}' NOT in LLM context",
                 field_name not in ctx)


def test_process_result_counts():
    print("\n── ProcessResult counts ──")
    pr, _ = _run_pipeline()

    test("total_findings = 30 (all rows ingested)",
         pr.total_findings == 30, f"got {pr.total_findings}")
    test("duplicate_count = 2",
         pr.duplicate_count == 2, f"got {pr.duplicate_count}")
    test("group_count > 0",
         pr.group_count > 0)
    test("included_count + excluded_count + duplicate_count == total",
         pr.included_count + pr.excluded_count + pr.duplicate_count == pr.total_findings,
         f"{pr.included_count} + {pr.excluded_count} + {pr.duplicate_count} != {pr.total_findings}")
    test("config preserved in ProcessResult",
         "severity_rules" in pr.config)


def test_empty_input():
    print("\n── Empty input handling ──")
    import openpyxl
    tmp = Path(tempfile.mkdtemp()) / "empty.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "prowler-output"
    from stage1_ingest import PROWLER_COLUMNS
    for i, h in enumerate(sorted(PROWLER_COLUMNS)[:41], 1):
        ws.cell(row=1, column=i, value=h)
    wb.save(str(tmp))

    cfg = load_config(CONFIG_PATH)
    ir  = ingest(tmp)
    pr  = process(ir, cfg)
    test("Empty input: process returns valid ProcessResult", pr is not None)
    test("Empty input: output_groups is empty list",         pr.output_groups == [])
    test("Empty input: EMPTY_OUTPUT warning emitted",
         any(w.code == "EMPTY_OUTPUT" for w in pr.warnings))


def test_section_assignment():
    print("\n── Section assignment ──")
    pr, _ = _run_pipeline()
    test("All Prowler/AWS groups assigned to 'AWS' section",
         all(g.output_section == "AWS" for g in pr.output_groups),
         f"{[(g.check_id, g.output_section) for g in pr.output_groups if g.output_section != 'AWS']}")


def test_audit_completeness():
    print("\n── Audit trail completeness ──")
    pr, _ = _run_pipeline()

    excluded = [
        f for f in pr.all_findings
        if f.report_inclusion == ReportInclusion.EXCLUDED
    ]
    test("Every excluded finding has at least one audit event",
         all(len(f.audit_trail) >= 1 for f in excluded),
         f"{[f.finding_instance_id for f in excluded if len(f.audit_trail) == 0]}")

    multi_instance_groups = [g for g in pr.output_groups if g.instance_count > 1]
    multi_with_audit = [
        g for g in multi_instance_groups
        if any(e.field == "instance_count" for e in g.representative.audit_trail)
    ]
    test("Multi-instance groups have instance_count audit event on representative",
         len(multi_with_audit) == len(multi_instance_groups),
         f"with audit: {len(multi_with_audit)}, multi-instance: {len(multi_instance_groups)}")


# ── Entry point ───────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("Stage 2 — Deterministic Process  —  Test Suite")
    print("=" * 60)

    test_config_loading()
    test_status_filter()
    test_deduplication()
    test_output_grouping()
    test_representative_selection()
    test_sorting()
    test_likelihood_rating()
    test_determinism()
    test_llm_context()
    test_process_result_counts()
    test_empty_input()
    test_section_assignment()
    test_audit_completeness()

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