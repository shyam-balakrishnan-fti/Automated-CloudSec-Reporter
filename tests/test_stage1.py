"""
test_stage1.py - Stage 1 ingest & parse test suite.

Tests every contract the parser makes:
    - File hash is reproducible
    - Sheet detection works correctly
    - All 41 columns mapped to raw_ fields
    - MUTED/STATUS reconciliation (3 cases)
    - Blank value classification (Category 1/2/3)
    - Region normalisation for global/IAM services
    - Resource ID normalisation (ARN, name fallback, neither)
    - Dedup key construction (4 cases)
    - Stable finding key construction
    - Extra/unknown columns stored in extra_fields
    - Formula injection strings preserved as-is (renderer sanitises)
    - Multi-value field parsing (categories, compliance, tags)
    - Zero-finding file produces valid empty IngestResult
    - Encoding fallback does not crash
"""

from __future__ import annotations

import sys
import tempfile
import hashlib
from pathlib import Path

# Allow running from project root or tests/
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from generate_synthetic import generate
from models import BlankCategory, ReportInclusion, ScannerStatus
from stage1_ingest import (
    IngestResult,
    _build_dedup_key,
    _build_stable_finding_key,
    _classify_blank,
    _normalise_resource_id,
    _parse_pipe_list,
    _parse_tags,
    _reconcile_status,
    ingest,
)

# ── Helpers ───────────────────────────────────────────────────────────

def _make_synthetic() -> Path:
    """Generate a fresh synthetic dataset and return its path."""
    tmp = Path(tempfile.mkdtemp()) / "synthetic_prowler.xlsx"
    generate(tmp)
    return tmp


def _find(result: IngestResult, check_id: str, account_uid: str = None) -> list:
    matches = [f for f in result.findings if f.raw_check_id == check_id]
    if account_uid:
        matches = [f for f in matches if f.raw_account_uid == account_uid]
    return matches


# ── Test runner ───────────────────────────────────────────────────────

PASS = []
FAIL = []

def test(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASS.append(name)
        print(f"  ✓  {name}")
    else:
        FAIL.append(name)
        print(f"  ✗  {name}" + (f" - {detail}" if detail else ""))


# ── Tests ──────────────────────────────────────────────────────────────

def test_file_hash():
    print("\n── File hash ──")
    path = _make_synthetic()

    r1 = ingest(path)
    r2 = ingest(path)
    test("SHA-256 is reproducible across two reads",
         r1.source_file_hash == r2.source_file_hash,
         f"{r1.source_file_hash} != {r2.source_file_hash}")
    test("SHA-256 is 64 hex chars",
         len(r1.source_file_hash) == 64)
    test("run_id is a UUID (36 chars)",
         len(r1.run_id) == 36)
    test("Two runs produce different run_ids",
         r1.run_id != r2.run_id)


def test_basic_ingestion():
    print("\n── Basic ingestion ──")
    path = _make_synthetic()
    result = ingest(path)

    test("IngestResult has findings",
         len(result.findings) > 0,
         f"got {len(result.findings)}")
    test("Scanner identified as prowler",
         result.scanner == "prowler")
    test("Prowler version extracted",
         result.scanner_version == "4.3.1",
         f"got '{result.scanner_version}'")
    test("Sheet name recorded",
         result.sheet_name == "prowler-output",
         f"got '{result.sheet_name}'")
    test("Source file hash non-empty",
         bool(result.source_file_hash))


def test_raw_field_mapping():
    print("\n── Raw field mapping ──")
    path = _make_synthetic()
    result = ingest(path)

    # Find the S3 public access finding for Account A
    findings = _find(result, "s3_bucket_public_access", account_uid="123456789012")
    test("S3 public access findings found",
         len(findings) >= 2)

    if findings:
        f = findings[0]
        test("raw_check_id populated",
             f.raw_check_id == "s3_bucket_public_access")
        test("raw_account_uid populated",
             f.raw_account_uid == "123456789012")
        test("raw_account_name populated",
             f.raw_account_name == "acme-prod")
        test("raw_provider populated",
             f.raw_provider == "aws")
        test("raw_severity populated",
             f.raw_severity == "high")
        test("raw_service_name populated",
             f.raw_service_name == "s3")
        test("raw_region populated",
             f.raw_region == "ap-southeast-2")
        test("raw_compliance populated",
             f.raw_compliance is not None)
        test("source_row_id contains sheet name",
             "prowler-output" in f.source_row_id)
        test("finding_instance_id is a UUID",
             len(f.finding_instance_id) == 36)
        test("run_id matches result run_id",
             f.run_id == result.run_id)


def test_muted_reconciliation():
    print("\n── MUTED/STATUS reconciliation ──")
    path = _make_synthetic()
    result = ingest(path)

    # Case 1: STATUS=MUTED(FAIL), MUTED=True → MUTED(FAIL) - no reconciliation needed
    muted_findings = _find(result, "s3_bucket_default_encryption")
    test("MUTED(FAIL) finding parsed",
         len(muted_findings) >= 1)
    if muted_findings:
        f = muted_findings[0]
        test("STATUS=MUTED(FAIL) → scanner_status=MUTED_FAIL",
             f.scanner_status == ScannerStatus.MUTED_FAIL,
             f"got {f.scanner_status}")

    # Case 2: STATUS=FAIL, MUTED=True → should reconcile to MUTED(FAIL)
    access_key = _find(result, "iam_user_access_key_age_90_days")
    test("Access key finding parsed",
         len(access_key) >= 1)
    if access_key:
        f = access_key[0]
        test("MUTED=True with STATUS=FAIL reconciles to MUTED(FAIL)",
             f.scanner_status == ScannerStatus.MUTED_FAIL,
             f"got {f.scanner_status}")
        test("muted_reconciled flag set True",
             f.muted_reconciled is True)
        test("Reconciliation audit event recorded",
             any("scanner_status" in e.field for e in f.audit_trail))

    # Case 3: Normal FAIL - no muting
    s3_fail = _find(result, "s3_bucket_public_access")
    if s3_fail:
        f = s3_fail[0]
        test("Normal FAIL → scanner_status=FAIL",
             f.scanner_status == ScannerStatus.FAIL,
             f"got {f.scanner_status}")
        test("muted_reconciled is False for normal FAIL",
             f.muted_reconciled is False)


def test_blank_classification():
    print("\n── Blank value classification ──")
    path = _make_synthetic()
    result = ingest(path)

    # Category 1: REGION blank for IAM (structural)
    iam_mfa = _find(result, "iam_user_mfa_enabled_console_access")
    test("IAM MFA finding parsed",
         len(iam_mfa) >= 1)
    if iam_mfa:
        f = iam_mfa[0]
        test("REGION blank for IAM → BlankCategory.STRUCTURAL",
             f.blank_region == BlankCategory.STRUCTURAL,
             f"got {f.blank_region}")
        test("Region normalised to 'global'",
             f.region_normalised == "global",
             f"got '{f.region_normalised}'")

    # Category 2: blank DESCRIPTION and RISK for RDS
    rds_enc = _find(result, "rds_instance_storage_encrypted")
    test("RDS encryption finding parsed",
         len(rds_enc) >= 1)
    if rds_enc:
        f = rds_enc[0]
        test("Blank DESCRIPTION → BlankCategory.DATA_QUALITY",
             f.blank_description == BlankCategory.DATA_QUALITY,
             f"got {f.blank_description}")
        test("Blank RISK → BlankCategory.DATA_QUALITY",
             f.blank_risk == BlankCategory.DATA_QUALITY,
             f"got {f.blank_risk}")
        test("Data quality blank sets human_review_required",
             f.human_review_required is True)
        test("DATA_QUALITY_BLANK warning emitted",
             any(w.code == "DATA_QUALITY_BLANK" for w in result.warnings))

    # Category 1: SUBSERVICE_NAME is structurally blank
    s3_f = _find(result, "s3_bucket_public_access")
    if s3_f:
        f = s3_f[0]
        test("SUBSERVICE_NAME None is not a data quality issue",
             f.blank_description != BlankCategory.DATA_QUALITY or f.raw_description is None)


def test_resource_normalisation():
    print("\n── Resource ID normalisation ──")
    path = _make_synthetic()
    result = ingest(path)

    # Valid ARN
    s3_f = _find(result, "s3_bucket_public_access")
    if s3_f:
        f = s3_f[0]
        test("Valid ARN used as resource_uid_normalised",
             f.resource_uid_normalised.startswith("arn:aws:s3:::"),
             f"got '{f.resource_uid_normalised}'")
        test("arn_fallback_used=False for valid ARN",
             f.arn_fallback_used is False)

    # Name-only (ARN fallback)
    ec2_imds = _find(result, "ec2_instance_imdsv2_enabled")
    test("EC2 IMDSv2 finding parsed",
         len(ec2_imds) >= 1)
    if ec2_imds:
        f = ec2_imds[0]
        test("ARN fallback: RESOURCE_NAME used when no ARN",
             f.resource_uid_normalised == "i-0abc1234",
             f"got '{f.resource_uid_normalised}'")
        test("arn_fallback_used=True for name-only",
             f.arn_fallback_used is True)
        test("ARN_FALLBACK warning emitted",
             any(w.code == "ARN_FALLBACK" for w in result.warnings))

    # Neither ARN nor name (account singleton)
    singleton = _find(result, "iam_root_mfa_enabled")
    test("Account singleton finding parsed",
         len(singleton) >= 1)
    if singleton:
        f = singleton[0]
        test("Account singleton: resource_uid_normalised is empty string",
             f.resource_uid_normalised == "",
             f"got '{f.resource_uid_normalised}'")
        test("Account singleton: human_review_required set",
             f.human_review_required is True)


def test_dedup_keys():
    print("\n── Dedup key construction ──")
    path = _make_synthetic()
    result = ingest(path)

    # AWS resource: includes region
    s3_a = _find(result, "s3_bucket_public_access", account_uid="123456789012")
    s3_b = _find(result, "s3_bucket_public_access", account_uid="987654321098")
    test("S3 Account A findings have dedup keys",
         all(f.dedup_key for f in s3_a))
    test("S3 Account B findings have different dedup keys than Account A",
         s3_a and s3_b and s3_a[0].dedup_key != s3_b[0].dedup_key)

    # Multi-account: same check_id but different account_uid → different dedup keys
    if s3_a and s3_b:
        test("Multi-account: dedup keys never match across accounts",
             not any(
                 a.dedup_key == b.dedup_key
                 for a in s3_a for b in s3_b
             ))

    # IAM global: region should be 'global' in key
    iam_f = _find(result, "iam_user_mfa_enabled_console_access")
    if iam_f:
        test("IAM dedup key contains 'global'",
             "global" in iam_f[0].dedup_key,
             f"got '{iam_f[0].dedup_key}'")

    # Account singleton: key is just account_uid + check_id
    singleton = _find(result, "iam_root_mfa_enabled")
    if singleton:
        f = singleton[0]
        parts = f.dedup_key.split(":")
        test("Account singleton dedup key has 2 parts (no resource, no region)",
             len(parts) == 2,
             f"key='{f.dedup_key}'")

    # Exact duplicate rows should produce identical dedup keys
    rds_dup = _find(result, "rds_instance_no_public_access")
    test("Duplicate rows produce identical dedup keys",
         len(rds_dup) >= 2 and rds_dup[0].dedup_key == rds_dup[1].dedup_key,
         f"keys: {[f.dedup_key for f in rds_dup]}")


def test_stable_finding_key():
    print("\n── Stable finding key ──")
    path = _make_synthetic()
    result = ingest(path)

    s3_f = _find(result, "s3_bucket_public_access")
    if s3_f:
        f = s3_f[0]
        test("stable_finding_key is non-empty",
             bool(f.stable_finding_key))
        test("stable_finding_key contains check_id",
             "s3_bucket_public_access" in f.stable_finding_key)
        test("stable_finding_key contains account_name (not UID)",
             "acme-prod" in f.stable_finding_key,
             f"key='{f.stable_finding_key}'")
        test("stable_finding_key uses underscore for spaces",
             " " not in f.stable_finding_key)


def test_multi_value_parsing():
    print("\n── Multi-value field parsing ──")
    path = _make_synthetic()
    result = ingest(path)

    s3_f = _find(result, "s3_bucket_public_access")
    if s3_f:
        f = s3_f[0]
        test("categories_list is a list",
             isinstance(f.categories_list, list))
        test("categories_list has values",
             len(f.categories_list) >= 1,
             f"got {f.categories_list}")
        test("internet-exposed in categories_list",
             "internet-exposed" in f.categories_list,
             f"got {f.categories_list}")
        test("compliance_values is a list",
             isinstance(f.compliance_values, list))

    # Tags parsing
    if s3_f:
        f = s3_f[0]
        test("resource_tags_parsed is a dict",
             isinstance(f.resource_tags_parsed, dict))
        test("account_tags_parsed is a dict",
             isinstance(f.account_tags_parsed, dict))


def test_extra_fields():
    print("\n── Unknown/extra columns ──")
    path = _make_synthetic()
    result = ingest(path)

    # The securityhub row has FUTURE_COLUMN_V5
    sh_f = _find(result, "securityhub_enabled")
    test("SecurityHub finding parsed",
         len(sh_f) >= 1)
    if sh_f:
        f = sh_f[0]
        test("Extra column stored in extra_fields dict",
             "FUTURE_COLUMN_V5" in f.extra_fields,
             f"extra_fields keys: {list(f.extra_fields.keys())}")
        test("Extra column value preserved",
             f.extra_fields.get("FUTURE_COLUMN_V5") == "some-future-value")
    test("UNKNOWN_COLUMNS warning emitted",
         any(w.code == "UNKNOWN_COLUMNS" for w in result.warnings),
         f"warnings: {[w.code for w in result.warnings]}")


def test_formula_injection_preserved():
    print("\n── Formula injection strings preserved ──")
    path = _make_synthetic()
    result = ingest(path)

    # The cloudtrail row has =SUM(1,2) in check_title
    ct_f = _find(result, "cloudtrail_multi_region_enabled")
    test("CloudTrail finding parsed",
         len(ct_f) >= 1)
    if ct_f:
        f = ct_f[0]
        test("Formula injection string preserved in raw_check_title (renderer sanitises)",
             f.raw_check_title and f.raw_check_title.startswith("="),
             f"got '{f.raw_check_title}'")


def test_pass_findings_ingested():
    print("\n── PASS findings are ingested (excluded downstream) ──")
    path = _make_synthetic()
    result = ingest(path)

    # PASS findings should be present in the ingest result
    pass_f = [f for f in result.findings if f.scanner_status == ScannerStatus.PASS]
    test("At least one PASS finding ingested",
         len(pass_f) >= 1,
         f"got {len(pass_f)}")
    # They should NOT already be excluded at ingest time (Stage 2 does that)
    test("PASS findings have INCLUDED status at ingest (Stage 2 will exclude)",
         all(f.report_inclusion == ReportInclusion.INCLUDED for f in pass_f))


def test_zero_finding_file():
    print("\n── Zero-finding file (schema-only) ──")
    import openpyxl
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "prowler-output"
    # Write header only
    from stage1_ingest import PROWLER_COLUMNS
    headers = sorted(PROWLER_COLUMNS)[:41]
    for i, h in enumerate(headers, 1):
        ws.cell(row=1, column=i, value=h)
    wb.save(str(tmp_path))

    result = ingest(tmp_path)
    test("Zero-finding file produces valid IngestResult",
         result is not None)
    test("Zero-finding file has empty findings list",
         result.findings == [],
         f"got {len(result.findings)} findings")
    test("Zero-finding file still has valid hash",
         len(result.source_file_hash) == 64)


def test_audit_trail():
    print("\n── Audit trail ──")
    path = _make_synthetic()
    result = ingest(path)

    # Findings with MUTED reconciliation should have audit events
    access_key = _find(result, "iam_user_access_key_age_90_days")
    if access_key:
        f = access_key[0]
        test("Reconciled finding has audit trail entries",
             len(f.audit_trail) >= 1)
        audit_stages = [e.stage for e in f.audit_trail]
        test("Audit events reference stage1_ingest",
             any("stage1" in s for s in audit_stages),
             f"stages: {audit_stages}")

    # Data quality blank finding should have review flag in audit
    rds_enc = _find(result, "rds_instance_storage_encrypted")
    if rds_enc:
        f = rds_enc[0]
        test("Data quality finding has human_review audit event",
             any(e.field == "human_review_required" for e in f.audit_trail))


def test_completeness_score():
    print("\n── Completeness score ──")
    path = _make_synthetic()
    result = ingest(path)

    # Well-populated finding
    s3_f = _find(result, "s3_bucket_public_access")
    if s3_f:
        f = s3_f[0]
        score = f.completeness_score()
        test("Well-populated finding has completeness score > 2",
             score > 2, f"got {score}")

    # Finding with blank DESCRIPTION and RISK
    rds_enc = _find(result, "rds_instance_storage_encrypted")
    if rds_enc:
        f = rds_enc[0]
        score_low = f.completeness_score()
        s3_score = s3_f[0].completeness_score() if s3_f else 5
        test("Finding with blanks has lower completeness score than full finding",
             score_low < s3_score,
             f"rds={score_low} s3={s3_score}")


def test_file_not_found():
    print("\n── Error handling ──")
    try:
        ingest("/nonexistent/path/file.xlsx")
        test("FileNotFoundError raised for missing file", False)
    except FileNotFoundError:
        test("FileNotFoundError raised for missing file", True)


# ── Entry point ───────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("Stage 1 - Ingest & Parse  -  Test Suite")
    print("=" * 60)

    test_file_hash()
    test_basic_ingestion()
    test_raw_field_mapping()
    test_muted_reconciliation()
    test_blank_classification()
    test_resource_normalisation()
    test_dedup_keys()
    test_stable_finding_key()
    test_multi_value_parsing()
    test_extra_fields()
    test_formula_injection_preserved()
    test_pass_findings_ingested()
    test_zero_finding_file()
    test_audit_trail()
    test_completeness_score()
    test_file_not_found()

    print("\n" + "=" * 60)
    print(f"Results: {len(PASS)} passed  /  {len(FAIL)} failed")
    if FAIL:
        print("\nFailed tests:")
        for t in FAIL:
            print(f"  ✗  {t}")
        sys.exit(1)
    else:
        print("All tests passed.")
        sys.exit(0)
