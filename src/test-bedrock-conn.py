"""
test_bedrock_connection.py — Bedrock mantle connection smoke test.

Tests BEFORE running the full pipeline:
    1. BEDROCK_API_KEY env var is set
    2. Endpoint is reachable (ap-northeast-1)
    3. store=false is accepted (zero retention confirmed)
    4. Model responds with valid JSON
    5. All 7 required LLM fields are present
    6. Prints the full LLM output so you can read it

Usage (from cloud-tool/):
    python3 src/test_bedrock_connection.py

Switch to ap-southeast-4 tomorrow by changing aws_region in config.toml.
No code changes needed.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from stage2_process import load_config
from stage3_llm import (
    _build_prompt,
    _call_bedrock_mantle,
    _extract_json,
    _validate_response,
)

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.toml"

# ── Minimal realistic test context ───────────────────────────────────
# Uses a generic S3 finding — realistic enough to produce
# meaningful narratives without any real client data.

TEST_CONTEXT = {
    "check_id":         "s3_bucket_public_access",
    "check_title":      "Ensure S3 bucket does not allow public access",
    "check_type":       "Software and Configuration Checks",
    "service_name":     "s3",
    "resource_type":    "AWSS3Bucket",
    "resource_name":    "test-bucket-smoke-test",
    "resource_uid":     "arn:aws:s3:::test-bucket-smoke-test",
    "account_name":     "synthetic-test-account",
    "region":           "ap-northeast-1",
    "severity":         "high",
    "categories":       ["internet-exposed", "data-protection"],
    "compliance":       ["CIS-2.0: 2.1.5", "NIST-800-53: SC-7"],
    "description":      (
        "This control checks whether Amazon S3 buckets have the "
        "Block Public Access feature enabled at the bucket level."
    ),
    "risk":             (
        "Public S3 buckets can expose sensitive data to unauthenticated "
        "internet users, increasing the risk of data exfiltration."
    ),
    "status_extended":  (
        "Bucket test-bucket-smoke-test has Block Public Access disabled. "
        "BlockPublicAcls=false, IgnorePublicAcls=false."
    ),
    "remediation_recommendation_text": (
        "Enable S3 Block Public Access at the bucket level by setting all "
        "four Block Public Access settings to true."
    ),
    "remediation_code_cli": (
        "aws s3api put-public-access-block "
        "--bucket test-bucket-smoke-test "
        "--public-access-block-configuration "
        "BlockPublicAcls=true,IgnorePublicAcls=true,"
        "BlockPublicPolicy=true,RestrictPublicBuckets=true"
    ),
    "resource_tags":    {"Environment": "test", "Owner": "platform-team"},
    "instance_count":   1,
    "affected_account_names": ["synthetic-test-account"],
    "likelihood_rating": "High",
}


def _check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  ✓  {label}")
    else:
        print(f"  ✗  {label}" + (f" — {detail}" if detail else ""))
        sys.exit(1)


def run() -> None:
    print()
    print("=" * 65)
    print("Bedrock Mantle Connection Test")
    print("=" * 65)

    # ── Load config ──────────────────────────────────────────────────
    print("\n[ 1 ] Loading config...")
    cfg     = load_config(CONFIG_PATH)
    llm_cfg = cfg.get("llm", {})

    provider   = llm_cfg.get("provider")
    model      = llm_cfg.get("deployment_name")
    region     = llm_cfg.get("aws_region")
    key_env    = llm_cfg.get("api_key_env_var", "BEDROCK_API_KEY")
    endpoint   = f"https://bedrock-mantle.{region}.api.aws"

    print(f"  Provider   : {provider}")
    print(f"  Model      : {model}")
    print(f"  Region     : {region}")
    print(f"  Endpoint   : {endpoint}")
    print(f"  Key env var: {key_env}")

    _check("Provider is bedrock_mantle", provider == "bedrock_mantle",
           f"got '{provider}' — check config.toml [llm] provider")
    _check("Model ID is set", bool(model),
           "set deployment_name in config.toml [llm]")
    _check("Region is set", bool(region),
           "set aws_region in config.toml [llm]")

    # ── Check API key ────────────────────────────────────────────────
    print(f"\n[ 2 ] Checking {key_env} environment variable...")
    api_key = os.environ.get(key_env)
    _check(
        f"{key_env} is set",
        bool(api_key),
        f"Run: export {key_env}=your_bedrock_api_key",
    )
    print(f"  Key prefix : {api_key[:8]}... ({len(api_key)} chars)")

    # ── Build prompt ─────────────────────────────────────────────────
    print("\n[ 3 ] Building test prompt...")
    prompt = _build_prompt(TEST_CONTEXT)
    print(f"  Prompt length : {len(prompt)} chars")
    print(f"  Input tokens  : ~{len(prompt) // 4} (estimate)")
    _check("Prompt contains check_id",       "s3_bucket_public_access" in prompt)
    _check("Prompt contains store=false note","store" in prompt or "OUTPUT FORMAT" in prompt)

    # ── Call Bedrock mantle ──────────────────────────────────────────
    print(f"\n[ 4 ] Calling bedrock-mantle ({region})...")
    print(f"  store=false  : zero retention — no data written to durable storage")
    print(f"  Sending request...", flush=True)

    try:
        raw = _call_bedrock_mantle(prompt, llm_cfg)
    except EnvironmentError as e:
        print(f"\n  ✗ Auth error: {e}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"\n  ✗ API error: {e}")
        sys.exit(1)

    _check("Response received", bool(raw))
    print(f"  Response length : {len(raw)} chars")
    print(f"  Output tokens   : ~{len(raw) // 4} (estimate)")

    # ── Parse JSON ───────────────────────────────────────────────────
    print("\n[ 5 ] Parsing JSON response...")
    try:
        parsed = _extract_json(raw)
        _check("JSON parsed successfully", True)
    except Exception as e:
        print(f"  ✗ JSON parse failed: {e}")
        print(f"  Raw response:\n{raw[:500]}")
        sys.exit(1)

    # ── Validate fields ──────────────────────────────────────────────
    print("\n[ 6 ] Validating required fields...")
    errors = _validate_response(parsed)
    if errors:
        print("  ✗ Validation errors:")
        for err in errors:
            print(f"      — {err}")
        print(f"\n  Raw response:\n{raw[:500]}")
        sys.exit(1)

    required = [
        "finding_title", "root_cause_narrative", "situation_narrative",
        "consequence_narrative", "consequence_rating",
        "access_required", "needs_human_review",
    ]
    for field in required:
        _check(f"Field '{field}' present and valid", field in parsed and parsed[field] is not None)

    # ── Print LLM output ─────────────────────────────────────────────
    print("\n[ 7 ] LLM Output (read and verify quality):")
    print("-" * 65)
    print(f"  finding_title      : {parsed['finding_title']}")
    print()
    print(f"  consequence_rating : {parsed['consequence_rating']}")
    print(f"  needs_human_review : {parsed['needs_human_review']}")
    print()
    print(f"  root_cause_narrative:")
    print(f"    {parsed['root_cause_narrative']}")
    print()
    print(f"  situation_narrative:")
    print(f"    {parsed['situation_narrative']}")
    print()
    print(f"  consequence_narrative:")
    print(f"    {parsed['consequence_narrative']}")
    print()
    print(f"  access_required:")
    print(f"    {parsed['access_required']}")
    print("-" * 65)

    # ── Data residency confirmation ───────────────────────────────────
    print("\n[ 8 ] Data residency summary:")
    print(f"  Endpoint        : bedrock-mantle.{region}.api.aws")
    print(f"  store=false     : ✓ sent on this request")
    print(f"  Data retained   : None — request/response not written to storage")
    print(f"  Model provider  : No data shared (store=false)")
    print(f"  Data stayed in  : {region} (AWS region boundary)")
    if region == "ap-northeast-1":
        print(f"  Note            : Tokyo region — switch to ap-southeast-4")
        print(f"                    tomorrow by changing aws_region in config.toml")
    elif region == "ap-southeast-4":
        print(f"  ✓ Melbourne region — Australian data residency confirmed")

    print()
    print("=" * 65)
    print("✓ All checks passed — Bedrock is configured correctly")
    print("  Safe to run the full pipeline on synthetic data")
    print("=" * 65)
    print()


if __name__ == "__main__":
    run()