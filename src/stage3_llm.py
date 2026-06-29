"""
stage3_llm.py — Stage 3: LLM Enrichment

Responsibilities:
    - Build a structured prompt per OutputGroup with full finding context
    - Call the configured LLM (AWS Bedrock via Converse API)
    - Validate the returned JSON — all 7 required fields must be present and valid
    - On failure: retry once with a correction prompt
    - On second failure: write placeholder text, set llm_enrichment_failed=True
    - Write enrichment results back to the representative CanonicalFinding
    - Compute risk_rating from likelihood × consequence via the risk matrix
    - Record all enrichment events in the audit trail

Contract:
    enrich(process_result, config) -> EnrichResult

Data privacy:
    AWS Bedrock confirmed: model providers have no access to prompts or
    completions, data is not used for training, and retention is configurable
    to zero. Full finding context (including resource identifiers, account
    names, ARNs) is sent to produce accurate narratives.

LLM output fields (all required for final mode):
    finding_title          — normalised check title (≤ 120 chars)
    root_cause_narrative   — 1-3 sentences
    situation_narrative    — 2-4 sentences, scope language if instance_count > 1
    consequence_narrative  — 1-3 sentences
    consequence_rating     — Minor | Moderate | Major
    access_required        — 1 sentence
    needs_human_review     — bool, true if LLM is uncertain about any field
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from models import CanonicalFinding, ReportInclusion
from stage2_process import OutputGroup, ProcessResult

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────

VALID_CONSEQUENCE_RATINGS = {"Minor", "Moderate", "Major"}

REQUIRED_LLM_FIELDS = {
    "finding_title",
    "root_cause_narrative",
    "situation_narrative",
    "consequence_narrative",
    "consequence_rating",
    "access_required",
    "needs_human_review",
}

SYSTEM_PROMPT = (
    "You are a cloud security analyst writing a professional security "
    "assessment report. You always respond with valid JSON only. "
    "No preamble, no markdown fences, no explanation outside the JSON object."
)


# ── Prompt builder ────────────────────────────────────────────────────

def _build_prompt(ctx: dict[str, Any]) -> str:
    """
    Build the LLM prompt from an OutputGroup's full context dict.
    Full context is sent — AWS Bedrock does not share data with model providers.
    """
    instance_count  = ctx.get("instance_count", 1)
    account_names   = ctx.get("affected_account_names", [])
    likelihood      = ctx.get("likelihood_rating", "Medium")
    check_title     = ctx.get("check_title") or "Unknown check"
    check_type      = ctx.get("check_type") or ""
    service_name    = ctx.get("service_name") or ""
    resource_type   = ctx.get("resource_type") or ""
    resource_name   = ctx.get("resource_name") or ""
    resource_uid    = ctx.get("resource_uid") or ""
    account_name    = ctx.get("account_name") or ""
    region          = ctx.get("region") or ""
    severity        = ctx.get("severity") or "medium"
    description     = ctx.get("description") or ""
    risk            = ctx.get("risk") or ""
    remediation     = ctx.get("remediation_recommendation_text") or ""
    remediation_cli = ctx.get("remediation_code_cli") or ""
    remediation_tf  = ctx.get("remediation_code_terraform") or ""
    categories      = ctx.get("categories") or []
    compliance      = ctx.get("compliance") or []
    status_extended = ctx.get("status_extended") or ""
    resource_tags   = ctx.get("resource_tags") or {}

    # Scope language
    if instance_count > 1 and account_names:
        scope_note = (
            f"This finding affects {instance_count} resources across "
            f"{len(account_names)} account(s): {', '.join(account_names)}."
        )
    elif instance_count > 1:
        scope_note = f"This finding affects {instance_count} resources."
    else:
        scope_note = (
            f"This finding affects a single resource"
            + (f" ({resource_name})" if resource_name else "")
            + (f" in account '{account_name}'" if account_name else "")
            + (f" in region {region}" if region and region != "global" else "")
            + "."
        )

    # Resource identity block
    resource_block = ""
    if resource_uid or resource_name:
        resource_block = f"\nResource ARN:   {resource_uid or 'N/A'}"
        resource_block += f"\nResource name:  {resource_name or 'N/A'}"
    if resource_tags:
        tags_str = ", ".join(f"{k}={v}" for k, v in resource_tags.items())
        resource_block += f"\nResource tags:  {tags_str}"

    # Compliance block
    compliance_str = ""
    if compliance:
        compliance_str = f"\nCompliance:     {', '.join(compliance[:5])}"

    prompt = f"""You are a cloud security analyst writing a professional security assessment report.

Analyse the following AWS security finding and produce the required output fields.

=== FINDING CONTEXT ===
Check:          {check_title}
Check ID:       {ctx.get('check_id', '')}
Service:        {service_name}
Resource type:  {resource_type}
Severity:       {severity}
Check type:     {check_type}
Categories:     {', '.join(categories) if categories else 'None'}
Scope:          {scope_note}
Likelihood:     {likelihood} (pre-computed — do not change){resource_block}{compliance_str}

Description:    {description if description else '[Not provided — infer from check title and context]'}
Risk:           {risk if risk else '[Not provided — infer from check title and context]'}
Status detail:  {status_extended if status_extended else '[Not provided]'}
Remediation:    {remediation if remediation else '[Not provided — infer from context]'}
CLI fix:        {remediation_cli if remediation_cli else '[Not provided]'}
Terraform fix:  {remediation_tf if remediation_tf else '[Not provided]'}

=== INSTRUCTIONS ===
Write for a technical audience (security engineers, IT managers).
- finding_title: concise, professional title. Max 120 characters.
- root_cause_narrative: 1-3 sentences explaining WHY this misconfiguration exists.
- situation_narrative: 2-4 sentences describing WHAT was found and its scope.
  If instance_count > 1, include scope language (e.g. "across {instance_count} resources").
- consequence_narrative: 1-3 sentences on business/security impact if exploited.
- consequence_rating: rate the finding as Minor / Moderate / Major.
  Minor    = low impact, limited blast radius, easy to remediate.
  Moderate = material risk, requires planned remediation within weeks.
  Major    = high impact, could lead to data breach or significant outage, urgent.
- access_required: one sentence — what level of access would an attacker need to exploit this?
- needs_human_review: true only if you are genuinely uncertain about consequence_rating
  or if critical context is missing.
- Do NOT use "significant", "crucial", "critical" as filler words.
- Write clearly and concisely — no padding.

=== OUTPUT FORMAT ===
Respond with ONLY a valid JSON object. No preamble, no explanation, no markdown.

{{
  "finding_title": "...",
  "root_cause_narrative": "...",
  "situation_narrative": "...",
  "consequence_narrative": "...",
  "consequence_rating": "Minor|Moderate|Major",
  "access_required": "...",
  "needs_human_review": false
}}"""
    return prompt


def _build_correction_prompt(
    original_prompt: str,
    bad_response: str,
    errors: list[str],
) -> str:
    return f"""{original_prompt}

=== CORRECTION REQUIRED ===
Your previous response was invalid. Fix these issues:
{chr(10).join(f'- {e}' for e in errors)}

Previous response (first 400 chars): {bad_response[:400]}

Respond again with ONLY valid JSON containing ALL 7 required fields.
consequence_rating MUST be exactly: Minor, Moderate, or Major
needs_human_review MUST be a JSON boolean: true or false (not a string)"""


# ── Response validator ────────────────────────────────────────────────

def _validate_response(data: dict[str, Any]) -> list[str]:
    """Returns list of error strings. Empty = valid."""
    errors = []

    for fname in REQUIRED_LLM_FIELDS:
        if fname not in data:
            errors.append(f"missing field '{fname}'")
        elif data[fname] is None:
            errors.append(f"field '{fname}' is null")

    cr = data.get("consequence_rating", "")
    if cr not in VALID_CONSEQUENCE_RATINGS:
        errors.append(
            f"consequence_rating='{cr}' must be one of: "
            f"{sorted(VALID_CONSEQUENCE_RATINGS)}"
        )

    nhr = data.get("needs_human_review")
    if not isinstance(nhr, bool):
        errors.append(
            f"needs_human_review must be boolean true/false, got: {repr(nhr)}"
        )

    title = data.get("finding_title", "")
    if isinstance(title, str) and len(title) > 120:
        errors.append(f"finding_title is {len(title)} chars, max 120")

    return errors


# ── JSON extraction ───────────────────────────────────────────────────

def _extract_json(raw: str) -> dict[str, Any]:
    """
    Extract JSON from LLM response.
    Handles clean JSON, markdown-fenced JSON, and JSON with leading text.
    """
    text = raw.strip()

    # Strip markdown fences
    if text.startswith("```"):
        lines = [l for l in text.split("\n") if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()

    # Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Find first complete JSON object
    start = text.find("{")
    end   = text.rfind("}") + 1
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass

    raise json.JSONDecodeError(
        "No valid JSON object found in LLM response", text, 0
    )


# ── LLM clients ───────────────────────────────────────────────────────

def _call_bedrock_runtime(prompt: str, llm_cfg: dict[str, Any]) -> str:
    """
    Call AWS Bedrock using the Converse API via bedrock-runtime.

    Uses Converse (not InvokeModel) because:
    - Works with cross-region inference profiles (au.* prefix)
    - Unified interface across all Claude model versions
    - No request format changes needed when upgrading model

    Auth:
    - AWS credentials via environment variables, ~/.aws/credentials,
      or IAM role — picked up automatically by boto3.
      Required env vars: AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
      Or use: aws configure

    Zero data retention:
    - Governed by account-level policy:
      aws bedrock put-data-retention --mode none --region {region}
    - Verify: aws bedrock get-data-retention --region {region}
    - When mode=none: no data retained, model provider receives nothing.
    """
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import ClientError
    except ImportError:
        raise ImportError(
            "boto3 not installed. Run: pip install boto3"
        )

    model_id   = llm_cfg.get("deployment_name")
    region     = llm_cfg.get("aws_region", "ap-southeast-2")
    max_tokens = llm_cfg.get("max_tokens", 1000)
    timeout    = llm_cfg.get("timeout_seconds", 60)

    if not model_id:
        raise ValueError(
            "config.toml [llm] deployment_name is required. "
            "Example: anthropic.claude-opus-4-8"
        )

    client = boto3.client(
        "bedrock-runtime",
        region_name=region,
        config=Config(
            read_timeout=timeout,
            connect_timeout=10,
        ),
    )

    try:
        response = client.converse(
            modelId=model_id,
            system=[{"text": SYSTEM_PROMPT}],
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": max_tokens},
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg  = e.response["Error"]["Message"]
        raise RuntimeError(
            f"Bedrock runtime error [{code}]: {msg}. "
            f"Model: {model_id}, Region: {region}"
        ) from e

    return response["output"]["message"]["content"][0]["text"]


def _call_ollama(prompt: str, llm_cfg: dict[str, Any]) -> str:
    """Call a local Ollama endpoint (offline fallback)."""
    import urllib.request

    endpoint = llm_cfg.get("endpoint", "http://localhost:11434")
    model    = llm_cfg.get("deployment_name", "mistral")
    timeout  = llm_cfg.get("timeout_seconds", 30)

    payload = json.dumps({
        "model":  model,
        "stream": False,
        "format": "json",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{endpoint.rstrip('/')}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    return result["message"]["content"]


def _call_llm(prompt: str, llm_cfg: dict[str, Any]) -> str:
    """Route to the correct LLM provider."""
    provider = llm_cfg.get("provider", "bedrock_runtime").lower()
    if provider in ("bedrock_runtime", "bedrock"):
        return _call_bedrock_runtime(prompt, llm_cfg)
    elif provider == "local_ollama":
        return _call_ollama(prompt, llm_cfg)
    else:
        raise ValueError(
            f"Unknown LLM provider '{provider}'. "
            "Valid values: bedrock_runtime | local_ollama"
        )


# ── Placeholder writer ────────────────────────────────────────────────

def _write_placeholders(finding: CanonicalFinding, reason: str) -> None:
    """
    Write structured placeholder text when LLM enrichment fails.
    The quality gate blocks final mode until placeholders are replaced.
    """
    finding.finding_title         = (
        f"[REQUIRES_HUMAN_INPUT] {finding.raw_check_title or 'Unknown check'}"
    )
    finding.root_cause_narrative  = "[REQUIRES_HUMAN_INPUT: root_cause_narrative]"
    finding.situation_narrative   = "[REQUIRES_HUMAN_INPUT: situation_narrative]"
    finding.consequence_narrative = "[REQUIRES_HUMAN_INPUT: consequence_narrative]"
    finding.consequence_rating    = "Moderate"  # safe default for risk matrix
    finding.access_required       = "[REQUIRES_HUMAN_INPUT: access_required]"
    finding.llm_enrichment_failed = True

    finding.add_audit(
        stage="stage3_llm",
        field="llm_enrichment_failed",
        old_value=False,
        new_value=True,
        reason=reason,
        actor="pipeline",
    )
    finding.flag_for_review(
        reason=f"LLM enrichment failed — placeholders written. {reason}",
        stage="stage3_llm",
    )


# ── Risk matrix ───────────────────────────────────────────────────────

def _compute_risk_rating(
    likelihood: str,
    consequence: str,
    risk_matrix: dict[str, str],
) -> str:
    """Look up Risk Rating: 'Likelihood_Consequence' → 'High|Medium|Low'."""
    return risk_matrix.get(f"{likelihood}_{consequence}", "Medium")


# ── Single group enrichment ───────────────────────────────────────────

def _enrich_group(
    group: "GroupedOutputGroup | OutputGroup",
    llm_cfg: dict[str, Any],
    risk_matrix: dict[str, str],
    warnings: list["EnrichWarning"],
    group_num: int,
    total_groups: int,
) -> None:
    """Enrich one OutputGroup. Mutates group.representative in-place."""
    rep = group.representative
    # GroupedOutputGroup uses check_ids (list); OutputGroup uses check_id (str)
    from stage2_5_grouping import GroupedOutputGroup as _GOG
    if isinstance(group, _GOG):
        check_id = group.group_name
    else:
        check_id = group.check_id
    ctx = group.to_llm_context()

    print(
        f"  [{group_num}/{total_groups}] {check_id} "
        f"(instances={group.instance_count}, likelihood={group.likelihood_rating})",
        flush=True,
    )

    prompt       = _build_prompt(ctx)
    raw_response = None
    parsed       = None
    errors       = []
    attempt      = 0

    # ── Attempt 1 ──
    try:
        attempt = 1
        raw_response = _call_llm(prompt, llm_cfg)
        parsed       = _extract_json(raw_response)
        errors       = _validate_response(parsed)
        if not errors:
            print(f"         ✓ attempt 1 succeeded", flush=True)
    except Exception as e:
        errors = [f"{type(e).__name__}: {e}"]
        print(f"         ✗ attempt 1 failed: {errors[0][:80]}", flush=True)

    # ── Attempt 2 (retry once) ──
    if errors:
        print(f"         → retrying...", flush=True)
        try:
            attempt      = 2
            raw_response = _call_llm(
                _build_correction_prompt(prompt, str(raw_response or ""), errors),
                llm_cfg,
            )
            parsed = _extract_json(raw_response)
            errors = _validate_response(parsed)
            if not errors:
                print(f"         ✓ attempt 2 succeeded", flush=True)
            else:
                print(f"         ✗ attempt 2 failed: {errors}", flush=True)
        except Exception as e:
            errors = [f"{type(e).__name__}: {e}"]
            print(f"         ✗ attempt 2 failed: {errors[0][:80]}", flush=True)

    # ── Write placeholders if both attempts failed ──
    if errors or parsed is None:
        reason = (
            f"LLM enrichment failed after {attempt} attempt(s): "
            f"{'; '.join(errors)}"
        )
        _write_placeholders(rep, reason)
        warnings.append(EnrichWarning(
            code="LLM_ENRICHMENT_FAILED",
            message=f"[{check_id}] {reason}",
            check_id=check_id,
            finding_id=rep.finding_instance_id,
        ))
        print(f"         ⚠ placeholders written — needs human review", flush=True)
        return

    # ── Write enrichment results ──
    rep.finding_title         = str(parsed["finding_title"])[:120]
    rep.root_cause_narrative  = str(parsed["root_cause_narrative"])
    rep.situation_narrative   = str(parsed["situation_narrative"])
    rep.consequence_narrative = str(parsed["consequence_narrative"])
    rep.consequence_rating    = str(parsed["consequence_rating"])
    rep.access_required       = str(parsed["access_required"])
    rep.ai_enriched           = True

    if parsed.get("needs_human_review") is True:
        rep.flag_for_review(
            reason="LLM flagged uncertainty on one or more fields",
            stage="stage3_llm",
        )
        print(f"         ⚠ LLM flagged needs_human_review=true", flush=True)

    # Audit enrichment
    rep.add_audit(
        stage="stage3_llm",
        field="ai_enriched",
        old_value=False,
        new_value=True,
        reason=(
            f"LLM enrichment completed (attempt {attempt}). "
            f"Provider: {llm_cfg.get('provider')}. "
            f"Model: {llm_cfg.get('deployment_name')}."
        ),
        actor="llm",
    )
    rep.add_audit(
        stage="stage3_llm",
        field="consequence_rating",
        old_value=None,
        new_value=rep.consequence_rating,
        reason=f"LLM assessed: {rep.consequence_rating}",
        actor="llm",
    )

    # ── Compute risk_rating from matrix ──
    likelihood  = group.likelihood_rating or "Medium"
    consequence = rep.consequence_rating
    risk_rating = _compute_risk_rating(likelihood, consequence, risk_matrix)
    rep.risk_rating = risk_rating

    rep.add_audit(
        stage="stage3_llm",
        field="risk_rating",
        old_value=None,
        new_value=risk_rating,
        reason=f"risk_matrix['{likelihood}_{consequence}'] = '{risk_rating}'",
        actor="pipeline",
    )

    print(
        f"         consequence={consequence} → risk_rating={risk_rating}",
        flush=True,
    )


# ── Result types ──────────────────────────────────────────────────────

@dataclass
class EnrichWarning:
    code:       str
    message:    str
    check_id:   Optional[str] = None
    finding_id: Optional[str] = None


@dataclass
class EnrichResult:
    """Output of Stage 3."""
    run_id:         str
    output_groups:  list["GroupedOutputGroup | OutputGroup"]
    all_findings:   list[CanonicalFinding]
    warnings:       list[EnrichWarning]
    config:         dict[str, Any]
    enriched_count: int = 0
    failed_count:   int = 0

    @property
    def group_count(self) -> int:
        return len(self.output_groups)

    @property
    def risk_rating_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {"High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        for g in self.output_groups:
            r = g.representative.risk_rating or "Unknown"
            counts[r] = counts.get(r, 0) + 1
        return counts


# ── Main entry point ──────────────────────────────────────────────────

def _run_enrichment(
    groups: list,
    all_findings: list,
    run_id: str,
    config: dict[str, Any],
) -> EnrichResult:
    """Shared enrichment loop — works on OutputGroup or GroupedOutputGroup."""
    llm_cfg     = config.get("llm", {})
    risk_matrix = config.get("risk_matrix", {})
    warnings: list[EnrichWarning] = []

    if not llm_cfg:
        raise ValueError(
            "config.toml is missing [llm] section. "
            "Cannot run Stage 3 without LLM configuration."
        )

    total    = len(groups)
    enriched = 0
    failed   = 0

    print(
        f"\n[ Stage 3 ] LLM enrichment — {total} groups "
        f"(provider={llm_cfg.get('provider')}, "
        f"model={llm_cfg.get('deployment_name')})",
        flush=True,
    )

    for i, group in enumerate(groups, 1):
        _enrich_group(
            group=group,
            llm_cfg=llm_cfg,
            risk_matrix=risk_matrix,
            warnings=warnings,
            group_num=i,
            total_groups=total,
        )
        if group.representative.llm_enrichment_failed:
            failed += 1
        else:
            enriched += 1

        # Write enrichment results to GroupedOutputGroup fields too
        from stage2_5_grouping import GroupedOutputGroup as GOG
        if isinstance(group, GOG):
            rep = group.representative
            group.risk_rating          = rep.risk_rating
            group.consequence_rating   = rep.consequence_rating
            group.finding_title        = rep.finding_title
            group.root_cause_narrative = rep.root_cause_narrative
            group.situation_narrative  = rep.situation_narrative
            group.consequence_narrative= rep.consequence_narrative
            group.access_required      = rep.access_required

    print(
        f"\n  ✓ Enrichment complete: "
        f"{enriched} succeeded, {failed} failed",
        flush=True,
    )

    return EnrichResult(
        run_id=run_id,
        output_groups=groups,
        all_findings=all_findings,
        warnings=warnings,
        config=config,
        enriched_count=enriched,
        failed_count=failed,
    )


def enrich(
    process_result: ProcessResult,
    config: dict[str, Any],
) -> EnrichResult:
    """
    Stage 3 entry point (direct from Stage 2, no semantic grouping).
    Use enrich_grouped() if Stage 2.5 has run.
    """
    return _run_enrichment(
        groups=process_result.output_groups,
        all_findings=process_result.all_findings,
        run_id=process_result.run_id,
        config=config,
    )


def enrich_grouped(
    grouping_result: "Any",  # GroupingResult — local import avoids circular dependency
    config: dict[str, Any],
) -> EnrichResult:
    """
    Stage 3 entry point when Stage 2.5 (semantic grouping) has run.
    Enriches GroupedOutputGroups with full merged context.
    """
    return _run_enrichment(
        groups=grouping_result.grouped_groups,
        all_findings=grouping_result.all_findings,
        run_id=grouping_result.run_id,
        config=config,
    )