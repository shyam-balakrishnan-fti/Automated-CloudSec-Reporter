"""
sg_enrich.py — Stage 3: LLM Enrichment

Responsibilities:
  - Build structured prompts for each group with full M365 finding context
  - Call AWS Bedrock (Converse API) with LLM response caching
  - Validate returned JSON — all 7 required fields must be present and valid
  - On failure: retry once with correction prompt
  - On second failure: write placeholder text, set llm_enrichment_failed=True
  - Write enrichment results to representative ScubaFinding and GroupedOutputGroup
  - Compute risk_rating from likelihood × consequence via the risk matrix
  - Record all enrichment events in the audit trail

Contract:
  enrich_grouped(grouping_result, config) -> EnrichResult
  enrich(process_result, config)          -> EnrichResult  (no semantic grouping)

LLM call patterns are copied verbatim from stage3_llm.py to maintain independence.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from sg_models import ScubaFinding

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
    "recommendations",
    "needs_human_review",
}

SYSTEM_PROMPT = (
    "You are a Microsoft 365 and cloud security analyst writing a professional "
    "security assessment report. You always respond with valid JSON only. "
    "No preamble, no markdown fences, no explanation outside the JSON object."
)


# ── LLM call + cache (copied from stage3_llm.py) ─────────────────────

def _cache_path(prompt: str, model_id: str) -> Optional[Path]:
    cache_dir = os.environ.get("PIPELINE_LLM_CACHE_DIR")
    if not cache_dir:
        return None
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(f"{model_id}::{prompt}".encode()).hexdigest()
    return Path(cache_dir) / f"{key}.txt"


def _call_bedrock_runtime(prompt: str, llm_cfg: dict[str, Any]) -> str:
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import ClientError
    except ImportError:
        raise ImportError("boto3 not installed. Run: pip install boto3")

    model_id   = llm_cfg.get("deployment_name")
    region     = llm_cfg.get("aws_region", "ap-southeast-2")
    max_tokens = llm_cfg.get("max_tokens", 1500)
    timeout    = llm_cfg.get("timeout_seconds", 60)

    if not model_id:
        raise ValueError(
            "scubagear_config.toml [llm] deployment_name is required. "
            "Example: anthropic.claude-opus-4-8"
        )

    client = boto3.client(
        "bedrock-runtime",
        region_name=region,
        config=Config(read_timeout=timeout, connect_timeout=10),
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

    stop_reason    = response.get("stopReason", "")
    content_blocks = response.get("output", {}).get("message", {}).get("content", [])

    if not content_blocks:
        raise RuntimeError(
            f"Bedrock returned no content. stopReason='{stop_reason}'. "
            f"Model: {model_id}, max_tokens={max_tokens}."
        )

    text = content_blocks[0].get("text", "")

    if stop_reason == "max_tokens":
        raise RuntimeError(
            f"Bedrock response truncated (stopReason='max_tokens', "
            f"max_tokens={max_tokens}). Increase max_tokens or reduce prompt."
        )

    if not text or not text.strip():
        raise RuntimeError(
            f"Bedrock returned empty text. stopReason='{stop_reason}'."
        )

    return text


def _call_llm(prompt: str, llm_cfg: dict[str, Any]) -> str:
    """Route to provider, with LLM response caching."""
    provider = llm_cfg.get("provider", "bedrock_runtime").lower()
    model_id = llm_cfg.get("deployment_name", "")

    cache = _cache_path(prompt, model_id)
    if cache and cache.exists():
        logger.debug("LLM cache hit: %s", cache.name)
        return cache.read_text(encoding="utf-8")

    if provider in ("bedrock_runtime", "bedrock"):
        result = _call_bedrock_runtime(prompt, llm_cfg)
    else:
        raise ValueError(
            f"Unknown LLM provider '{provider}'. Valid values: bedrock_runtime"
        )

    if cache:
        cache.write_text(result, encoding="utf-8")

    return result


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

def _extract_json(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        lines = [l for l in text.split("\n") if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end   = text.rfind("}") + 1
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass
    raise json.JSONDecodeError("No valid JSON object found in LLM response", text, 0)


# ── Response validator ────────────────────────────────────────────────

def _validate_response(data: dict[str, Any]) -> list[str]:
    errors = []
    for fname in REQUIRED_LLM_FIELDS:
        if fname not in data:
            errors.append(f"missing field '{fname}'")
        elif data[fname] is None:
            errors.append(f"field '{fname}' is null")
    cr = data.get("consequence_rating", "")
    if cr not in VALID_CONSEQUENCE_RATINGS:
        errors.append(
            f"consequence_rating='{cr}' must be one of: {sorted(VALID_CONSEQUENCE_RATINGS)}"
        )
    nhr = data.get("needs_human_review")
    if not isinstance(nhr, bool):
        errors.append(f"needs_human_review must be boolean true/false, got: {repr(nhr)}")
    title = data.get("finding_title", "")
    if isinstance(title, str) and len(title) > 120:
        errors.append(f"finding_title is {len(title)} chars, max 120")
    return errors


# ── Prompt builder ────────────────────────────────────────────────────

def _build_prompt(ctx: dict[str, Any]) -> str:
    """
    Build the enrichment prompt from a group's context dict.
    M365-specific framing: CISA SCUBA baseline controls, tenant scope,
    no per-resource ARNs — the Details field is the primary evidence.
    """
    check_id        = ctx.get("check_id", "")
    check_title     = ctx.get("check_title") or ctx.get("description") or "Unknown control"
    service_name    = ctx.get("service_name") or ""
    severity        = ctx.get("severity") or "high"
    criticality_raw = ctx.get("criticality_raw") or "Shall"
    status_extended = ctx.get("status_extended") or ""
    instance_count  = ctx.get("instance_count", 1)
    tenant_id       = ctx.get("account_name") or ""
    likelihood      = ctx.get("likelihood_rating") or "High"
    omitted_result  = ctx.get("omitted_result")
    incorrect_result= ctx.get("incorrect_result")
    original_result = ctx.get("original_result")

    # Scope note
    if instance_count > 1:
        scope_note = (
            f"This control affects {instance_count} resource(s) within the tenant."
        )
    else:
        scope_note = "This control is tenant-scoped (Microsoft 365 global configuration)."

    # Override/omission context
    override_block = ""
    if omitted_result and omitted_result not in ("N/A", ""):
        override_block += f"\nOmitted evaluation: {omitted_result}"
    if incorrect_result and incorrect_result not in ("N/A", ""):
        override_block += f"\nResult override applied: {incorrect_result}"
    if original_result and original_result not in ("N/A", ""):
        override_block += f"\nOriginal automated result: {original_result}"

    # Criticality context for narrative framing
    crit_note = ""
    if "3rd Party" in criticality_raw:
        crit_note = (
            "\nNote: This is a Shall/3rd Party control — remediation may require "
            "coordinating with a third-party vendor or managed service provider."
        )
    elif "Not Implemented" in criticality_raw:
        crit_note = (
            "\nNote: This control is marked Shall/Not Implemented — the organisation "
            "has acknowledged non-implementation. Narratives should reflect this context."
        )

    prompt = f"""You are a Microsoft 365 security analyst writing a professional security assessment report.

Analyse the following M365 CISA SCuBA baseline control failure and produce the required output fields.

=== CONTROL CONTEXT ===
Control ID:     {check_id}
Service:        {service_name}
Policy:         {check_title}
Criticality:    {criticality_raw}
Severity:       {severity}
Scope:          {scope_note}
Likelihood:     {likelihood} (pre-computed — do not change){crit_note}

Finding detail: {status_extended if status_extended else '[Not provided — infer from control policy text]'}
{override_block}

=== INSTRUCTIONS ===
Write for a technical audience (security engineers, IT managers, CISO).
This is a CISA SCuBA baseline compliance gap. Frame narratives accordingly.

- finding_title: concise, professional title for this M365 compliance gap. Max 120 characters.
- root_cause_narrative: 1-3 sentences explaining WHY this misconfiguration or gap exists.
  Focus on the likely organisational or configuration cause.
- situation_narrative: 2-4 sentences describing WHAT was found and its current state.
  Reference the specific policy requirement and what the scan found. Include the Finding detail
  above — it contains the evidence (e.g. specific users, policies, counts).
  Do NOT describe what could happen if exploited.
- consequence_narrative: 1-3 sentences on business/security IMPACT if this gap is exploited.
  Frame in terms of realistic M365/Azure AD attack scenarios (credential theft, lateral movement,
  data exfiltration from SharePoint/Exchange, persistent access via app registrations, etc.).
  Start from 'An attacker could...' or 'This could allow...'.
- consequence_rating: rate as Minor / Moderate / Major.
  Minor    = low blast radius, limited data exposure, easy to remediate.
  Moderate = material risk to M365 services or data, requires planned remediation.
  Major    = high impact, could enable tenant-wide compromise, data exfiltration, or persistent access.
- access_required: one sentence — what access level would an attacker need to exploit this gap?
  Be specific (e.g. "Any authenticated user", "Compromised user account", "External attacker",
  "Privileged admin account required").
- recommendations: 2-4 sentences of actionable remediation guidance. Reference the specific
  M365 admin portal, policy name, or PowerShell cmdlet where relevant. Write for the engineer
  who will fix this — be specific about WHAT to configure, not just WHERE to go.
- needs_human_review: true only if you are genuinely uncertain about consequence_rating or
  if critical context is missing from the finding detail.
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
  "recommendations": "...",
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

Respond again with ONLY valid JSON containing ALL 8 required fields.
consequence_rating MUST be exactly: Minor, Moderate, or Major
needs_human_review MUST be a JSON boolean: true or false (not a string)"""


# ── Risk matrix ───────────────────────────────────────────────────────

def _compute_risk_rating(
    likelihood: str,
    consequence: str,
    risk_matrix: dict[str, str],
) -> str:
    return risk_matrix.get(f"{likelihood}_{consequence}", "Medium")


# ── Placeholder writer ────────────────────────────────────────────────

def _write_placeholders(finding: ScubaFinding, reason: str) -> None:
    finding.finding_title         = f"[REQUIRES_HUMAN_INPUT] {finding.check_title or 'Unknown control'}"
    finding.root_cause_narrative  = "[REQUIRES_HUMAN_INPUT: root_cause_narrative]"
    finding.situation_narrative   = "[REQUIRES_HUMAN_INPUT: situation_narrative]"
    finding.consequence_narrative = "[REQUIRES_HUMAN_INPUT: consequence_narrative]"
    finding.consequence_rating    = "Moderate"
    finding.access_required       = "[REQUIRES_HUMAN_INPUT: access_required]"
    finding.recommendations       = "[REQUIRES_HUMAN_INPUT: recommendations]"
    finding.llm_enrichment_failed = True
    finding.add_audit(
        stage="sg_enrich", field="llm_enrichment_failed",
        old_value=False, new_value=True, reason=reason, actor="pipeline",
    )
    finding.flag_for_review(
        reason=f"LLM enrichment failed — placeholders written. {reason}",
        stage="sg_enrich",
    )


# ── Single group enrichment ───────────────────────────────────────────

def _enrich_group(
    group: Any,  # OutputGroup | GroupedOutputGroup
    llm_cfg: dict[str, Any],
    risk_matrix: dict[str, str],
    warnings: list["EnrichWarning"],
    group_num: int,
    total_groups: int,
) -> None:
    """Enrich one group. Mutates group.representative in-place."""
    rep      = group.representative
    check_id = getattr(group, "group_name", None) or getattr(group, "check_id", "unknown")
    ctx      = group.to_llm_context()

    print(
        f"  [{group_num}/{total_groups}] {check_id} "
        f"(instances={group.instance_count}, likelihood={group.likelihood_rating})",
        flush=True,
    )

    prompt       = _build_prompt(ctx)
    scaled_cfg   = _scaled_llm_cfg(llm_cfg, 1)
    raw_response = None
    parsed       = None
    errors: list[str] = []
    attempt      = 0

    # Attempt 1
    try:
        attempt      = 1
        raw_response = _call_llm(prompt, scaled_cfg)
        parsed       = _extract_json(raw_response)
        errors       = _validate_response(parsed)
        if not errors:
            print(f"         ✓ attempt 1 succeeded", flush=True)
    except Exception as e:
        errors = [f"{type(e).__name__}: {e}"]
        print(f"         ✗ attempt 1 failed: {errors[0][:80]}", flush=True)

    # Attempt 2 (retry once with correction prompt)
    if errors:
        print(f"         → retrying...", flush=True)
        try:
            attempt      = 2
            raw_response = _call_llm(
                _build_correction_prompt(prompt, str(raw_response or ""), errors),
                scaled_cfg,
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

    # Both attempts failed → placeholders
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

    # Write enrichment results to representative ScubaFinding
    rep.finding_title         = str(parsed["finding_title"])[:120]
    rep.root_cause_narrative  = str(parsed["root_cause_narrative"])
    rep.situation_narrative   = str(parsed["situation_narrative"])
    rep.consequence_narrative = str(parsed["consequence_narrative"])
    rep.consequence_rating    = str(parsed["consequence_rating"])
    rep.access_required       = str(parsed["access_required"])
    rep.recommendations       = str(parsed["recommendations"])
    rep.ai_enriched           = True

    if parsed.get("needs_human_review") is True:
        rep.flag_for_review(
            reason="LLM flagged uncertainty on one or more fields",
            stage="sg_enrich",
        )
        print(f"         ⚠ LLM flagged needs_human_review=true", flush=True)

    rep.add_audit(
        stage="sg_enrich", field="ai_enriched",
        old_value=False, new_value=True,
        reason=(
            f"LLM enrichment completed (attempt {attempt}). "
            f"Provider: {llm_cfg.get('provider')}. "
            f"Model: {llm_cfg.get('deployment_name')}."
        ),
        actor="llm",
    )
    rep.add_audit(
        stage="sg_enrich", field="consequence_rating",
        old_value=None, new_value=rep.consequence_rating,
        reason=f"LLM assessed: {rep.consequence_rating}", actor="llm",
    )

    # Compute risk rating — respect analyst override from review UI if present
    analyst_override = getattr(group, "risk_rating", None) or getattr(rep, "risk_rating", None)
    if analyst_override and analyst_override in ("High", "Medium", "Low"):
        risk_rating = analyst_override
        rep.risk_rating = risk_rating
        rep.add_audit(
            stage="sg_enrich", field="risk_rating",
            old_value=None, new_value=risk_rating,
            reason="Analyst override from review UI (preserved, matrix not applied)",
            actor="human",
        )
        print(f"         consequence={rep.consequence_rating} → risk_rating={risk_rating} (analyst override)", flush=True)
    else:
        likelihood  = group.likelihood_rating or "High"
        consequence = rep.consequence_rating
        risk_rating = _compute_risk_rating(likelihood, consequence, risk_matrix)
        rep.risk_rating = risk_rating
        rep.add_audit(
            stage="sg_enrich", field="risk_rating",
            old_value=None, new_value=risk_rating,
            reason=f"risk_matrix['{likelihood}_{consequence}'] = '{risk_rating}'",
            actor="pipeline",
        )
        print(f"         consequence={consequence} → risk_rating={risk_rating}", flush=True)

    # Mirror results to GroupedOutputGroup fields
    from sg_grouping import GroupedOutputGroup as GOG
    if isinstance(group, GOG):
        group.risk_rating           = rep.risk_rating
        group.consequence_rating    = rep.consequence_rating
        group.finding_title         = rep.finding_title
        group.root_cause_narrative  = rep.root_cause_narrative
        group.situation_narrative   = rep.situation_narrative
        group.consequence_narrative = rep.consequence_narrative
        group.access_required       = rep.access_required
        group.recommendations       = rep.recommendations


# ── Result types ──────────────────────────────────────────────────────

@dataclass
class EnrichWarning:
    code:       str
    message:    str
    check_id:   Optional[str] = None
    finding_id: Optional[str] = None


@dataclass
class EnrichResult:
    run_id:         str
    output_groups:  list[Any]
    all_findings:   list[ScubaFinding]
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


# ── Main entry points ─────────────────────────────────────────────────

def _run_enrichment(
    groups: list[Any],
    all_findings: list[ScubaFinding],
    run_id: str,
    config: dict[str, Any],
) -> EnrichResult:
    llm_cfg     = config.get("llm", {})
    risk_matrix = config.get("risk_matrix", {})
    warnings: list[EnrichWarning] = []

    if not llm_cfg:
        raise ValueError(
            "scubagear_config.toml is missing [llm] section. "
            "Cannot run enrichment without LLM configuration."
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
            group=group, llm_cfg=llm_cfg, risk_matrix=risk_matrix,
            warnings=warnings, group_num=i, total_groups=total,
        )
        if group.representative.llm_enrichment_failed:
            failed += 1
        else:
            enriched += 1

    print(
        f"\n  ✓ Enrichment complete: {enriched} succeeded, {failed} failed",
        flush=True,
    )

    return EnrichResult(
        run_id=run_id, output_groups=groups, all_findings=all_findings,
        warnings=warnings, config=config,
        enriched_count=enriched, failed_count=failed,
    )


def enrich_grouped(grouping_result: Any, config: dict[str, Any]) -> EnrichResult:
    """Stage 3 entry point when sg_grouping has run (recommended path)."""
    return _run_enrichment(
        groups=grouping_result.grouped_groups,
        all_findings=grouping_result.all_findings,
        run_id=grouping_result.run_id,
        config=config,
    )


def enrich(process_result: Any, config: dict[str, Any]) -> EnrichResult:
    """Stage 3 entry point without semantic grouping (direct from Stage 2)."""
    return _run_enrichment(
        groups=process_result.output_groups,
        all_findings=process_result.all_findings,
        run_id=process_result.run_id,
        config=config,
    )