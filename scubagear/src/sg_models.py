"""
sg_models.py — ScubaFinding Pydantic model

The backbone of the ScubaGear pipeline. Every stage reads from or writes to
this model. Intentionally independent of the Prowler CanonicalFinding — no
imports from the Prowler codebase anywhere in this file.

Field groups:
    RUN IDENTITY     — immutable after ingestion
    FINDING IDENTITY — immutable after parsing
    RAW FIELDS       — all ScubaGear CSV columns, presence-checked at ingestion
    NORMALISED       — cleaned/derived values written by sg_ingest / sg_process
    OUTPUT FIELDS    — LLM-generated narratives written by sg_enrich
    PROCESSING STATE — mutable workflow flags
    AUDIT            — append-only event log

Data sensitivity:
    The Details field and Requirement field may contain tenant-specific
    identifiers (admin names, UPNs, policy object IDs). These are sent to
    AWS Bedrock only. Zero data retention is enforced at account level.
    These fields are excluded from any serialisation that leaves Bedrock.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from enum import Enum
from html.parser import HTMLParser
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── HTML stripper ─────────────────────────────────────────────────────

class _HTMLStripper(HTMLParser):
    """Minimal HTML stripper used to clean Requirement and Details fields."""
    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self._parts.append(data)

    def get_text(self) -> str:
        return "".join(self._parts).strip()


def strip_html(text: str) -> str:
    """
    Remove all HTML tags from text. Used for:
    - Requirement field: strips <div class='policy-indicators'>...</div>
    - Details field (OriginalDetails): strips <a href='#caps'>...</a> refs
    Returns empty string if input is None or empty.
    """
    if not text:
        return ""
    # First: remove the entire policy-indicators div block (including its content,
    # since those are just compliance badge links not useful in narratives)
    text = re.sub(
        r"<div[^>]*class=['\"]policy-indicators['\"][^>]*>.*?</div>",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    # Then strip any remaining HTML tags
    stripper = _HTMLStripper()
    stripper.feed(text)
    return stripper.get_text()


def extract_instance_count(details: str) -> int:
    """
    Best-effort extraction of a numeric count from Details strings.
    Handles patterns like:
      "6 role(s) that contain users..."
      "3 conditional access policy(s) found..."
      "2 user(s) with..."
    Returns 1 if no count is found (safe default).
    """
    if not details:
        return 1
    match = re.search(r"\b(\d+)\s+\w+\(s\)", details)
    if match:
        count = int(match.group(1))
        return max(count, 1)
    return 1


# ── Enumerations ──────────────────────────────────────────────────────

class ScannerStatus(str, Enum):
    PASS    = "PASS"
    FAIL    = "FAIL"
    UNKNOWN = "UNKNOWN"


class ReportInclusion(str, Enum):
    INCLUDED             = "INCLUDED"
    EXCLUDED             = "EXCLUDED"
    INCLUDED_IN_APPENDIX = "INCLUDED_IN_APPENDIX"


class WorkflowStatus(str, Enum):
    OPEN                 = "OPEN"
    FALSE_POSITIVE       = "FALSE_POSITIVE"
    ACCEPTED_RISK        = "ACCEPTED_RISK"
    COMPENSATING_CONTROL = "COMPENSATING_CONTROL"
    NOT_APPLICABLE       = "NOT_APPLICABLE"
    RESOLVED             = "RESOLVED"
    NEEDS_REVIEW         = "NEEDS_REVIEW"


# ── Audit trail ───────────────────────────────────────────────────────

class AuditEvent(BaseModel):
    """One field-level transformation event. Immutable once created."""
    timestamp:  datetime = Field(default_factory=datetime.utcnow)
    stage:      str
    field:      str
    old_value:  Any
    new_value:  Any
    reason:     str
    actor:      str = "pipeline"   # "pipeline" | "llm" | "human"


# ── Service metadata helper ───────────────────────────────────────────

# Maps Control ID prefix → (output_section, ref_prefix)
# Kept here as a fallback; the config service_map overrides at runtime.
_DEFAULT_SERVICE_MAP: dict[str, dict[str, str]] = {
    "MS.AAD":           {"section": "Microsoft Entra ID (previously Azure Active Directory)", "ref_prefix": "ENT"},
    "MS.DEFENDER":      {"section": "Microsoft 365 Defender",         "ref_prefix": "DEF"},
    "MS.EXCHANGE":      {"section": "Microsoft Exchange Online",       "ref_prefix": "EXC"},
    "MS.SHAREPOINT":    {"section": "Microsoft SharePoint Online",     "ref_prefix": "SPT"},
    "MS.TEAMS":         {"section": "Microsoft Teams",                 "ref_prefix": "TEA"},
    "MS.POWERPLATFORM": {"section": "Microsoft Power Platform",        "ref_prefix": "PPL"},
}

# Section ordering for Excel output.
# Matches the Azure sheet in Output_Template.xlsx for existing headings;
# new headings (SharePoint Online, Teams) are inserted by the renderer.
SECTION_ORDER: list[str] = [
    "Microsoft Entra ID (previously Azure Active Directory)",
    "Microsoft 365 Defender",
    "Microsoft Exchange Online",
    "Microsoft SharePoint Online",
    "Microsoft Teams",
    "Microsoft Power Platform",
    "Azure Resources",
]


def resolve_service(control_id: str, service_map: Optional[dict] = None) -> tuple[str, str, str]:
    """
    Given a Control ID like "MS.AAD.3.1v1", return (service_prefix, section, ref_prefix).
    Falls back to _DEFAULT_SERVICE_MAP if service_map is not supplied or missing a key.
    Returns ("UNKNOWN", "Azure Resources", "M365") for unrecognised prefixes.
    """
    smap = service_map or {}
    # Try progressively shorter prefixes: "MS.POWERPLATFORM" before "MS.POWER"
    parts = control_id.upper().split(".")
    for length in (3, 2):
        prefix = ".".join(parts[:length])
        entry = smap.get(prefix) or _DEFAULT_SERVICE_MAP.get(prefix)
        if entry:
            return prefix, entry["section"], entry["ref_prefix"]
    return "UNKNOWN", "Azure Resources", "M365"


# ── Main model ────────────────────────────────────────────────────────

class ScubaFinding(BaseModel):
    """
    The single internal contract for the ScubaGear pipeline.

    Lean, M365-native schema. Does not inherit from or import CanonicalFinding.
    The to_ai_lane() and to_audit_dict() methods mirror CanonicalFinding's
    interface so downstream stages (grouping, enrichment) can use identical
    call patterns to the Prowler pipeline.
    """

    model_config = {"validate_assignment": True}

    # ── Run identity ──────────────────────────────────────────────────
    run_id:           str      = Field(default_factory=lambda: str(uuid.uuid4()))
    source_file:      str      = ""
    scanner:          str      = "scubagear"
    schema_version:   str      = "1.0.0"
    ingested_at:      datetime = Field(default_factory=datetime.utcnow)

    # ── Finding identity ──────────────────────────────────────────────
    finding_instance_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    # stable_key: "azure:{tenant_id}:{control_id}" — stable across repeated scans
    stable_key:          str = ""
    # dedup_key: within-run collision detection
    dedup_key:           str = ""

    # ── Tenant identity ───────────────────────────────────────────────
    tenant_id:   str = ""   # from CLI --tenant-id or config fallback
    provider:    str = "azure"
    region:      str = "global"  # M365 is always global

    # ── Raw fields ─────────────────────────────────────────────────────
    # All 16 possible columns from ActionPlan.csv / ScubaResults.csv.
    # Optional columns (absent in older team exports) default to None.
    # Comments ("System.Object[]") is always treated as None.
    raw_control_id:              Optional[str] = None   # "MS.AAD.3.1v1"
    raw_requirement:             Optional[str] = None   # full text incl. HTML
    raw_result:                  Optional[str] = None   # "Fail" | "Pass"
    raw_criticality:             Optional[str] = None   # "Shall" | "Shall/3rd Party" etc.
    raw_details:                 Optional[str] = None   # sensitive — admin names, UPNs
    raw_non_compliance_reason:   Optional[str] = None
    raw_remediation_date:        Optional[str] = None
    raw_justification:           Optional[str] = None
    # Optional columns — present in GitHub sample, absent in older team exports
    raw_omitted_result:          Optional[str] = None
    raw_omitted_details:         Optional[str] = None
    raw_incorrect_result:        Optional[str] = None
    raw_incorrect_details:       Optional[str] = None
    raw_original_result:         Optional[str] = None
    raw_original_details:        Optional[str] = None
    raw_resolution_date:         Optional[str] = None
    # Comments always treated as empty (PowerShell "System.Object[]" artefact)
    raw_comments:                Optional[str] = None

    # Unknown future columns
    extra_fields: dict[str, Any] = Field(default_factory=dict)

    # ── Normalised fields ─────────────────────────────────────────────
    control_id:         str           = ""   # normalised copy of raw_control_id
    check_title:        str           = ""   # raw_requirement stripped of HTML
    scanner_status:     ScannerStatus = ScannerStatus.UNKNOWN
    criticality_raw:    str           = ""   # preserved original Criticality value
    severity:           str           = ""   # "high" | "medium" | "low"
    service_prefix:     str           = ""   # "MS.AAD" | "MS.DEFENDER" etc.
    service_name:       str           = ""   # "Entra ID" | "Defender" etc.
    output_section:     str           = ""   # Excel section heading
    ref_prefix:         str           = ""   # "ENT" | "DEF" etc.
    instance_count:     int           = 1    # best-effort from Details regex
    ref_number:         Optional[int] = None # assigned by sg_process (per-section counter)

    # ── Output fields (written by sg_enrich) ──────────────────────────
    likelihood_rating:      Optional[str] = None  # High | Medium | Low
    consequence_rating:     Optional[str] = None  # Minor | Moderate | Major
    risk_rating:            Optional[str] = None  # High | Medium | Low
    finding_title:          Optional[str] = None
    root_cause_narrative:   Optional[str] = None
    situation_narrative:    Optional[str] = None
    consequence_narrative:  Optional[str] = None
    access_required:        Optional[str] = None
    recommendations:        Optional[str] = None

    # ── Processing state ──────────────────────────────────────────────
    report_inclusion:        ReportInclusion = ReportInclusion.INCLUDED
    workflow_status:         WorkflowStatus  = WorkflowStatus.OPEN
    human_review_required:   bool            = False
    review_reason:           Optional[str]   = None
    ai_enriched:             bool            = False
    ai_enrichment_validated: bool            = False
    llm_enrichment_failed:   bool            = False
    is_duplicate:            bool            = False
    duplicate_of:            Optional[str]   = None  # finding_instance_id of primary

    # ── Audit trail ───────────────────────────────────────────────────
    audit_trail: list[AuditEvent] = Field(default_factory=list)

    # ── Helpers ───────────────────────────────────────────────────────

    def add_audit(
        self,
        stage: str,
        field: str,
        old_value: Any,
        new_value: Any,
        reason: str,
        actor: str = "pipeline",
    ) -> None:
        self.audit_trail.append(
            AuditEvent(
                stage=stage, field=field,
                old_value=old_value, new_value=new_value,
                reason=reason, actor=actor,
            )
        )

    def set_report_inclusion(
        self,
        value: ReportInclusion,
        stage: str,
        reason: str,
    ) -> None:
        old = self.report_inclusion
        self.report_inclusion = value
        self.add_audit(stage, "report_inclusion", old.value, value.value, reason)

    def flag_for_review(self, reason: str, stage: str) -> None:
        if not self.human_review_required:
            self.human_review_required = True
            self.review_reason = reason
            self.add_audit(stage, "human_review_required", False, True, reason)

    def completeness_score(self) -> int:
        """
        Score for representative instance selection. Higher = more complete.
        +1 per populated critical field.
        """
        score = 0
        if self.raw_requirement:
            score += 1
        if self.raw_details and self.raw_details.strip() not in ("", "N/A"):
            score += 1
        if self.check_title:
            score += 1
        if self.raw_criticality:
            score += 1
        if self.control_id:
            score += 1
        return score

    def ref_label(self) -> str:
        """Return the formatted ref label e.g. 'ENT1', 'DEF3'. Empty if not yet assigned."""
        if self.ref_prefix and self.ref_number is not None:
            return f"{self.ref_prefix}{self.ref_number}"
        return ""

    def to_ai_lane(self) -> dict[str, Any]:
        """
        Return the finding context dict for the LLM.

        AWS Bedrock policy confirmed: model providers have no access to prompts
        or completions, data is not used for training, retention is configurable
        to zero. Full context (including Details) produces better narratives.

        Mirrors CanonicalFinding.to_ai_lane() interface so sg_enrich can use
        identical call patterns to the Prowler pipeline.
        """
        return {
            # Identity
            "check_id":       self.control_id,
            "check_title":    self.check_title,
            "severity":       self.severity,
            "criticality_raw": self.criticality_raw,
            "status":         self.scanner_status.value,
            # Content
            "description":    self.check_title,     # check_title IS the policy statement
            "risk":           "",                    # no dedicated risk column in ScubaGear
            "status_extended": self.raw_details or "",  # most important field for narratives
            "remediation_recommendation_text": self.raw_details or "",
            "remediation_recommendation_url":  "",
            "remediation_code_cli":            "",
            "remediation_code_terraform":      "",
            # Scope
            "service_name":   self.service_name,
            "subservice_name": "",
            "resource_type":  "",
            "resource_uid":   self.control_id,  # no per-resource UID in ScubaGear
            "resource_name":  "",
            "region":         self.region,
            "account_name":   self.tenant_id,
            # Structured
            "categories":     [],
            "compliance":     [],
            "resource_tags":  {},
            # Pipeline-computed
            "instance_count":     self.instance_count,
            "likelihood_rating":  self.likelihood_rating,
            # ScubaGear-specific extras for richer narratives
            "omitted_result":     self.raw_omitted_result,
            "incorrect_result":   self.raw_incorrect_result,
            "original_result":    self.raw_original_result,
        }

    def to_audit_dict(self) -> dict[str, Any]:
        """Full canonical record for JSON export."""
        return self.model_dump(mode="json")