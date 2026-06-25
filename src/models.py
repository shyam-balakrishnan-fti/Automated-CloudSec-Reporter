"""
models.py — CanonicalFinding Pydantic model

The backbone of the entire pipeline. Every stage reads from or writes to this model.
Raw fields are write-once after parsing — enforced by validators.
Sensitive fields are never serialised into LLM payloads.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, model_validator


# ── Enumerations ─────────────────────────────────────────────────────

class ScannerStatus(str, Enum):
    PASS            = "PASS"
    FAIL            = "FAIL"
    MUTED_FAIL      = "MUTED(FAIL)"
    MUTED_PASS      = "MUTED(PASS)"
    MUTED_MANUAL    = "MUTED(MANUAL)"
    MANUAL          = "MANUAL"
    UNKNOWN         = "UNKNOWN"


class ReportInclusion(str, Enum):
    INCLUDED            = "INCLUDED"
    EXCLUDED            = "EXCLUDED"
    INCLUDED_IN_APPENDIX = "INCLUDED_IN_APPENDIX"


class WorkflowStatus(str, Enum):
    OPEN                    = "OPEN"
    FALSE_POSITIVE          = "FALSE_POSITIVE"
    ACCEPTED_RISK           = "ACCEPTED_RISK"
    COMPENSATING_CONTROL    = "COMPENSATING_CONTROL"
    NOT_APPLICABLE          = "NOT_APPLICABLE"
    RESOLVED                = "RESOLVED"
    NEEDS_REVIEW            = "NEEDS_REVIEW"


class BlankCategory(str, Enum):
    """
    Category 1: Structurally blank — Prowler never populates for this check type
    Category 2: Data quality blank — should have a value but Prowler omitted it
    Category 3: By-design blank — analyst/design intent, rarely populated
    """
    STRUCTURAL      = "STRUCTURAL"
    DATA_QUALITY    = "DATA_QUALITY"
    BY_DESIGN       = "BY_DESIGN"
    POPULATED       = "POPULATED"


# ── Audit trail entry ────────────────────────────────────────────────

class AuditEvent(BaseModel):
    """One field-level transformation event. Immutable once created."""
    timestamp:      datetime    = Field(default_factory=datetime.utcnow)
    stage:          str
    field:          str
    old_value:      Any
    new_value:      Any
    reason:         str
    actor:          str         = "pipeline"   # "pipeline" | "llm" | "human"


# ── Main canonical model ──────────────────────────────────────────────

class CanonicalFinding(BaseModel):
    """
    The single internal contract for the entire pipeline.

    Field groups:
        RUN IDENTITY        — immutable after ingestion
        FINDING IDENTITY    — four distinct keys, immutable after parsing
        RAW FIELDS          — all 41 Prowler columns, immutable after parsing
        NORMALISED FIELDS   — cleaned versions, written by Stage 2
        OUTPUT FIELDS       — pipeline-generated, written by Stages 2-3
        PROCESSING STATE    — mutable workflow flags
        AUDIT               — append-only event log
    """

    model_config = {"validate_assignment": True}

    # ── Run identity ─────────────────────────────────────────────────
    run_id:             str     = Field(default_factory=lambda: str(uuid.uuid4()))
    source_file:        str     = ""
    source_file_hash:   str     = ""
    scanner:            str     = "prowler"
    scanner_version:    str     = ""
    schema_version:     str     = "1.0.0"
    ingested_at:        datetime = Field(default_factory=datetime.utcnow)

    # ── Finding identity ──────────────────────────────────────────────
    # source_row_id: exact location in source file, e.g. "Sheet:prowler-output Row:5"
    source_row_id:          str = ""
    # finding_instance_id: stable handle within this file
    finding_instance_id:    str = Field(default_factory=lambda: str(uuid.uuid4()))
    # stable_finding_key: stable across repeated scans of same environment
    # Format: "provider:account_name:service:check_id:normalised_resource_id"
    stable_finding_key:     str = ""
    # dedup_key: within-run collision detection
    dedup_key:              str = ""

    # ── Raw fields (ALL 41 Prowler columns) ──────────────────────────
    # These are set once by the parser. The _raw_fields_locked flag
    # prevents any downstream stage from overwriting them.
    _raw_fields_locked: bool = False

    raw_auth_method:                Optional[str]   = None
    raw_timestamp:                  Optional[str]   = None
    raw_account_uid:                Optional[str]   = None
    raw_account_name:               Optional[str]   = None
    raw_account_email:              Optional[str]   = None
    raw_account_organization_uid:   Optional[str]   = None
    raw_account_organization_name:  Optional[str]   = None
    raw_account_tags:               Optional[str]   = None
    raw_finding_uid:                Optional[str]   = None
    raw_provider:                   Optional[str]   = None
    raw_check_id:                   Optional[str]   = None
    raw_check_title:                Optional[str]   = None
    raw_check_type:                 Optional[str]   = None
    raw_status:                     Optional[str]   = None
    raw_status_extended:            Optional[str]   = None
    raw_muted:                      Optional[str]   = None
    raw_service_name:               Optional[str]   = None
    raw_subservice_name:            Optional[str]   = None
    raw_severity:                   Optional[str]   = None
    raw_resource_type:              Optional[str]   = None
    raw_resource_uid:               Optional[str]   = None
    raw_resource_name:              Optional[str]   = None
    raw_resource_details:           Optional[str]   = None
    raw_resource_tags:              Optional[str]   = None
    raw_partition:                  Optional[str]   = None
    raw_region:                     Optional[str]   = None
    raw_description:                Optional[str]   = None
    raw_risk:                       Optional[str]   = None
    raw_related_url:                Optional[str]   = None
    raw_remediation_recommendation_text:    Optional[str] = None
    raw_remediation_recommendation_url:     Optional[str] = None
    raw_remediation_code_nativeiac:         Optional[str] = None
    raw_remediation_code_terraform:         Optional[str] = None
    raw_remediation_code_cli:               Optional[str] = None
    raw_remediation_code_other:             Optional[str] = None
    raw_compliance:                 Optional[str]   = None
    raw_categories:                 Optional[str]   = None
    raw_depends_on:                 Optional[str]   = None
    raw_related_to:                 Optional[str]   = None
    raw_notes:                      Optional[str]   = None
    raw_prowler_version:            Optional[str]   = None

    # Unknown columns from future Prowler versions
    extra_fields:   dict[str, Any]  = Field(default_factory=dict)

    # ── Blank value classifications ───────────────────────────────────
    blank_description:      BlankCategory = BlankCategory.POPULATED
    blank_risk:             BlankCategory = BlankCategory.POPULATED
    blank_remediation:      BlankCategory = BlankCategory.POPULATED
    blank_region:           BlankCategory = BlankCategory.POPULATED

    # ── Normalised fields (written by Stage 2) ────────────────────────
    scanner_status:             ScannerStatus   = ScannerStatus.UNKNOWN
    muted_reconciled:           bool            = False  # True if MUTED=True overrode STATUS
    region_normalised:          str             = ""     # "global" for IAM/account-level
    resource_uid_normalised:    str             = ""     # ARN preferred, name fallback
    arn_fallback_used:          bool            = False  # True if name used instead of ARN
    compliance_values:          list[str]       = Field(default_factory=list)
    compliance_parsed:          bool            = False
    categories_list:            list[str]       = Field(default_factory=list)
    account_tags_parsed:        dict[str, str]  = Field(default_factory=dict)
    resource_tags_parsed:       dict[str, str]  = Field(default_factory=dict)

    # ── Output-facing fields (written by Stages 2–3) ──────────────────
    likelihood_rating:          Optional[str]   = None  # Low | Medium | High
    consequence_rating:         Optional[str]   = None  # Minor | Moderate | Major
    risk_rating:                Optional[str]   = None  # Low | Medium | High
    output_section:             str             = ""    # "AWS" | "Azure Resources" etc.
    instance_count:             int             = 1
    representative_instance_id: Optional[str]   = None

    # LLM-generated narratives
    finding_title:              Optional[str]   = None
    root_cause_narrative:       Optional[str]   = None
    situation_narrative:        Optional[str]   = None
    consequence_narrative:      Optional[str]   = None
    access_required:            Optional[str]   = None

    # ── Processing state ──────────────────────────────────────────────
    report_inclusion:       ReportInclusion = ReportInclusion.INCLUDED
    workflow_status:        WorkflowStatus  = WorkflowStatus.OPEN
    human_review_required:  bool            = False
    review_reason:          Optional[str]   = None
    ai_enriched:            bool            = False
    ai_enrichment_validated:bool            = False
    llm_enrichment_failed:  bool            = False

    # Dedup state
    is_duplicate:           bool            = False
    duplicate_of:           Optional[str]   = None  # finding_instance_id of primary

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
        """Append a field-level audit event. This is the only way audit entries are created."""
        self.audit_trail.append(
            AuditEvent(
                stage=stage,
                field=field,
                old_value=old_value,
                new_value=new_value,
                reason=reason,
                actor=actor,
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
        Score used for representative instance selection.
        +1 for each non-blank critical field.
        """
        score = 0
        if self.raw_description:
            score += 1
        if self.raw_risk:
            score += 1
        if self.raw_remediation_recommendation_text:
            score += 1
        if self.raw_check_title:
            score += 1
        if self.raw_status_extended:
            score += 1
        return score

    def to_ai_lane(self) -> dict[str, Any]:
        """
        Return only the non-sensitive fields safe to send to the LLM.
        Sensitive fields (16 columns) are never included.
        STATUS_EXTENDED is included but must be scrubbed before use.
        """
        return {
            "check_id":                         self.raw_check_id,
            "check_title":                      self.raw_check_title,
            "check_type":                       self.raw_check_type,
            "severity":                         self.raw_severity,
            "status":                           self.scanner_status.value,
            "status_extended_raw":              self.raw_status_extended,  # caller must scrub
            "description":                      self.raw_description,
            "risk":                             self.raw_risk,
            "remediation_recommendation_text":  self.raw_remediation_recommendation_text,
            "remediation_recommendation_url":   self.raw_remediation_recommendation_url,
            "remediation_code_cli":             self.raw_remediation_code_cli,
            "remediation_code_terraform":       self.raw_remediation_code_terraform,
            "service_name":                     self.raw_service_name,
            "subservice_name":                  self.raw_subservice_name,
            "resource_type":                    self.raw_resource_type,
            "categories":                       self.categories_list,
            "compliance":                       self.compliance_values,
            "instance_count":                   self.instance_count,
            "likelihood_rating":                self.likelihood_rating,
        }

    def to_audit_dict(self) -> dict[str, Any]:
        """Full canonical record for JSON export — includes both lanes."""
        return self.model_dump(mode="json")
