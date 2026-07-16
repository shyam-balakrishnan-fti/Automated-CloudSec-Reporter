"""
api/models.py — Pydantic request and response models for the GUI API.

Kept separate from the pipeline models (CanonicalFinding etc.) — this file
only covers what the GUI API accepts and returns.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────

class PipelineType(str, Enum):
    PROWLER    = "prowler"
    SCUBAGEAR  = "scubagear"
    BOTH       = "both"


class RunStatus(str, Enum):
    PENDING          = "pending"
    RUNNING          = "running"
    AWAITING_REVIEW  = "awaiting_review"
    ENRICHING        = "enriching"
    COMPLETE         = "complete"
    FAILED           = "failed"
    CANCELLED        = "cancelled"


class CredentialSource(str, Enum):
    PROFILE = "profile"
    KEYS    = "keys"


# ── Engagement ────────────────────────────────────────────────────────

class EngagementCreate(BaseModel):
    client_name:       str = Field(..., min_length=1, max_length=120)
    assessment_period: str = Field(..., min_length=1, max_length=60)
    analyst:           str = Field(default="", max_length=80)
    pipeline_type:     PipelineType
    notes:             str = Field(default="", max_length=2000)


class EngagementResponse(BaseModel):
    id:                str
    client_name:       str
    assessment_period: str
    analyst:           str
    pipeline_type:     PipelineType
    created_at:        str
    archived_at:       Optional[str]
    notes:             str
    run_count:         int = 0
    last_run_status:   Optional[str] = None


# ── Run ───────────────────────────────────────────────────────────────

class RunCreate(BaseModel):
    pipeline:          PipelineType
    input_file:        str = Field(..., min_length=1)
    input_format:      str = Field(default="auto")
    tenant_id:         str = Field(default="")

    # Bedrock inference profile ARN or deployment name
    deployment_name:   str = Field(default="")

    # AWS credentials
    credential_source: CredentialSource = CredentialSource.PROFILE
    aws_profile:       str = Field(default="")
    aws_region:        str = Field(default="ap-southeast-2")
    # Raw keys — only used when credential_source == "keys".
    # Never stored in DB; injected into subprocess env at launch time only.
    aws_access_key_id:     Optional[str] = Field(default=None, exclude=True)
    aws_secret_access_key: Optional[str] = Field(default=None, exclude=True)
    aws_session_token:     Optional[str] = Field(default=None, exclude=True)

    # Flags
    skip_review: bool = False
    skip_llm:    bool = False


class RunResponse(BaseModel):
    id:                str
    engagement_id:     str
    pipeline:          str
    status:            str
    input_file:        str
    input_format:      str
    tenant_id:         str
    credential_source: str
    aws_profile:       str
    aws_region:        str
    skip_review:       bool
    skip_llm:          bool
    created_at:        str
    started_at:        Optional[str]
    completed_at:      Optional[str]
    findings_total:    Optional[int]
    findings_included: Optional[int]
    groups_total:      Optional[int]
    groups_enriched:   Optional[int]
    risk_high:         Optional[int]
    risk_medium:       Optional[int]
    risk_low:          Optional[int]
    llm_failures:      Optional[int]
    excel_path:        Optional[str]
    config_path:       Optional[str]
    output_dir:        Optional[str]


# ── Config generation ─────────────────────────────────────────────────

class ConfigPreview(BaseModel):
    """What the GUI will write to config.toml before launching a run."""
    client_name:       str
    assessment_period: str
    analyst:           str
    aws_region:        str
    output_filename:   str


# ── Preflight ─────────────────────────────────────────────────────────

class PreflightCheck(BaseModel):
    name:    str
    status:  str   # "ok" | "warning" | "error"
    message: str
    blocking: bool  # if True, run cannot start until this passes


class PreflightResult(BaseModel):
    can_proceed: bool
    checks: list[PreflightCheck]


# ── Platform info (returned on startup) ───────────────────────────────

class PlatformInfo(BaseModel):
    os:                  str   # "windows" | "linux" | "darwin"
    scubagear_available: bool
    python_version:      str
    uv_available:        bool
    prowler_installed:   bool
    scubagear_installed: bool
    aws_profiles:        list[str]


# ── Scans ─────────────────────────────────────────────────────────────

class ScanProvider(str, Enum):
    AWS       = "aws"
    AZURE     = "azure"
    SCUBAGEAR = "scubagear"


class ScanType(str, Enum):
    PROWLER_AWS   = "prowler_aws"
    PROWLER_AZURE = "prowler_azure"
    SCUBAGEAR     = "scubagear"


class ScanStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETE  = "complete"
    FAILED    = "failed"
    CANCELLED = "cancelled"


class ScanCreate(BaseModel):
    provider:       ScanProvider
    scan_type:      str = Field(default="prowler_aws")
    tenant_domain:  str = Field(default="")
    m365_environment: str = Field(default="commercial")

    # Credential source
    credential_source: CredentialSource = CredentialSource.KEYS
    aws_profile:    str = Field(default="")

    # AWS fields
    scan_region:    str = Field(default="")
    scan_account_id: str = Field(default="")

    # Azure fields — secrets injected at launch, never stored
    azure_tenant_id:       str = Field(default="")
    azure_client_id:       str = Field(default="")
    azure_subscription_id: str = Field(default="")

    # Scope (optional)
    resource_scope: list[str] = Field(default_factory=list)  # ARN list
    services_scope: list[str] = Field(default_factory=list)  # service names

    # Raw secrets — never stored in DB, injected into subprocess env only
    aws_access_key_id:      Optional[str] = Field(default=None, exclude=True)
    aws_secret_access_key:  Optional[str] = Field(default=None, exclude=True)
    aws_session_token:      Optional[str] = Field(default=None, exclude=True)
    azure_client_secret:    Optional[str] = Field(default=None, exclude=True)


class ScanResponse(BaseModel):
    id:                   str
    engagement_id:        str
    provider:             str
    status:               str
    credential_source:    str
    aws_profile:          str
    scan_region:          str
    scan_account_id:      str
    azure_tenant_id:      str
    azure_client_id:      str
    azure_subscription_id: str
    resource_scope:       list[str]
    services_scope:       list[str]
    output_dir:           str
    output_file:          str
    created_at:           str
    started_at:           Optional[str]
    completed_at:         Optional[str]
    findings_count:       Optional[int]
    duration_secs:        Optional[int]