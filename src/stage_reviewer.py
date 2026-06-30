"""
stage_reviewer.py — Combined enrichment review + grouping UI

Replaces stage2_5_reviewer.py with a richer sequential interface.

Flow:
    1. Stage 3 enriches individual OutputGroups (one per check_id)
    2. start_review_server() opens the review UI
    3. Analyst reads each finding in full context
    4. Analyst edits narratives inline (Option C — instant)
       OR leaves a comment for AI re-generation (Option A — live Bedrock call)
    5. After reviewing all findings, analyst groups them at the bottom
    6. Approve → server writes review_approved.json → pipeline continues

Server endpoints:
    GET  /              → serves the HTML
    POST /regenerate    → re-runs LLM for one finding with analyst comment
    POST /approve       → saves final state, signals pipeline to continue
"""

from __future__ import annotations

import json
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from models import CanonicalFinding
from stage2_process import OutputGroup
from stage3_llm import (
    EnrichResult,
    _build_prompt,
    _call_llm,
    _compute_risk_rating,
    _extract_json,
    _validate_response,
)


# ── Result schema ─────────────────────────────────────────────────────

@dataclass
class ReviewedFinding:
    check_id:              str
    group_name:            str
    finding_title:         str
    root_cause_narrative:  str
    situation_narrative:   str
    consequence_narrative: str
    consequence_rating:    str
    access_required:       str
    likelihood_rating:     str
    risk_rating:           str
    instance_count:        int
    affected_accounts:     list[str]
    analyst_comment:       str = ""
    analyst_edited:        bool = False
    ai_regenerated:        bool = False


@dataclass
class ReviewGroup:
    group_name: str
    check_ids:  list[str]
    rationale:  str = ""


@dataclass
class ReviewApproval:
    run_id:           str
    approved_at:      str
    findings:         list[ReviewedFinding]
    groups:           list[ReviewGroup]


def load_review_approval(path: Path) -> ReviewApproval:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = [ReviewedFinding(**f) for f in data.get("findings", [])]
    groups   = [ReviewGroup(**g) for g in data.get("groups", [])]
    return ReviewApproval(
        run_id      = data.get("run_id", ""),
        approved_at = data.get("approved_at", ""),
        findings    = findings,
        groups      = groups,
    )


# ── Build finding data for HTML ───────────────────────────────────────

def _build_findings_data(
    enrich_result: EnrichResult,
    ai_proposed_groups: list[dict],
) -> list[dict]:
    """Serialise enriched OutputGroups for the HTML."""
    findings = []
    fmap = {f.finding_instance_id: f for f in enrich_result.all_findings}

    for g in enrich_result.output_groups:
        rep = g.representative

        # Collect affected resources
        resources = []
        for fid in g.instance_ids:
            f = fmap.get(fid)
            if not f:
                continue
            res = (
                f.resource_uid_normalised
                or f.raw_resource_uid
                or f.raw_resource_name
                or ""
            )
            acct = f.raw_account_name or f.raw_account_uid or ""
            region = f.region_normalised or ""
            if res and res not in ("", "no_resource"):
                entry = {"resource": res, "account": acct, "region": region,
                         "type": f.raw_resource_type or ""}
                if entry not in resources:
                    resources.append(entry)

        check_id = getattr(g, "check_id", None) or (
            g.check_ids[0] if hasattr(g, "check_ids") and g.check_ids else ""
        )

        findings.append({
            "check_id":             check_id,
            "group_name":           getattr(g, "group_name", rep.raw_check_title or check_id),
            "finding_title":        rep.finding_title or rep.raw_check_title or check_id,
            "severity":             rep.raw_severity or "unknown",
            "likelihood_rating":    g.likelihood_rating or "Medium",
            "consequence_rating":   rep.consequence_rating or "Moderate",
            "risk_rating":          rep.risk_rating or "Medium",
            "root_cause_narrative": rep.root_cause_narrative or "",
            "situation_narrative":  rep.situation_narrative or "",
            "consequence_narrative":rep.consequence_narrative or "",
            "access_required":      rep.access_required or "",
            "recommendations":      rep.raw_remediation_recommendation_text or "",
            "instance_count":       g.instance_count,
            "affected_accounts":    g.affected_account_names,
            "affected_resources":   resources,
            "llm_failed":           rep.llm_enrichment_failed,
            "human_review_required":rep.human_review_required,
            "service":              rep.raw_service_name or "",
            "categories":           rep.categories_list or [],
            "check_title":          rep.raw_check_title or check_id,
            # LLM context for re-generation
            "_llm_ctx": g.to_llm_context(),
        })

    # Sort: Critical → High → Medium → Low
    _SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    _RISK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda x: (
        _RISK.get(x["risk_rating"], 2),
        _SEV.get(x["severity"].lower(), 5),
    ))
    return findings


# ── HTML generator ────────────────────────────────────────────────────

def _generate_html(
    enrich_result: EnrichResult,
    ai_proposed_groups: list[dict],
    client_name: str,
    port: int,
) -> str:
    findings_data = _build_findings_data(enrich_result, ai_proposed_groups)
    run_id        = enrich_result.run_id
    client_label  = client_name or "Security Assessment"
    total         = len(findings_data)

    findings_json       = json.dumps(findings_data)
    proposed_groups_json= json.dumps(ai_proposed_groups)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Automated Cloud Security Reporter — Review</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=DM+Sans:ital,wght@0,400;0,500;0,600;1,400&display=swap" rel="stylesheet">
<style>
:root{{
  --bg:#f0f2f5;--sidebar:#1b2332;--card:#fff;--border:#dde2ea;
  --accent:#2563eb;--accent-bg:#eff4ff;--accent-2:#1d4ed8;
  --text:#1a202c;--text-2:#4a5568;--muted:#8896a5;
  --success:#16a34a;--success-bg:#f0fdf4;
  --danger:#dc2626;--danger-bg:#fff1f2;
  --warning:#d97706;--warning-bg:#fffbeb;
  --critical-bg:#faf5ff;--critical-fg:#7c3aed;
  --high-bg:#fff1f2;--high-fg:#be123c;
  --medium-bg:#fffbeb;--medium-fg:#b45309;
  --low-bg:#f0fdf4;--low-fg:#15803d;
  --info-bg:#f8fafc;--info-fg:#64748b;
  --fh:"Plus Jakarta Sans",sans-serif;
  --fb:"DM Sans",sans-serif;
  --mono:"JetBrains Mono","Fira Code",monospace;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html,body{{height:100%;overflow:hidden;font-family:var(--fb)}}
body{{display:flex;font-size:13px;color:var(--text);background:var(--bg)}}

/* ── Sidebar ── */
.sidebar{{width:220px;min-width:220px;background:var(--sidebar);display:flex;flex-direction:column;height:100vh;overflow-y:auto}}
.sb-logo{{padding:18px 16px 12px;border-bottom:1px solid rgba(255,255,255,0.06)}}
.sb-product{{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#6b8cba;font-family:var(--fh)}}
.sb-client{{font-size:13px;font-weight:700;color:#e8edf5;line-height:1.3;font-family:var(--fh);margin-top:3px}}
.sb-runid{{font-size:10px;color:#4a6080;margin-top:3px;font-family:var(--mono);word-break:break-all}}
.logo-ph{{height:32px;width:110px;background:rgba(255,255,255,0.05);border:1px dashed rgba(255,255,255,0.12);border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:9px;color:#4a6080;margin-bottom:10px}}

.sb-section{{padding:12px 16px 6px}}
.sb-section-title{{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#4a6080;margin-bottom:8px;font-family:var(--fh)}}
.sb-stat{{display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.04)}}
.sb-stat:last-child{{border-bottom:none}}
.sb-stat-label{{font-size:11px;color:#8896a5}}
.sb-stat-value{{font-size:12px;font-weight:600;color:#c8d6e8;font-family:var(--mono)}}

.sb-nav{{padding:12px 16px 6px}}
.sb-nav-item{{display:flex;align-items:center;gap:8px;padding:6px 8px;border-radius:5px;cursor:pointer;font-size:12px;color:#8896a5;transition:all .12s;margin-bottom:2px}}
.sb-nav-item:hover,.sb-nav-item.active{{background:rgba(37,99,235,.15);color:#93b4f5}}
.sb-nav-dot{{width:6px;height:6px;border-radius:50%;background:currentColor;flex-shrink:0}}

.sb-actions{{padding:12px 16px;margin-top:auto;border-top:1px solid rgba(255,255,255,0.06);display:flex;flex-direction:column;gap:7px}}
.btn-sb{{width:100%;padding:8px 12px;border-radius:5px;border:none;font-size:12px;font-weight:600;cursor:pointer;transition:all .15s;font-family:var(--fb);display:flex;align-items:center;justify-content:center;gap:6px}}
.btn-sb:hover{{filter:brightness(1.1)}}
.btn-regen{{background:rgba(37,99,235,.15);color:#93b4f5;border:1px solid rgba(37,99,235,.3)}}
.btn-approve{{background:#16a34a;color:#fff;font-size:13px;padding:10px}}
.btn-approve:disabled{{background:#374151;color:#6b7280;cursor:not-allowed}}

/* ── Main ── */
.main{{flex:1;display:flex;flex-direction:column;height:100vh;overflow:hidden}}
.topbar{{background:var(--card);border-bottom:1px solid var(--border);padding:10px 20px;display:flex;align-items:center;gap:10px;flex-shrink:0}}
.topbar-title{{font-size:15px;font-weight:700;color:var(--text);font-family:var(--fh)}}
.topbar-badge{{font-size:11px;padding:2px 8px;border-radius:10px;background:var(--accent-bg);color:var(--accent);font-weight:600}}
.topbar-right{{margin-left:auto;display:flex;align-items:center;gap:12px}}
.progress-bar{{width:140px;height:6px;background:#e5e7eb;border-radius:3px;overflow:hidden}}
.progress-fill{{height:100%;background:var(--accent);border-radius:3px;transition:width .3s}}

.inst-bar{{background:var(--accent-bg);border-bottom:1px solid #bfdbfe;padding:7px 20px;font-size:12px;color:#1e40af;flex-shrink:0}}

.content{{flex:1;overflow-y:auto;padding:16px 20px 80px}}

/* ── Section headers ── */
.section-header{{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:20px 0 10px;padding-left:2px;font-family:var(--fh)}}
.section-header:first-child{{margin-top:0}}

/* ── Finding card ── */
.finding-card{{background:var(--card);border:1px solid var(--border);border-radius:8px;margin-bottom:10px;overflow:hidden;transition:box-shadow .15s}}
.finding-card.expanded{{box-shadow:0 4px 16px rgba(0,0,0,.08)}}
.finding-card.approved-card{{border-left:3px solid var(--success)}}
.finding-card.flagged-card{{border-left:3px solid var(--warning)}}
.finding-card.failed-card{{border-left:3px solid var(--danger)}}

/* Card header (always visible) */
.card-header{{padding:10px 14px;display:flex;align-items:center;gap:10px;cursor:pointer;user-select:none}}
.card-header:hover{{background:#fafafa}}
.risk-badge{{font-size:11px;font-weight:700;padding:3px 9px;border-radius:4px;flex-shrink:0;min-width:60px;text-align:center}}
.rb-critical{{background:var(--critical-bg);color:var(--critical-fg)}}
.rb-high{{background:var(--high-bg);color:var(--high-fg)}}
.rb-medium{{background:var(--medium-bg);color:var(--medium-fg)}}
.rb-low{{background:var(--low-bg);color:var(--low-fg)}}
.card-title{{font-size:13px;font-weight:600;color:var(--text);flex:1;font-family:var(--fh)}}
.card-meta{{display:flex;align-items:center;gap:6px;flex-shrink:0}}
.meta-pill{{font-size:11px;padding:2px 7px;border-radius:10px;font-weight:500;white-space:nowrap}}
.mp-likelihood{{background:#f1f5f9;color:#475569}}
.mp-consequence{{background:#f0f9ff;color:#0369a1}}
.mp-count{{background:#f0fdf4;color:#15803d}}
.mp-accounts{{background:#fef9c3;color:#854d0e}}
.mp-service{{background:#f8fafc;color:#64748b}}
.card-chevron{{color:var(--muted);font-size:14px;transition:transform .2s;flex-shrink:0}}
.card-chevron.open{{transform:rotate(180deg)}}
.status-dot{{width:8px;height:8px;border-radius:50%;flex-shrink:0}}
.sd-pending{{background:#d1d5db}}
.sd-approved{{background:#16a34a}}
.sd-flagged{{background:#f59e0b}}
.sd-failed{{background:#dc2626}}

/* Card body (expanded) */
.card-body{{padding:0 14px 14px;display:none;border-top:1px solid var(--border)}}
.card-body.open{{display:block}}

.fields-grid{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}}
.field-full{{grid-column:1/-1}}
.field-label{{font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:4px;font-family:var(--fh)}}
.field-edit{{width:100%;border:1px solid var(--border);border-radius:5px;padding:6px 9px;font-size:12px;color:var(--text);font-family:var(--fb);resize:vertical;min-height:60px;transition:border-color .12s,box-shadow .12s;background:#fff;line-height:1.5}}
.field-edit:focus{{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-bg)}}
.field-edit.edited{{border-color:#f59e0b;background:#fffbeb}}
.field-select{{width:100%;border:1px solid var(--border);border-radius:5px;padding:6px 9px;font-size:12px;color:var(--text);font-family:var(--fb);background:#fff;cursor:pointer;transition:border-color .12s}}
.field-select:focus{{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-bg)}}
.field-readonly{{font-size:12px;color:var(--text-2);background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:6px 9px;line-height:1.5}}

/* Resources */
.resources-list{{margin-top:4px;display:flex;flex-direction:column;gap:3px}}
.resource-item{{font-size:11px;font-family:var(--mono);color:var(--text-2);background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:3px 7px;display:flex;gap:8px;align-items:center}}
.res-arn{{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.res-acct{{color:var(--muted);flex-shrink:0;font-size:10px}}
.res-region{{color:var(--muted);flex-shrink:0;font-size:10px}}

/* Comment + regen */
.comment-section{{margin-top:12px;padding-top:12px;border-top:1px solid var(--border)}}
.comment-label{{font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:5px;font-family:var(--fh)}}
.comment-input{{width:100%;border:1px solid var(--border);border-radius:5px;padding:7px 9px;font-size:12px;color:var(--text);font-family:var(--fb);resize:vertical;min-height:50px;transition:border-color .12s}}
.comment-input:focus{{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-bg)}}
.comment-actions{{display:flex;align-items:center;gap:8px;margin-top:7px}}
.btn-regen-inline{{padding:6px 14px;border-radius:5px;border:1px solid rgba(37,99,235,.3);background:var(--accent-bg);color:var(--accent);font-size:12px;font-weight:600;cursor:pointer;font-family:var(--fb);transition:all .12s}}
.btn-regen-inline:hover{{background:var(--accent);color:#fff}}
.btn-regen-inline:disabled{{opacity:.5;cursor:not-allowed}}
.regen-status{{font-size:11px;color:var(--muted)}}

/* Card footer */
.card-footer{{display:flex;align-items:center;gap:8px;margin-top:12px;padding-top:10px;border-top:1px solid var(--border)}}
.btn-approve-finding{{padding:5px 14px;border-radius:5px;border:none;background:var(--success);color:#fff;font-size:12px;font-weight:600;cursor:pointer;font-family:var(--fb)}}
.btn-approve-finding:hover{{background:#15803d}}
.btn-flag-finding{{padding:5px 14px;border-radius:5px;border:1px solid var(--warning);background:var(--warning-bg);color:var(--warning);font-size:12px;font-weight:600;cursor:pointer;font-family:var(--fb)}}
.btn-collapse{{padding:5px 14px;border-radius:5px;border:1px solid var(--border);background:#fff;color:var(--text-2);font-size:12px;cursor:pointer;font-family:var(--fb);margin-left:auto}}

/* ── Grouping section ── */
.grouping-section{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;margin-top:20px}}
.gs-title{{font-size:14px;font-weight:700;color:var(--text);font-family:var(--fh);margin-bottom:4px}}
.gs-subtitle{{font-size:12px;color:var(--muted);margin-bottom:14px}}
.gs-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:10px}}
.group-card{{background:var(--bg);border:2px solid var(--border);border-radius:6px;min-height:80px;padding:10px;transition:border-color .15s}}
.group-card.drag-over{{border-color:var(--accent);background:var(--accent-bg)}}
.group-card.merged{{border-top:3px solid var(--accent)}}
.gc-header{{display:flex;align-items:center;gap:6px;margin-bottom:8px}}
.gc-name-input{{flex:1;border:1px solid transparent;border-radius:4px;padding:3px 6px;font-size:12px;font-weight:700;font-family:var(--fh);color:var(--text);background:transparent}}
.gc-name-input:hover,.gc-name-input:focus{{border-color:var(--border);background:#fff;outline:none}}
.gc-del{{padding:2px 7px;border-radius:4px;border:1px solid #fecaca;background:#fff;color:var(--danger);font-size:11px;cursor:pointer;font-family:var(--fb)}}
.gc-chips{{display:flex;flex-wrap:wrap;gap:4px;min-height:30px}}
.gc-chip{{font-size:11px;padding:3px 8px;border-radius:4px;background:#fff;border:1px solid var(--border);cursor:grab;font-family:var(--mono);display:flex;align-items:center;gap:4px;transition:all .12s}}
.gc-chip:hover{{border-color:var(--accent);background:var(--accent-bg)}}
.gc-chip.dragging{{opacity:.3}}
.chip-risk{{width:8px;height:8px;border-radius:2px;flex-shrink:0}}

.unassigned-pool-wrap{{background:var(--warning-bg);border:1px solid #fde68a;border-radius:6px;padding:10px;margin-bottom:12px}}
.unassigned-pool-wrap h4{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--warning);font-family:var(--fh);margin-bottom:6px}}
.unassigned-pool{{display:flex;flex-wrap:wrap;gap:4px;min-height:30px}}
.unassigned-pool.drag-over{{background:#fef3c7}}
.gs-actions{{display:flex;gap:8px;margin-top:12px}}
.btn-gs{{padding:6px 14px;border-radius:5px;font-size:12px;font-weight:600;cursor:pointer;font-family:var(--fb);border:1px solid var(--border);background:#fff;color:var(--text-2)}}
.btn-gs:hover{{background:var(--bg)}}

/* ── Status bar ── */
.statusbar{{position:fixed;bottom:0;left:220px;right:0;background:#fff;border-top:1px solid var(--border);padding:7px 20px;display:flex;align-items:center;gap:12px;z-index:50;font-size:12px}}
.status-ok{{color:var(--success);font-weight:500}}
.status-err{{color:var(--danger);font-weight:500}}
.status-info{{color:var(--text-2)}}

/* ── Spinner ── */
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.spinner{{width:14px;height:14px;border:2px solid #e5e7eb;border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;display:inline-block;vertical-align:middle}}

/* Scrollbar */
::-webkit-scrollbar{{width:5px}}
::-webkit-scrollbar-thumb{{background:#cbd5e1;border-radius:3px}}
</style>
</head>
<body>

<!-- ── Sidebar ── -->
<aside class="sidebar">
  <div class="sidebar-logo">
    <div class="logo-img-wrap">
    <img class="logo-img" id="company-logo"
     src="/static/logo.png"
     alt="FTI logo"
     onerror="this.style.display='none';document.getElementById('logo-ph').style.display='flex';" />
    </div>

  <div class="sb-section">
    <div class="sb-section-title">Progress</div>
    <div class="sb-stat"><span class="sb-stat-label">Total Findings</span><span class="sb-stat-value">{total}</span></div>
    <div class="sb-stat"><span class="sb-stat-label">Reviewed</span><span class="sb-stat-value" id="s-reviewed">0</span></div>
    <div class="sb-stat"><span class="sb-stat-label">Approved</span><span class="sb-stat-value" id="s-approved">0</span></div>
    <div class="sb-stat"><span class="sb-stat-label">Flagged</span><span class="sb-stat-value" id="s-flagged">0</span></div>
    <div class="sb-stat"><span class="sb-stat-label">AI Regenerated</span><span class="sb-stat-value" id="s-regen">0</span></div>
    <div class="sb-stat"><span class="sb-stat-label">Edited Inline</span><span class="sb-stat-value" id="s-edited">0</span></div>
  </div>

  <div class="sb-section">
    <div class="sb-section-title">Risk Summary</div>
    <div class="sb-stat"><span class="sb-stat-label" style="color:#7c3aed">Critical</span><span class="sb-stat-value" id="s-critical">0</span></div>
    <div class="sb-stat"><span class="sb-stat-label" style="color:#be123c">High</span><span class="sb-stat-value" id="s-high">0</span></div>
    <div class="sb-stat"><span class="sb-stat-label" style="color:#b45309">Medium</span><span class="sb-stat-value" id="s-medium">0</span></div>
    <div class="sb-stat"><span class="sb-stat-label" style="color:#15803d">Low</span><span class="sb-stat-value" id="s-low">0</span></div>
  </div>

  <div class="sb-actions">
    <button class="btn-sb btn-regen" id="btn-regen-all" onclick="regenAllFlagged()">
      ↺ Re-gen All Flagged
    </button>
    <button class="btn-sb btn-approve" id="btn-approve" onclick="approveAll()" disabled>
      ✓ Approve &amp; Continue
    </button>
  </div>
</aside>

<!-- ── Main ── -->
<div class="main">
  <div class="topbar">
    <div>
      <span class="topbar-title">Finding Review</span>
      <span class="topbar-badge" id="tb-badge">0 / {total} reviewed</span>
    </div>
    <div class="topbar-right">
      <div class="progress-bar"><div class="progress-fill" id="progress-fill" style="width:0%"></div></div>
      <span style="font-size:11px;color:var(--muted)" id="tb-pct">0%</span>
    </div>
  </div>

  <div class="inst-bar">
    <strong>Review each finding:</strong> expand to read full context, edit text inline, or leave a comment and click
    <strong>Re-generate</strong> for AI to revise. Approve or flag each finding.
    After reviewing all findings, scroll down to <strong>Group Findings</strong>.
  </div>

  <div class="content" id="content">
    <div id="findings-list"></div>

    <!-- ── Grouping section ── -->
    <div class="grouping-section" id="grouping-section">
      <div class="gs-title">Group Findings</div>
      <div class="gs-subtitle">Drag findings into groups. The AI has suggested groups below — adjust as needed.</div>

      <div id="unassigned-pool-wrap" style="display:none" class="unassigned-pool-wrap">
        <h4>⚠ Unassigned — drag into a group</h4>
        <div class="unassigned-pool" id="unassigned-pool"
             ondragover="onGDragOver(event,'__unassigned__')"
             ondrop="onGDrop(event,'__unassigned__')"
             ondragleave="onGDragLeave(event)"></div>
      </div>

      <div class="gs-grid" id="groups-grid"></div>

      <div class="gs-actions">
        <button class="btn-gs" onclick="addGroup()">＋ New Group</button>
        <button class="btn-gs" onclick="resetGroups()">↺ Reset to AI Proposal</button>
      </div>
    </div>
  </div>
</div>

<!-- Status bar -->
<div class="statusbar">
  <span id="status-msg" class="status-info">Loading findings...</span>
</div>

<script>
const FINDINGS      = {findings_json};
const AI_GROUPS     = {proposed_groups_json};
const RUN_ID        = "{run_id}";
const PORT          = {port};
const RISK_MATRIX   = {{"High_Major":"High","High_Moderate":"High","High_Minor":"High","Medium_Major":"High","Medium_Moderate":"Medium","Medium_Minor":"Medium","Low_Major":"Medium","Low_Moderate":"Medium","Low_Minor":"Low","Critical_Major":"Critical","Critical_Moderate":"Critical","Critical_Minor":"High"}};

// ── State ──────────────────────────────────────────────────────────────
let state = {{}};  // check_id → {{...finding fields, status:'pending'|'approved'|'flagged'}}
let groups = [];   // {{id, group_name, check_ids, rationale}}
let gDragCid = null, gDragFrom = null;

// ── Init ───────────────────────────────────────────────────────────────
function init() {{
  FINDINGS.forEach(f => {{
    state[f.check_id] = {{
      ...f,
      status:         'pending',
      analyst_comment:'',
      analyst_edited: false,
      ai_regenerated: false,
    }};
  }});
  initGroups();
  renderFindings();
  renderGroups();
  updateStats();
  setStatus('Review each finding, then group and approve.', 'info');
}}

// ── Render findings ────────────────────────────────────────────────────
function renderFindings() {{
  const list = document.getElementById('findings-list');
  list.innerHTML = '';

  // Section headers by risk
  const sections = {{'Critical':[],'High':[],'Medium':[],'Low':[]}};
  FINDINGS.forEach(f => {{
    const r = state[f.check_id].risk_rating || 'Medium';
    (sections[r] || sections['Medium']).push(f.check_id);
  }});

  ['Critical','High','Medium','Low'].forEach(risk => {{
    if (!sections[risk].length) return;
    const hdr = document.createElement('div');
    hdr.className = 'section-header';
    hdr.textContent = risk + ' (' + sections[risk].length + ')';
    list.appendChild(hdr);
    sections[risk].forEach(cid => list.appendChild(buildCard(cid)));
  }});
}}

function buildCard(checkId) {{
  const s   = state[checkId];
  const rr  = s.risk_rating || 'Medium';
  const div = document.createElement('div');
  div.id        = 'card-' + esc(checkId);
  div.className = 'finding-card ' + cardClass(s);

  const dot  = dotClass(s);
  const meta = buildMetaPills(s);
  const body = buildCardBody(s);

  div.innerHTML = `
    <div class="card-header" onclick="toggleCard('${{esc(checkId)}}')">
      <span class="status-dot ${{dot}}"></span>
      <span class="risk-badge rb-${{rr.toLowerCase()}}">${{rr}}</span>
      <span class="card-title">${{esc(s.finding_title || s.check_id)}}</span>
      <div class="card-meta">${{meta}}</div>
      <span class="card-chevron" id="chev-${{esc(checkId)}}">▼</span>
    </div>
    <div class="card-body" id="body-${{esc(checkId)}}">${{body}}</div>
  `;
  return div;
}}

function buildMetaPills(s) {{
  const parts = [];
  if (s.likelihood_rating) parts.push(`<span class="meta-pill mp-likelihood">Likelihood: ${{s.likelihood_rating}}</span>`);
  if (s.consequence_rating) parts.push(`<span class="meta-pill mp-consequence">${{s.consequence_rating}}</span>`);
  if (s.instance_count > 1) parts.push(`<span class="meta-pill mp-count">${{s.instance_count}} resources</span>`);
  if (s.affected_accounts?.length) parts.push(`<span class="meta-pill mp-accounts">${{s.affected_accounts.join(', ')}}</span>`);
  if (s.service) parts.push(`<span class="meta-pill mp-service">${{s.service}}</span>`);
  return parts.join('');
}}

function buildCardBody(s) {{
  const resources = (s.affected_resources || []).map(r =>
    `<div class="resource-item">
      <span class="res-arn" title="${{esc(r.resource)}}">${{esc(r.resource || r.type || 'Unknown resource')}}</span>
      <span class="res-acct">${{esc(r.account)}}</span>
      <span class="res-region">${{esc(r.region)}}</span>
    </div>`
  ).join('');

  return `
    <div class="fields-grid">
      <div>
        <div class="field-label">Root Cause</div>
        <textarea class="field-edit" id="rc-${{esc(s.check_id)}}" rows="3"
          oninput="onEdit('${{esc(s.check_id)}}','root_cause_narrative',this.value)"
        >${{esc(s.root_cause_narrative)}}</textarea>
      </div>
      <div>
        <div class="field-label">Consequence Rating</div>
        <select class="field-select" id="cr-${{esc(s.check_id)}}"
          onchange="onSelectChange('${{esc(s.check_id)}}','consequence_rating',this.value)">
          <option value="Minor" ${{s.consequence_rating==='Minor'?'selected':''}}>Minor</option>
          <option value="Moderate" ${{s.consequence_rating==='Moderate'?'selected':''}}>Moderate</option>
          <option value="Major" ${{s.consequence_rating==='Major'?'selected':''}}>Major</option>
        </select>
        <div style="margin-top:8px">
          <div class="field-label">Access Required</div>
          <textarea class="field-edit" id="ar-${{esc(s.check_id)}}" rows="2"
            oninput="onEdit('${{esc(s.check_id)}}','access_required',this.value)"
          >${{esc(s.access_required)}}</textarea>
        </div>
      </div>
      <div class="field-full">
        <div class="field-label">Situation</div>
        <textarea class="field-edit" id="si-${{esc(s.check_id)}}" rows="3"
          oninput="onEdit('${{esc(s.check_id)}}','situation_narrative',this.value)"
        >${{esc(s.situation_narrative)}}</textarea>
      </div>
      <div class="field-full">
        <div class="field-label">Consequence</div>
        <textarea class="field-edit" id="co-${{esc(s.check_id)}}" rows="3"
          oninput="onEdit('${{esc(s.check_id)}}','consequence_narrative',this.value)"
        >${{esc(s.consequence_narrative)}}</textarea>
      </div>
      ${{(s.affected_resources||[]).length ? `
      <div class="field-full">
        <div class="field-label">Affected Resources (${{(s.affected_resources||[]).length}})</div>
        <div class="resources-list">${{resources}}</div>
      </div>` : ''}}
      <div class="field-full">
        <div class="field-label">Recommendations (from scanner — read only)</div>
        <div class="field-readonly">${{esc(s.recommendations || 'Not available')}}</div>
      </div>
    </div>

    <div class="comment-section">
      <div class="comment-label">Comment for AI — describe what to improve (leave blank if editing inline)</div>
      <textarea class="comment-input" id="cmt-${{esc(s.check_id)}}" rows="2"
        placeholder="e.g. The situation narrative is too generic, mention the specific service type and the compliance implication..."
        oninput="state['${{esc(s.check_id)}}'].analyst_comment = this.value"
      >${{esc(s.analyst_comment||'')}}</textarea>
      <div class="comment-actions">
        <button class="btn-regen-inline" id="btn-rg-${{esc(s.check_id)}}"
          onclick="regenOne('${{esc(s.check_id)}}')"
          title="Re-generate this finding with your comment">
          ↺ Re-generate with AI
        </button>
        <span class="regen-status" id="rg-status-${{esc(s.check_id)}}"></span>
      </div>
    </div>

    <div class="card-footer">
      <button class="btn-approve-finding" onclick="approveFinding('${{esc(s.check_id)}}')">✓ Approve</button>
      <button class="btn-flag-finding" onclick="flagFinding('${{esc(s.check_id)}}')">⚑ Flag for review</button>
      <button class="btn-collapse" onclick="toggleCard('${{esc(s.check_id)}}')">Collapse</button>
    </div>
  `;
}}

function cardClass(s) {{
  if (s.llm_failed) return 'failed-card';
  if (s.status === 'approved') return 'approved-card';
  if (s.status === 'flagged') return 'flagged-card';
  return '';
}}
function dotClass(s) {{
  if (s.llm_failed) return 'sd-failed';
  if (s.status === 'approved') return 'sd-approved';
  if (s.status === 'flagged') return 'sd-flagged';
  return 'sd-pending';
}}

// ── Card interactions ──────────────────────────────────────────────────
function toggleCard(checkId) {{
  const body = document.getElementById('body-' + checkId);
  const chev = document.getElementById('chev-' + checkId);
  const card = document.getElementById('card-' + checkId);
  const open = body.classList.contains('open');
  body.classList.toggle('open', !open);
  if (chev) chev.classList.toggle('open', !open);
  if (card) card.classList.toggle('expanded', !open);
}}

function onEdit(checkId, field, value) {{
  state[checkId][field] = value;
  state[checkId].analyst_edited = true;
  const el = document.getElementById(
    {{root_cause_narrative:'rc',situation_narrative:'si',
      consequence_narrative:'co',access_required:'ar'}}[field] + '-' + checkId
  );
  if (el) el.classList.add('edited');
}}

function onSelectChange(checkId, field, value) {{
  state[checkId][field] = value;
  // Recompute risk_rating
  const likelihood = state[checkId].likelihood_rating || 'Medium';
  const key = likelihood + '_' + value;
  state[checkId].risk_rating = RISK_MATRIX[key] || 'Medium';
  state[checkId].analyst_edited = true;
  // Update header badge
  const card = document.getElementById('card-' + checkId);
  if (card) {{
    const badge = card.querySelector('.risk-badge');
    const rr = state[checkId].risk_rating;
    if (badge) {{ badge.textContent = rr; badge.className = 'risk-badge rb-' + rr.toLowerCase(); }}
  }}
  updateStats();
}}

function approveFinding(checkId) {{
  state[checkId].status = 'approved';
  refreshCard(checkId);
  updateStats();
  setStatus('✓ ' + (state[checkId].finding_title || checkId) + ' approved.', 'ok');
}}

function flagFinding(checkId) {{
  state[checkId].status = 'flagged';
  refreshCard(checkId);
  updateStats();
  setStatus('⚑ ' + (state[checkId].finding_title || checkId) + ' flagged for review.', 'info');
}}

function refreshCard(checkId) {{
  const card = document.getElementById('card-' + checkId);
  if (!card) return;
  const s = state[checkId];
  card.className = 'finding-card ' + cardClass(s) + (card.classList.contains('expanded') ? ' expanded' : '');
  const dot = card.querySelector('.status-dot');
  if (dot) dot.className = 'status-dot ' + dotClass(s);
}}

// ── AI Re-generation ───────────────────────────────────────────────────
function regenOne(checkId) {{
  const s       = state[checkId];
  const comment = s.analyst_comment || '';
  const btn     = document.getElementById('btn-rg-' + checkId);
  const status  = document.getElementById('rg-status-' + checkId);

  btn.disabled = true;
  status.innerHTML = '<span class="spinner"></span> Asking AI...';

  fetch('http://localhost:' + PORT + '/regenerate', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{
      check_id:        checkId,
      analyst_comment: comment,
      current_state:   s,
    }}),
  }})
  .then(r => r.json())
  .then(data => {{
    if (data.ok) {{
      // Update state
      ['finding_title','root_cause_narrative','situation_narrative',
       'consequence_narrative','consequence_rating','access_required'].forEach(f => {{
        if (data[f]) state[checkId][f] = data[f];
      }});
      if (data.risk_rating) state[checkId].risk_rating = data.risk_rating;
      state[checkId].ai_regenerated = true;
      state[checkId].analyst_comment = '';

      // Update DOM
      updateFieldEl('rc', checkId, state[checkId].root_cause_narrative);
      updateFieldEl('si', checkId, state[checkId].situation_narrative);
      updateFieldEl('co', checkId, state[checkId].consequence_narrative);
      updateFieldEl('ar', checkId, state[checkId].access_required);
      const crEl = document.getElementById('cr-' + checkId);
      if (crEl) crEl.value = state[checkId].consequence_rating;
      const cmtEl = document.getElementById('cmt-' + checkId);
      if (cmtEl) cmtEl.value = '';

      // Update header
      const card = document.getElementById('card-' + checkId);
      if (card) {{
        const badge = card.querySelector('.risk-badge');
        const rr = state[checkId].risk_rating;
        if (badge) {{ badge.textContent = rr; badge.className = 'risk-badge rb-' + rr.toLowerCase(); }}
        const title = card.querySelector('.card-title');
        if (title) title.textContent = state[checkId].finding_title || checkId;
      }}

      status.textContent = '✓ Regenerated';
      status.style.color = '#16a34a';
      updateStats();
    }} else {{
      status.textContent = '✗ ' + (data.error || 'Failed');
      status.style.color = '#dc2626';
    }}
    btn.disabled = false;
  }})
  .catch(err => {{
    status.textContent = '✗ Server error: ' + err;
    status.style.color = '#dc2626';
    btn.disabled = false;
  }});
}}

function updateFieldEl(prefix, checkId, value) {{
  const el = document.getElementById(prefix + '-' + checkId);
  if (el) {{ el.value = value; el.classList.remove('edited'); }}
}}

function regenAllFlagged() {{
  const flagged = Object.keys(state).filter(cid => state[cid].status === 'flagged' && state[cid].analyst_comment);
  if (!flagged.length) {{
    setStatus('No flagged findings with comments to re-generate.', 'info');
    return;
  }}
  setStatus('Re-generating ' + flagged.length + ' flagged finding(s)...', 'info');
  // Sequential to avoid rate limits
  flagged.reduce((p, cid) => p.then(() => {{
    regenOne(cid);
    return new Promise(r => setTimeout(r, 500));
  }}), Promise.resolve());
}}

// ── Stats ──────────────────────────────────────────────────────────────
function updateStats() {{
  const vals = Object.values(state);
  const approved  = vals.filter(s => s.status === 'approved').length;
  const flagged   = vals.filter(s => s.status === 'flagged').length;
  const reviewed  = vals.filter(s => s.status !== 'pending').length;
  const regen     = vals.filter(s => s.ai_regenerated).length;
  const edited    = vals.filter(s => s.analyst_edited && !s.ai_regenerated).length;

  const counts = {{'Critical':0,'High':0,'Medium':0,'Low':0}};
  vals.forEach(s => {{ counts[s.risk_rating] = (counts[s.risk_rating]||0)+1; }});

  setText('s-reviewed', reviewed);
  setText('s-approved', approved);
  setText('s-flagged', flagged);
  setText('s-regen', regen);
  setText('s-edited', edited);
  setText('s-critical', counts.Critical||0);
  setText('s-high', counts.High||0);
  setText('s-medium', counts.Medium||0);
  setText('s-low', counts.Low||0);

  const pct = Math.round(reviewed / vals.length * 100);
  setText('tb-badge', reviewed + ' / ' + vals.length + ' reviewed');
  const fill = document.getElementById('progress-fill');
  if (fill) fill.style.width = pct + '%';
  setText('tb-pct', pct + '%');

  const approveBtn = document.getElementById('btn-approve');
  if (approveBtn) approveBtn.disabled = (reviewed < vals.length);
}}

// ── Grouping ───────────────────────────────────────────────────────────
function initGroups() {{
  if (AI_GROUPS && AI_GROUPS.length) {{
    groups = AI_GROUPS.map((g, i) => ({{
      id: 'g' + i,
      group_name: g.group_name,
      check_ids:  [...g.check_ids],
      rationale:  g.rationale || '',
    }}));
  }} else {{
    // One group per finding as fallback
    groups = FINDINGS.map((f, i) => ({{
      id: 'g' + i,
      group_name: f.finding_title || f.check_id,
      check_ids:  [f.check_id],
      rationale:  '',
    }}));
  }}
}}

function renderGroups() {{
  const grid = document.getElementById('groups-grid');
  grid.innerHTML = '';
  groups.forEach(g => grid.appendChild(buildGroupCard(g)));

  const allAssigned = new Set(groups.flatMap(g => g.check_ids));
  const unassigned  = FINDINGS.map(f => f.check_id).filter(cid => !allAssigned.has(cid));
  const pool = document.getElementById('unassigned-pool');
  const wrap = document.getElementById('unassigned-pool-wrap');
  pool.innerHTML = '';
  if (unassigned.length) {{
    wrap.style.display = 'block';
    unassigned.forEach(cid => pool.appendChild(buildGroupChip(cid, '__unassigned__')));
  }} else {{
    wrap.style.display = 'none';
  }}
}}

function buildGroupCard(g) {{
  const merged = g.check_ids.length > 1;
  const card = document.createElement('div');
  card.className = 'group-card ' + (merged ? 'merged' : '');
  card.dataset.gid = g.id;
  card.ondragover  = e => onGDragOver(e, g.id);
  card.ondrop      = e => onGDrop(e, g.id);
  card.ondragleave = e => onGDragLeave(e);

  const chips = g.check_ids.map(cid => buildGroupChip(cid, g.id).outerHTML).join('');
  card.innerHTML = `
    <div class="gc-header">
      <input class="gc-name-input" type="text" value="${{esc(g.group_name)}}"
        onchange="renameGroup('${{g.id}}',this.value)" />
      <button class="gc-del" onclick="deleteGroup('${{g.id}}')">✕</button>
    </div>
    <div class="gc-chips" id="gchips-${{g.id}}">${{chips}}</div>
  `;
  return card;
}}

function buildGroupChip(checkId, gid) {{
  const s   = state[checkId];
  const rr  = (s && s.risk_rating || 'medium').toLowerCase();
  const colors = {{critical:'#7c3aed',high:'#be123c',medium:'#b45309',low:'#15803d'}};
  const chip = document.createElement('div');
  chip.className = 'gc-chip';
  chip.draggable = true;
  chip.dataset.cid = checkId;
  chip.dataset.gid = gid;
  chip.innerHTML = `<span class="chip-risk" style="background:${{colors[rr]||'#64748b'}}"></span>${{esc(checkId)}}`;
  chip.ondragstart = e => {{ gDragCid = checkId; gDragFrom = gid; e.currentTarget.classList.add('dragging'); e.dataTransfer.effectAllowed='move'; }};
  chip.ondragend   = e => e.currentTarget.classList.remove('dragging');
  return chip;
}}

function onGDragOver(e, gid) {{
  e.preventDefault();
  const el = gid === '__unassigned__' ? document.getElementById('unassigned-pool') : document.querySelector('[data-gid="' + gid + '"]');
  if (el) el.classList.add('drag-over');
}}
function onGDragLeave(e) {{ const el = e.currentTarget; if (el) el.classList.remove('drag-over'); }}
function onGDrop(e, toGid) {{
  e.preventDefault();
  document.querySelectorAll('.drag-over').forEach(el => el.classList.remove('drag-over'));
  if (!gDragCid || gDragFrom === toGid) {{ gDragCid = null; gDragFrom = null; return; }}

  // Remove from source
  if (gDragFrom !== '__unassigned__') {{
    const g = groups.find(x => x.id === gDragFrom);
    if (g) g.check_ids = g.check_ids.filter(c => c !== gDragCid);
  }}
  // Add to dest
  if (toGid !== '__unassigned__') {{
    const g = groups.find(x => x.id === toGid);
    if (g && !g.check_ids.includes(gDragCid)) g.check_ids.push(gDragCid);
  }}
  groups = groups.filter(g => g.check_ids.length > 0);
  gDragCid = null; gDragFrom = null;
  renderGroups();
}}

function renameGroup(gid, v) {{ const g = groups.find(x => x.id === gid); if (g) g.group_name = v.trim() || g.group_name; }}
function deleteGroup(gid) {{
  const g = groups.find(x => x.id === gid); if (!g) return;
  groups = groups.filter(x => x.id !== gid);
  renderGroups();
}}
function addGroup() {{
  const id = 'gnew' + Date.now();
  groups.push({{id, group_name:'New Group', check_ids:[], rationale:''}});
  renderGroups();
  setTimeout(() => {{
    const inp = document.querySelector('[data-gid="' + id + '"] .gc-name-input');
    if (inp) {{ inp.focus(); inp.select(); }}
  }}, 50);
}}
function resetGroups() {{ if (confirm('Reset to AI proposal?')) {{ initGroups(); renderGroups(); }} }}

// ── Approve all ────────────────────────────────────────────────────────
function approveAll() {{
  const unassigned = FINDINGS.map(f => f.check_id)
    .filter(cid => !groups.some(g => g.check_ids.includes(cid)));
  if (unassigned.length) {{
    setStatus('⚠ ' + unassigned.length + ' finding(s) not in any group. Please assign them first.', 'err');
    document.getElementById('grouping-section').scrollIntoView({{behavior:'smooth'}});
    return;
  }}
  const emptyGroups = groups.filter(g => g.check_ids.length === 0);
  if (emptyGroups.length) {{
    setStatus('⚠ ' + emptyGroups.length + ' empty group(s). Delete them before approving.', 'err');
    return;
  }}

  const findings = Object.values(state).map(s => ({{
    check_id:              s.check_id,
    group_name:            s.group_name || s.check_id,
    finding_title:         s.finding_title,
    root_cause_narrative:  s.root_cause_narrative,
    situation_narrative:   s.situation_narrative,
    consequence_narrative: s.consequence_narrative,
    consequence_rating:    s.consequence_rating,
    access_required:       s.access_required,
    likelihood_rating:     s.likelihood_rating,
    risk_rating:           s.risk_rating,
    instance_count:        s.instance_count,
    affected_accounts:     s.affected_accounts,
    analyst_comment:       s.analyst_comment,
    analyst_edited:        s.analyst_edited,
    ai_regenerated:        s.ai_regenerated,
  }}));

  const payload = {{
    run_id:       RUN_ID,
    approved_at:  new Date().toISOString(),
    findings,
    groups: groups.map(g => ({{
      group_name: g.group_name,
      check_ids:  g.check_ids,
      rationale:  g.rationale || '',
    }})),
  }};

  setStatus('Sending approval to pipeline...', 'info');
  document.getElementById('btn-approve').disabled = true;

  fetch('http://localhost:' + PORT + '/approve', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify(payload),
  }})
  .then(r => r.json())
  .then(data => {{
    if (data.ok) {{
      setStatus('✓ Approved — pipeline is continuing to render Excel...', 'ok');
      document.getElementById('btn-approve').textContent = '✓ Approved';
    }} else {{
      setStatus('✗ Error: ' + data.error, 'err');
      document.getElementById('btn-approve').disabled = false;
    }}
  }})
  .catch(err => {{
    setStatus('✗ Could not reach pipeline: ' + err, 'err');
    document.getElementById('btn-approve').disabled = false;
  }});
}}

// ── Helpers ────────────────────────────────────────────────────────────
function esc(s) {{ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }}
function setText(id, v) {{ const el = document.getElementById(id); if (el) el.textContent = v; }}
function setStatus(msg, type) {{
  const el = document.getElementById('status-msg');
  if (!el) return;
  el.textContent = msg;
  el.className = type === 'ok' ? 'status-ok' : type === 'err' ? 'status-err' : 'status-info';
}}

init();
</script>
</body>
</html>"""


# ── HTTP server ───────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):
    html_content:      str = ""
    approved_path:     Path = None
    approval_event:    threading.Event = None
    llm_cfg:           dict = {}
    risk_matrix:       dict = {}

    def log_message(self, fmt, *args):
        pass  # suppress access logs

    def do_GET(self):
        if self.path in ("/", "/review"):
            body = _Handler.html_content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/static/"):
            static_dir = Path(__file__).resolve().parent / "static"
            file_path  = static_dir / self.path[8:]
            if file_path.exists() and file_path.is_file():
                ext  = file_path.suffix.lower()
                mime = {".png":"image/png",".jpg":"image/jpeg",".jpeg":"image/jpeg",
                        ".svg":"image/svg+xml",".gif":"image/gif",".webp":"image/webp"
                        }.get(ext, "application/octet-stream")
                body = file_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", len(body))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)

        if self.path == "/regenerate":
            self._handle_regenerate(body)
        elif self.path == "/approve":
            self._handle_approve(body)
        else:
            self.send_response(404)
            self.end_headers()

    def _json_response(self, status: int, data: dict):
        resp = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", len(resp))
        self.end_headers()
        self.wfile.write(resp)

    def _handle_regenerate(self, body: bytes):
        """Re-run LLM for one finding with analyst comment."""
        try:
            req          = json.loads(body)
            check_id     = req.get("check_id", "")
            comment      = req.get("analyst_comment", "")
            current      = req.get("current_state", {})
            llm_ctx      = current.get("_llm_ctx", {})

            # Build enriched prompt with analyst comment
            prompt = _build_prompt(llm_ctx)
            if comment:
                prompt += (
                    f"\n\n=== ANALYST FEEDBACK ===\n"
                    f"The analyst reviewed the current output and provided this feedback:\n"
                    f"{comment}\n\n"
                    f"Please revise ALL narrative fields to address this feedback. "
                    f"Return the same JSON structure with improved content."
                )

            raw    = _call_llm(prompt, _Handler.llm_cfg)
            parsed = _extract_json(raw)
            errors = _validate_response(parsed)

            if errors:
                self._json_response(400, {"ok": False, "error": "; ".join(errors)})
                return

            # Recompute risk_rating
            likelihood  = current.get("likelihood_rating", "Medium")
            consequence = parsed.get("consequence_rating", "Moderate")
            risk_rating = _compute_risk_rating(likelihood, consequence, _Handler.risk_matrix)

            self._json_response(200, {
                "ok":                    True,
                "finding_title":         parsed.get("finding_title", ""),
                "root_cause_narrative":  parsed.get("root_cause_narrative", ""),
                "situation_narrative":   parsed.get("situation_narrative", ""),
                "consequence_narrative": parsed.get("consequence_narrative", ""),
                "consequence_rating":    parsed.get("consequence_rating", ""),
                "access_required":       parsed.get("access_required", ""),
                "risk_rating":           risk_rating,
            })

        except Exception as e:
            self._json_response(500, {"ok": False, "error": str(e)})

    def _handle_approve(self, body: bytes):
        """Save the final approval and signal the pipeline."""
        try:
            data = json.loads(body)
            if not data.get("findings"):
                raise ValueError("No findings in payload")
            _Handler.approved_path.write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )
            self._json_response(200, {"ok": True})
            _Handler.approval_event.set()
        except Exception as e:
            self._json_response(400, {"ok": False, "error": str(e)})


# ── Public entry point ────────────────────────────────────────────────

def start_review_server(
    enrich_result:      EnrichResult,
    output_dir:         Path,
    ai_proposed_groups: list[dict],
    config:             dict[str, Any],
    client_name:        str = "",
    port:               int = 8742,
    open_browser:       bool = True,
    timeout_seconds:    int = 7200,
) -> dict:
    """
    Start the review server and wait for analyst approval.

    Returns the raw approval dict (findings + groups).
    """
    approved_path  = output_dir / "review_approved.json"
    if approved_path.exists():
        approved_path.unlink()

    html = _generate_html(enrich_result, ai_proposed_groups, client_name, port)

    approval_event = threading.Event()
    _Handler.html_content   = html
    _Handler.approved_path  = approved_path
    _Handler.approval_event = approval_event
    _Handler.llm_cfg        = config.get("llm", {})
    _Handler.risk_matrix    = config.get("risk_matrix", {})

    server = HTTPServer(("localhost", port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://localhost:{port}/review"
    print(f"\n  {'─'*60}", flush=True)
    print(f"  🌐 Review UI: {url}", flush=True)
    print(f"  ⏳ Waiting for analyst approval...", flush=True)
    print(f"  {'─'*60}\n", flush=True)

    if open_browser:
        time.sleep(0.4)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    spinner = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    elapsed = 0
    while elapsed < timeout_seconds:
        if approval_event.wait(timeout=1):
            print(f"\r  ✓ Approval received                           ", flush=True)
            server.shutdown()
            return json.loads(approved_path.read_text(encoding="utf-8"))
        mins, secs = divmod(elapsed, 60)
        print(
            f"\r  {spinner[elapsed % len(spinner)]} Waiting... {mins:02d}:{secs:02d}  ",
            end="", flush=True,
        )
        elapsed += 1

    server.shutdown()
    raise TimeoutError(f"No approval after {timeout_seconds // 60} minutes.")