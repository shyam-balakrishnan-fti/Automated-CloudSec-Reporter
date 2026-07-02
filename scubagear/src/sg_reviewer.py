"""
sg_reviewer.py — ScubaGear Grouping Review UI

Localhost browser review server. Identical architecture to stage_reviewer.py
with M365-specific adaptations:
  - Check chips show Control ID (MS.AAD.3.1v1) instead of AWS check IDs
  - Resource panel shows M365 service + Details text instead of ARNs
  - Regroup prompts reference M365 services, not AWS services
  - /regroup-global and /regroup-one use sg_enrich._call_llm (not stage3_llm)
  - ApprovedGrouping / load_approved_grouping are M365-agnostic (identical interface)

Critical JS patterns (do not change):
  - Chip drag-and-drop uses appendChild, never outerHTML (preserves event listeners)
  - Group card IDs are position-based ("g0", "g1") never name-derived
  - e.dataTransfer.setData('text/plain', cid) always called in dragstart
"""

from __future__ import annotations

import json
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from sg_grouping import GroupedOutputGroup, GroupingResult, GroupingWarning
from sg_process import OutputGroup


# ── Approved grouping schema ──────────────────────────────────────────

@dataclass
class ApprovedGroup:
    group_name:   str
    check_ids:    list[str]
    rationale:    str = ""
    analyst_note: str = ""
    risk_rating:  str = ""   # analyst override; empty = compute from risk matrix


@dataclass
class ApprovedGrouping:
    run_id:      str
    approved_at: str
    groups:      list[ApprovedGroup] = field(default_factory=list)


def load_approved_grouping(path: Path) -> ApprovedGrouping:
    data = json.loads(path.read_text(encoding="utf-8"))
    groups = []
    for g in data.get("groups", []):
        if not g.get("group_name") or not g.get("check_ids"):
            raise ValueError(
                f"Invalid group in approved file: missing group_name or check_ids. Got: {g}"
            )
        groups.append(ApprovedGroup(
            group_name   = g["group_name"],
            check_ids    = g["check_ids"],
            rationale    = g.get("rationale", ""),
            analyst_note = g.get("analyst_note", ""),
            risk_rating  = g.get("risk_rating", ""),
        ))
    if not groups:
        raise ValueError("Approved grouping has no groups.")
    return ApprovedGrouping(
        run_id=data.get("run_id", ""),
        approved_at=data.get("approved_at", ""),
        groups=groups,
    )


# ── Data builder (M365-specific) ──────────────────────────────────────

def _build_group_data(grouping_result: GroupingResult) -> list[dict]:
    result = []
    for i, g in enumerate(grouping_result.grouped_groups):
        checks = []
        for src in g.source_groups:
            f = src.representative
            checks.append({
                "check_id":       src.check_id,
                "check_title":    f.check_title or src.check_id,
                "severity":       f.severity or "medium",
                "instance_count": src.instance_count,
                "accounts":       src.affected_tenant_ids,
                "likelihood":     src.likelihood_rating or "High",
                "service":        f.service_name or "",
                "categories":     [],  # ScubaGear has no categories column
            })

        result.append({
            "id":               f"grp_{i}",
            "group_name":       g.group_name,
            "rationale":        g.group_rationale,
            "is_merged":        g.is_merged,
            "check_ids":        g.check_ids,
            "checks":           checks,
            "instance_count":   g.instance_count,
            "accounts":         g.affected_tenant_ids,
            "severity":         g.severity or "medium",
            "likelihood":       g.likelihood_rating or "High",
            "affected_resources": g.affected_resources(),
            "output_section":   g.output_section or "Other",
            "ref_label":        g.representative.ref_label() if g.representative else "",
            "risk_rating":      (g.representative.risk_rating or "") if g.representative else "",
        })
    return result


def _all_checks_lookup(groups_data: list[dict]) -> dict[str, dict]:
    lookup: dict[str, dict] = {}
    for g in groups_data:
        for c in g["checks"]:
            lookup[c["check_id"]] = c
    return lookup


# ── Regroup prompts (M365-specific) ──────────────────────────────────

def _build_global_regroup_prompt(
    instruction: str,
    all_groups: list[dict],
    unassigned: list[str],
) -> str:
    group_list = "\n".join(
        f'{i+1:3}. "{g["group_name"]}" — check_ids={g["check_ids"]}'
        for i, g in enumerate(all_groups)
    )
    unassigned_block = f"\nUnassigned controls: {unassigned}\n" if unassigned else ""
    return f"""You are a Microsoft 365 security analyst regrouping CISA SCuBA baseline
findings per an analyst's explicit instruction.

=== CURRENT GROUPS ===
{group_list}
{unassigned_block}
=== ANALYST INSTRUCTION ===
{instruction}

=== INSTRUCTIONS ===
1. Apply the analyst's instruction across the ENTIRE board.
2. Every check_id (control ID) must appear in exactly one output group.
3. For any group you create or change, write a brief rationale.
4. Do NOT merge controls across different M365 services (MS.AAD, MS.EXCHANGE,
   MS.DEFENDER, etc.) unless the analyst explicitly asks for this.

=== OUTPUT FORMAT ===
Respond with ONLY a valid JSON array.

[
  {{"group_name": "...", "check_ids": [...], "rationale": ""}}
]"""


def _build_one_group_regroup_prompt(
    instruction: str,
    target_group: dict,
    all_groups: list[dict],
) -> str:
    group_list = "\n".join(
        f'{i+1:3}. "{g["group_name"]}" — check_ids={g["check_ids"]}'
        for i, g in enumerate(all_groups)
    )
    return f"""You are a Microsoft 365 security analyst adjusting ONE finding group.

=== TARGET GROUP ===
"{target_group['group_name']}" — check_ids={target_group['check_ids']}
Current rationale: {target_group.get('rationale', '')}

=== ALL GROUPS (for context) ===
{group_list}

=== ANALYST INSTRUCTION (for the target group only) ===
{instruction}

=== INSTRUCTIONS ===
1. Apply the instruction to the target group only.
2. Every check_id from the target group must end up in exactly one output group.
3. Return ALL groups (changed and unchanged) so the board can be reconstructed.

=== OUTPUT FORMAT ===
Respond with ONLY a valid JSON array.

[
  {{"group_name": "...", "check_ids": [...], "rationale": "..."}}
]"""


def _extract_json_array(raw: str) -> Any:
    text = raw.strip()
    if text.startswith("```"):
        lines = [l for l in text.split("\n") if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("[")
    end   = text.rfind("]") + 1
    if start != -1 and end > start:
        return json.loads(text[start:end])
    raise json.JSONDecodeError("No valid JSON array found", text, 0)


def _validate_regroup_response(data: Any, expected_ids: set[str]) -> list[str]:
    errors = []
    if not isinstance(data, list) or not data:
        return ["Expected a non-empty JSON array"]
    seen: set[str] = set()
    for i, item in enumerate(data):
        if not isinstance(item, dict) or not item.get("group_name") or not item.get("check_ids"):
            errors.append(f"Group {i}: missing group_name or check_ids")
            continue
        for cid in item["check_ids"]:
            if cid in seen:
                errors.append(f"check_id '{cid}' appears in more than one group")
            seen.add(cid)
    missing = expected_ids - seen
    if missing:
        errors.append(f"Missing check_ids: {sorted(missing)}")
    return errors


# ── HTML generator ────────────────────────────────────────────────────

def generate_review_html(
    grouping_result: GroupingResult,
    client_name: str,
    port: int,
) -> str:
    groups_data   = _build_group_data(grouping_result)
    all_checks    = _all_checks_lookup(groups_data)
    run_id        = grouping_result.run_id
    client_label  = client_name or "M365 Security Assessment"
    total_checks  = sum(len(g["check_ids"]) for g in groups_data)
    total_groups  = len(groups_data)

    groups_json     = json.dumps(groups_data)
    all_checks_json = json.dumps(all_checks)

    # Build section order list for JS (only sections that have groups)
    from sg_models import SECTION_ORDER as _SO
    section_order_json = json.dumps(_SO)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Automated Cloud Security Reporter — M365 Grouping Review</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Source+Sans+3:ital,wght@0,400;0,500;0,600;0,700;1,400&display=swap" rel="stylesheet">
<style>
:root{{
  --navy:#002A54;--navy-light:#0a3d6e;--navy-pale:#e9eef4;
  --teal:#007A87;--teal-light:#e3f1f3;--teal-dark:#005f69;
  --bg:#f4f6f8;--sidebar:#002A54;--card:#fff;--border:#d8dee5;
  --accent:#007A87;--accent-bg:#e3f1f3;--accent-2:#005f69;
  --text:#1a2b3c;--text-2:#4a5b6c;--muted:#7a8a99;
  --success:#0f7a3d;--success-bg:#eaf6ef;
  --danger:#a8231f;--danger-bg:#fbeceb;
  --warning:#9a5b00;--warning-bg:#fdf3e3;
  --high-bg:#fbeceb;--high-fg:#a8231f;
  --medium-bg:#fdf3e3;--medium-fg:#9a5b00;
  --low-bg:#eaf6ef;--low-fg:#0f7a3d;
  --info-bg:#eef1f4;--info-fg:#5a6b7a;
  --fh:"Source Sans 3","Segoe UI",Arial,sans-serif;
  --fb:"Source Sans 3","Segoe UI",Arial,sans-serif;
  --mono:"IBM Plex Mono","Consolas",monospace;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html,body{{height:100%;overflow:hidden;font-family:var(--fb)}}
body{{display:flex;font-size:13px;color:var(--text);background:var(--bg)}}

/* ── Sidebar ── */
.sidebar{{width:230px;min-width:230px;background:var(--sidebar);display:flex;flex-direction:column;height:100vh;overflow-y:auto}}
.sb-logo{{padding:18px 16px 12px;border-bottom:1px solid rgba(255,255,255,0.06)}}
.logo-img{{height:32px;width:auto;max-width:160px;object-fit:contain;display:block;margin-bottom:10px}}
.logo-ph{{height:32px;width:120px;background:rgba(255,255,255,0.05);border:1px dashed rgba(255,255,255,0.12);border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:9px;color:#4a6080;margin-bottom:10px}}
.sb-product{{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#6b8cba;font-family:var(--fh)}}
.sb-client{{font-size:13px;font-weight:700;color:#e8edf5;line-height:1.3;font-family:var(--fh);margin-top:3px}}
.sb-runid{{font-size:10px;color:#4a6080;margin-top:3px;font-family:var(--mono);word-break:break-all}}
.sb-section{{padding:12px 16px 6px}}
.sb-section-title{{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#4a6080;margin-bottom:8px;font-family:var(--fh)}}
.sb-stat{{display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.04)}}
.sb-stat:last-child{{border-bottom:none}}
.sb-stat-label{{font-size:11px;color:#8896a5}}
.sb-stat-value{{font-size:12px;font-weight:600;color:#c8d6e8;font-family:var(--mono)}}
.sb-actions{{padding:12px 16px;margin-top:auto;border-top:1px solid rgba(255,255,255,0.06);display:flex;flex-direction:column;gap:7px}}
.btn-sb{{width:100%;padding:9px 12px;border-radius:5px;border:none;font-size:13px;font-weight:600;cursor:pointer;transition:all .15s;font-family:var(--fb)}}
.btn-sb:hover{{filter:brightness(1.1)}}
.btn-approve{{background:#16a34a;color:#fff}}
.btn-approve:disabled{{background:#374151;color:#6b7280;cursor:not-allowed}}
.btn-reset{{background:rgba(255,255,255,0.06);color:#93b4f5;border:1px solid rgba(255,255,255,0.1)}}
.btn-new-group{{background:rgba(22,163,74,0.12);color:#4ade80;border:1px solid rgba(22,163,74,0.25)}}

/* ── Main ── */
.main{{flex:1;display:flex;flex-direction:column;height:100vh;overflow:hidden}}
.topbar{{background:var(--card);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:10px;flex-shrink:0}}
.topbar-title{{font-size:15px;font-weight:700;color:var(--text);font-family:var(--fh)}}
.topbar-sub{{font-size:12px;color:var(--muted);margin-left:4px}}

/* ── Global AI bar ── */
.global-ai-bar{{background:var(--navy-pale);border-bottom:1px solid var(--border);padding:12px 20px;flex-shrink:0;display:flex;gap:10px;align-items:flex-start}}
.global-ai-input-wrap{{flex:1;display:flex;gap:8px}}
.global-ai-input{{flex:1;border:1px solid #c7d6fb;border-radius:6px;padding:8px 12px;font-size:13px;font-family:var(--fb);background:#fff;resize:none;min-height:38px}}
.global-ai-input:focus{{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-bg)}}
.btn-global-ai{{padding:8px 16px;border-radius:6px;border:none;background:var(--accent);color:#fff;font-size:13px;font-weight:600;cursor:pointer;font-family:var(--fb);white-space:nowrap;flex-shrink:0}}
.btn-global-ai:hover{{background:var(--accent-2)}}
.btn-global-ai:disabled{{background:#94a3b8;cursor:not-allowed}}
.global-ai-hint{{font-size:11px;color:var(--muted);margin-top:4px}}
.inst-bar{{background:var(--accent-bg);border-bottom:1px solid #bfdbfe;padding:7px 20px;font-size:12px;color:#1e40af;flex-shrink:0}}

/* ── Content ── */
.content{{flex:1;overflow-y:auto;padding:16px 20px 80px}}

/* ── Unassigned pool ── */
.unassigned-bar{{position:sticky;top:0;z-index:40;background:var(--warning-bg);border:1px solid #e0c28a;border-radius:4px;padding:10px 14px;margin-bottom:14px}}
.unassigned-bar h4{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--warning);font-family:var(--fh);margin-bottom:6px}}
.unassigned-pool{{display:flex;flex-wrap:wrap;gap:5px;min-height:32px}}
.unassigned-pool.drag-over{{background:#fef3c7}}

/* ── Section header ── */
.section-block{{margin-bottom:20px}}
.section-header{{display:flex;align-items:center;gap:10px;padding:8px 0 8px 2px;cursor:pointer;user-select:none}}
.section-chevron{{font-size:14px;color:var(--accent);transition:transform .2s;display:inline-block;width:18px;text-align:center}}
.section-chevron.collapsed{{transform:rotate(-90deg)}}
.section-label{{font-size:13px;font-weight:700;color:var(--navy);font-family:var(--fh);flex:1}}
.section-badge{{font-size:11px;font-weight:600;background:var(--accent-bg);color:var(--accent);padding:2px 8px;border-radius:10px}}
.section-body{{display:grid;grid-template-columns:repeat(auto-fill,minmax(420px,1fr));gap:14px;align-items:start}}
.section-body.collapsed{{display:none}}

/* ── Group card ── */
.group-card{{background:var(--card);border:1px solid var(--border);border-radius:4px;overflow:visible;transition:border-color .15s;display:flex;flex-direction:column}}
.group-card.drag-over{{border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-bg)}}
.group-card.merged{{border-top:3px solid var(--accent)}}
.group-card.standalone{{border-top:3px solid var(--border)}}
.gc-header{{padding:12px 14px 8px;display:flex;align-items:flex-start;gap:8px}}
.gc-header-left{{flex:1;min-width:0}}
.gc-ref{{font-size:11px;font-weight:700;font-family:var(--mono);color:var(--accent);margin-bottom:3px}}
.gc-name-input{{font-size:14px;font-weight:700;color:var(--text);border:1px solid transparent;border-radius:4px;padding:3px 6px;width:100%;background:transparent;font-family:var(--fh)}}
.gc-name-input:hover{{border-color:var(--border);background:var(--bg)}}
.gc-name-input:focus{{outline:none;border-color:var(--accent);background:#fff;box-shadow:0 0 0 2px var(--accent-bg)}}
.gc-badges{{display:flex;gap:4px;flex-wrap:wrap;margin-top:6px}}
.badge{{font-size:10px;padding:2px 7px;border-radius:3px;font-weight:600;white-space:nowrap;letter-spacing:.02em}}
.badge-merged{{background:#dbeafe;color:#1d4ed8}}
.badge-standalone{{background:var(--info-bg);color:var(--info-fg)}}
.badge-count{{background:#f0fdf4;color:#15803d}}
.badge-accts{{background:#fef9c3;color:#92400e}}
.badge-high{{background:var(--high-bg);color:var(--high-fg)}}
.badge-medium{{background:var(--medium-bg);color:var(--medium-fg)}}
.badge-low{{background:var(--low-bg);color:var(--low-fg)}}
.badge-unknown{{background:var(--info-bg);color:var(--info-fg)}}
.gc-header-actions{{display:flex;gap:4px;flex-shrink:0;padding-top:2px}}
.btn-xs{{padding:3px 8px;border-radius:4px;border:1px solid var(--border);font-size:11px;font-weight:500;cursor:pointer;background:#fff;color:var(--text-2);font-family:var(--fb)}}
.btn-xs:hover{{background:var(--bg)}}
.btn-xs-danger{{border-color:#fecaca;color:var(--danger)}}
.btn-xs-danger:hover{{background:#fff1f2}}

/* ── Risk rating editor ── */
.gc-risk-row{{padding:6px 14px 0;display:flex;align-items:center;gap:8px;border-top:1px solid var(--border)}}
.gc-risk-label{{font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-family:var(--fh);flex-shrink:0}}
.gc-risk-select{{padding:3px 8px;border-radius:4px;border:1px solid var(--border);font-size:12px;font-weight:600;font-family:var(--fb);background:#fff;cursor:pointer;flex-shrink:0}}
.gc-risk-select:focus{{outline:none;border-color:var(--accent)}}
.gc-risk-select.risk-High{{background:var(--high-bg);color:var(--high-fg);border-color:#fca5a5}}
.gc-risk-select.risk-Medium{{background:var(--medium-bg);color:var(--medium-fg);border-color:#fcd34d}}
.gc-risk-select.risk-Low{{background:var(--low-bg);color:var(--low-fg);border-color:#86efac}}
.gc-risk-hint{{font-size:10px;color:var(--muted);font-style:italic}}

.gc-rationale{{font-size:11px;color:var(--text-2);line-height:1.5;margin:8px 14px;padding:7px 9px;background:var(--accent-bg);border-radius:5px;border-left:2px solid var(--accent);overflow:hidden;min-height:38px}}
.gc-rationale.empty{{color:var(--muted);font-style:italic}}
.gc-chips{{padding:6px 14px 10px;display:flex;flex-wrap:wrap;gap:5px;min-height:40px;border-top:1px solid var(--border)}}
.check-chip{{background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:4px 8px;font-size:11px;cursor:grab;user-select:none;display:flex;align-items:center;gap:5px;transition:all .12s}}
.check-chip:hover{{border-color:var(--accent);background:var(--accent-bg)}}
.check-chip.dragging{{opacity:.35}}
.chip-sev{{width:14px;height:14px;border-radius:2px;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:800;flex-shrink:0}}
.chip-body{{display:flex;flex-direction:column;min-width:0}}
.chip-id{{font-family:var(--mono);font-size:10px;font-weight:600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:240px}}
.chip-title{{font-size:10px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:240px}}
.gc-resources-toggle{{padding:8px 14px;font-size:11px;color:var(--accent);cursor:pointer;border-top:1px solid var(--border);font-weight:600;display:flex;align-items:center;gap:5px}}
.gc-resources-toggle:hover{{background:var(--bg)}}
.gc-resources{{display:none;padding:0 14px 10px;border-top:1px solid var(--border)}}
.gc-resources.open{{display:block}}
.resource-row{{font-size:10.5px;font-family:var(--mono);color:var(--text-2);background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:4px 8px;margin-top:5px;display:flex;gap:8px;align-items:center}}
.res-arn{{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.res-meta{{color:var(--muted);flex-shrink:0;font-size:9.5px}}
.gc-ai-box{{padding:10px 14px;border-top:1px solid var(--border);background:#fafbff}}
.gc-ai-label{{font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:5px;font-family:var(--fh)}}
.gc-ai-input{{width:100%;border:1px solid var(--border);border-radius:5px;padding:6px 9px;font-size:11.5px;font-family:var(--fb);resize:none;min-height:36px}}
.gc-ai-input:focus{{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-bg)}}
.gc-ai-actions{{display:flex;align-items:center;gap:8px;margin-top:6px}}
.btn-ai-regen{{padding:5px 12px;border-radius:5px;border:1px solid rgba(37,99,235,.3);background:var(--accent-bg);color:var(--accent);font-size:11px;font-weight:600;cursor:pointer;font-family:var(--fb)}}
.btn-ai-regen:hover{{background:var(--accent);color:#fff}}
.btn-ai-regen:disabled{{opacity:.5;cursor:not-allowed}}
.ai-regen-status{{font-size:10.5px;color:var(--muted)}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.spinner{{width:12px;height:12px;border:2px solid #e5e7eb;border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;display:inline-block;vertical-align:middle}}
.statusbar{{position:fixed;bottom:0;left:230px;right:0;background:#fff;border-top:1px solid var(--border);padding:8px 20px;display:flex;align-items:center;gap:12px;z-index:50;font-size:12px}}
.status-ok{{color:var(--success);font-weight:500}}
.status-err{{color:var(--danger);font-weight:500}}
.status-info{{color:var(--text-2)}}
::-webkit-scrollbar{{width:5px}}
::-webkit-scrollbar-thumb{{background:#cbd5e1;border-radius:3px}}
</style>
</head>
<body>

<aside class="sidebar">
  <div class="sb-logo">
    <img class="logo-img" id="company-logo" src="/static/logo.jpeg" alt="Company logo"
         onerror="this.style.display='none';document.getElementById('logo-ph').style.display='flex';" />
    <div class="logo-ph" id="logo-ph" style="display:none">YOUR LOGO</div>
    <div class="sb-product">Automated Cloud Security Reporter</div>
    <div class="sb-client">{client_label}</div>
    <div class="sb-runid">Run: {run_id[:16]}...</div>
  </div>

  <div class="sb-section">
    <div class="sb-section-title">Summary</div>
    <div class="sb-stat"><span class="sb-stat-label">AI Proposed Groups</span><span class="sb-stat-value">{total_groups}</span></div>
    <div class="sb-stat"><span class="sb-stat-label">Current Groups</span><span class="sb-stat-value" id="s-current">—</span></div>
    <div class="sb-stat"><span class="sb-stat-label">Merged</span><span class="sb-stat-value" id="s-merged">—</span></div>
    <div class="sb-stat"><span class="sb-stat-label">Standalone</span><span class="sb-stat-value" id="s-standalone">—</span></div>
    <div class="sb-stat"><span class="sb-stat-label">Total Controls</span><span class="sb-stat-value">{total_checks}</span></div>
    <div class="sb-stat"><span class="sb-stat-label">Unassigned</span><span class="sb-stat-value" id="s-unassigned" style="color:#f59e0b">0</span></div>
  </div>

  <div class="sb-actions">
    <button class="btn-sb btn-new-group" onclick="addNewGroup()">New Group</button>
    <button class="btn-sb btn-reset" onclick="resetToProposal()">Reset to Proposed Grouping</button>
    <button class="btn-sb btn-approve" id="approve-btn" onclick="approveGrouping()">Approve &amp; Continue</button>
  </div>
</aside>

<div class="main">
  <div class="topbar">
    <span class="topbar-title">M365 Grouping Review</span>
    <span class="topbar-sub">— review CISA SCuBA control grouping before enrichment runs</span>
  </div>

  <div class="global-ai-bar">
    <div style="flex:1">
      <div class="global-ai-input-wrap">
        <textarea class="global-ai-input" id="global-ai-input" rows="1"
          placeholder="Board-wide instruction — e.g. &quot;merge all Entra ID MFA controls into one group&quot;"></textarea>
        <button class="btn-global-ai" id="btn-global-ai" onclick="regroupGlobal()">Re-group All</button>
      </div>
      <div class="global-ai-hint">This instruction applies to ALL groups on the board with full visibility.</div>
    </div>
  </div>

  <div class="inst-bar">
    <strong>Drag</strong> control chips between groups &nbsp;·&nbsp;
    <strong>Click group name</strong> to rename &nbsp;·&nbsp;
    <strong>Risk Rating</strong> dropdown on each card for analyst override &nbsp;·&nbsp;
    <strong>Per-group AI box</strong> for narrow fixes, <strong>global box above</strong> for board-wide instructions
  </div>

  <div class="content" id="content">
    <div id="unassigned-bar" style="display:none" class="unassigned-bar">
      <h4>⚠ Unassigned — drag into a group</h4>
      <div class="unassigned-pool" id="unassigned-pool"
           ondragover="onDragOver(event,'__unassigned__')"
           ondrop="onDrop(event,'__unassigned__')"
           ondragleave="onDragLeave(event)"></div>
    </div>
    <div id="sections-container"></div>
  </div>
</div>

<div class="statusbar"><span id="status-msg" class="status-info">Review the AI's proposed grouping below.</span></div>

<script>
const PROPOSAL       = {groups_json};
const ALL_CHECKS     = {all_checks_json};
const RUN_ID         = "{run_id}";
const PORT           = {port};
const SECTION_ORDER  = {section_order_json};

const RESOURCES_BY_CHECK = {{}};
PROPOSAL.forEach(g => {{
  (g.affected_resources || []).forEach(r => {{
    if (!RESOURCES_BY_CHECK[r.check_id]) RESOURCES_BY_CHECK[r.check_id] = [];
    RESOURCES_BY_CHECK[r.check_id].push(r);
  }});
}});

function resourcesForCheckIds(checkIds) {{
  const out = []; const seen = new Set();
  checkIds.forEach(cid => {{
    (RESOURCES_BY_CHECK[cid] || []).forEach(r => {{
      const key = r.resource + "|" + r.check_id;
      if (!seen.has(key)) {{ seen.add(key); out.push(r); }}
    }});
  }});
  return out;
}}

let groups = []; let unassigned = []; let dragCid = null, dragFrom = null;

function init() {{
  groups = PROPOSAL.map((g, i) => ({{
    id: `g${{i}}`,
    group_name: g.group_name, rationale: g.rationale || "",
    check_ids: [...g.check_ids], is_merged: g.check_ids.length > 1,
    affected_resources: g.affected_resources || [],
    resources_open: false,
    output_section: g.output_section || "Other",
    ref_label: g.ref_label || "",
    risk_rating: g.risk_rating || "",   // analyst-editable override
  }}));
  unassigned = [];
  render();
}}

// ── Section-grouped render ──────────────────────────────────────────────
function render() {{
  const container = document.getElementById("sections-container");
  container.innerHTML = "";

  // Group by output_section preserving SECTION_ORDER
  const bySection = {{}};
  SECTION_ORDER.forEach(s => bySection[s] = []);
  groups.forEach(g => {{
    const s = g.output_section || "Other";
    if (!bySection[s]) bySection[s] = [];
    bySection[s].push(g);
  }});

  // Collect sections with content (in order, then any extras)
  const orderedSections = [...SECTION_ORDER, "Other"].filter(
    s => bySection[s] && bySection[s].length > 0
  );

  orderedSections.forEach(section => {{
    const sectionGroups = bySection[section];
    if (!sectionGroups || sectionGroups.length === 0) return;

    const block = document.createElement("div");
    block.className = "section-block";
    block.dataset.section = section;

    // Section header
    const header = document.createElement("div");
    header.className = "section-header";
    header.innerHTML = `
      <span class="section-chevron" id="chev-${{esc(section)}}">▾</span>
      <span class="section-label">${{esc(section)}}</span>
      <span class="section-badge">${{sectionGroups.length}} group${{sectionGroups.length !== 1 ? "s" : ""}}</span>
    `;
    header.onclick = () => toggleSection(section);
    block.appendChild(header);

    // Grid of cards
    const grid = document.createElement("div");
    grid.className = "section-body";
    grid.id = `section-grid-${{esc(section)}}`;
    sectionGroups.forEach(g => grid.appendChild(buildCard(g)));
    block.appendChild(grid);

    container.appendChild(block);
  }});

  // Unassigned pool
  const pool = document.getElementById("unassigned-pool");
  const wrap = document.getElementById("unassigned-bar");
  pool.innerHTML = "";
  if (unassigned.length) {{
    wrap.style.display = "block";
    unassigned.forEach(cid => pool.appendChild(buildChip(cid, "__unassigned__")));
  }} else {{
    wrap.style.display = "none";
  }}

  updateStats();
}}

function toggleSection(section) {{
  const grid = document.getElementById(`section-grid-${{esc(section)}}`);
  const chev = document.getElementById(`chev-${{esc(section)}}`);
  if (!grid) return;
  const collapsed = grid.classList.toggle("collapsed");
  if (chev) chev.classList.toggle("collapsed", collapsed);
}}

function buildCard(group) {{
  const merged = group.check_ids.length > 1;
  const sev    = groupSev(group.check_ids);
  const inst   = groupInst(group.check_ids);
  const accts  = groupAccts(group.check_ids);

  const card = document.createElement("div");
  card.className = `group-card ${{merged ? "merged" : "standalone"}}`;
  card.dataset.groupId = group.id;
  card.ondragover  = e => onDragOver(e, group.id);
  card.ondrop      = e => onDrop(e, group.id);
  card.ondragleave = e => onDragLeave(e);

  const rationaleClass = group.rationale && group.rationale.trim() ? "" : "empty";
  const resourcesHtml = (group.affected_resources || []).map(r => `
    <div class="resource-row">
      <span class="res-arn" title="${{esc(r.resource_name || r.resource)}}">${{esc(r.resource_name || r.resource || "Unknown")}}</span>
      <span class="res-meta">${{esc(r.resource_type || "")}}</span>
      <span class="res-meta">${{esc(r.account_name || "")}}</span>
    </div>`).join("");

  // Risk rating dropdown — pre-select analyst override or show blank (computed after enrichment)
  const rr = group.risk_rating || "";
  const riskOptions = ["", "High", "Medium", "Low"].map(v =>
    `<option value="${{v}}" ${{rr === v ? "selected" : ""}}>${{v || "— compute from matrix —"}}</option>`
  ).join("");
  const riskClass = rr ? `risk-${{rr}}` : "";

  card.innerHTML = `
    <div class="gc-header">
      <div class="gc-header-left">
        ${{group.ref_label ? `<div class="gc-ref">${{esc(group.ref_label)}}</div>` : ""}}
        <input class="gc-name-input" type="text" value="${{esc(group.group_name)}}"
          onchange="renameGroup('${{group.id}}', this.value)" />
        <div class="gc-badges">
          <span class="badge ${{merged ? "badge-merged" : "badge-standalone"}}">${{merged ? "Merged" : "Standalone"}}</span>
          <span class="badge badge-${{sev}}">${{cap(sev)}}</span>
          <span class="badge badge-count">${{inst}} instance${{inst !== 1 ? "s" : ""}}</span>
          ${{accts.length ? `<span class="badge badge-accts">${{accts.length}} tenant${{accts.length !== 1 ? "s" : ""}}</span>` : ""}}
        </div>
      </div>
      <div class="gc-header-actions">
        <button class="btn-xs btn-xs-danger" onclick="deleteGroup('${{group.id}}')" title="Remove group">✕</button>
      </div>
    </div>

    <div class="gc-risk-row">
      <span class="gc-risk-label">Risk Rating</span>
      <select class="gc-risk-select ${{riskClass}}" id="risk-${{group.id}}"
        onchange="updateRiskRating('${{group.id}}', this.value, this)">
        ${{riskOptions}}
      </select>
      <span class="gc-risk-hint">Override — leave blank to compute from risk matrix after enrichment</span>
    </div>

    <textarea class="gc-rationale ${{rationaleClass}}" id="gc-rat-${{group.id}}"
      onchange="updateRationale('${{group.id}}', this.value)"
      style="width:calc(100% - 28px);border:none;resize:none;font-family:var(--fb);overflow:hidden;display:block;margin:8px 14px 0"
    >${{group.rationale || ""}}</textarea>

    <div class="gc-chips" id="chips-${{group.id}}"></div>

    ${{(group.affected_resources || []).length ? `
    <div class="gc-resources-toggle" onclick="toggleResources('${{group.id}}')">
      <span>▸</span> ${{(group.affected_resources || []).length}} control detail(s)
    </div>
    <div class="gc-resources">${{resourcesHtml}}</div>` : ""}}

    <div class="gc-ai-box">
      <div class="gc-ai-label">AI instruction for this group only</div>
      <textarea class="gc-ai-input" id="gai-${{group.id}}" rows="1"
        placeholder="e.g. split this — legacy auth is different from MFA enforcement"></textarea>
      <div class="gc-ai-actions">
        <button class="btn-ai-regen" id="gai-btn-${{group.id}}" onclick="regroupOne('${{group.id}}')">Apply to This Group</button>
        <span class="ai-regen-status" id="gai-status-${{group.id}}"></span>
      </div>
    </div>
  `;

  // Always append live DOM elements — never outerHTML (destroys drag event listeners)
  const chipsContainer = card.querySelector(`#chips-${{group.id}}`);
  if (chipsContainer) {{
    group.check_ids.forEach(cid => chipsContainer.appendChild(buildChip(cid, group.id)));
  }}

  const ta = card.querySelector(".gc-rationale");
  if (ta) {{ requestAnimationFrame(() => autoGrow(ta)); ta.addEventListener("input", () => autoGrow(ta)); }}

  if (group.resources_open) {{
    const panel = card.querySelector(".gc-resources");
    const chev  = card.querySelector(".gc-resources-toggle span");
    if (panel) panel.classList.add("open");
    if (chev) chev.textContent = "▾";
  }}
  return card;
}}

function autoGrow(ta) {{ ta.style.height = "0px"; ta.style.height = ta.scrollHeight + "px"; }}

function toggleResources(gid) {{
  const g = groups.find(x => x.id === gid); if (g) g.resources_open = !g.resources_open;
  const card = document.querySelector(`[data-group-id="${{gid}}"]`); if (!card) return;
  const panel = card.querySelector(".gc-resources");
  const chev  = card.querySelector(".gc-resources-toggle span");
  if (panel) panel.classList.toggle("open");
  if (chev) chev.textContent = panel && panel.classList.contains("open") ? "▾" : "▸";
}}

function buildChip(cid, groupId) {{
  const m   = ALL_CHECKS[cid] || {{}};
  const sev = (m.severity || "medium").toLowerCase();
  const chip = document.createElement("div");
  chip.className = "check-chip"; chip.draggable = true;
  chip.dataset.checkId = cid; chip.dataset.groupId = groupId;
  chip.innerHTML = `
    <span class="chip-sev badge-${{sev}}">${{(sev[0] || "?").toUpperCase()}}</span>
    <span class="chip-body">
      <span class="chip-id">${{esc(cid)}}</span>
      <span class="chip-title">${{esc(m.check_title || "")}}</span>
    </span>
  `;
  chip.ondragstart = e => {{
    dragCid = cid; dragFrom = groupId;
    e.currentTarget.classList.add("dragging");
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", cid);  // required — browser cancels drag without this
  }};
  chip.ondragend = e => e.currentTarget.classList.remove("dragging");
  return chip;
}}

function onDragOver(e, gid) {{
  e.preventDefault();
  const el = gid === "__unassigned__"
    ? document.getElementById("unassigned-pool")
    : document.querySelector(`[data-group-id="${{gid}}"]`);
  if (el) el.classList.add("drag-over");
}}
function onDragLeave(e) {{ const el = e.currentTarget; if (el) el.classList.remove("drag-over"); }}
function onDrop(e, toGid) {{
  e.preventDefault(); e.stopPropagation();
  document.querySelectorAll(".drag-over").forEach(el => el.classList.remove("drag-over"));
  let cid = dragCid;
  if (!cid) {{ try {{ cid = e.dataTransfer.getData("text/plain"); }} catch(err) {{ cid = null; }} }}
  if (!cid || dragFrom === toGid) {{ dragCid = null; dragFrom = null; return; }}

  if (dragFrom !== "__unassigned__") {{
    const src = groups.find(x => x.id === dragFrom);
    if (src) {{ src.check_ids = src.check_ids.filter(c => c !== cid); src.affected_resources = resourcesForCheckIds(src.check_ids); }}
  }}
  if (toGid !== "__unassigned__") {{
    const dst = groups.find(x => x.id === toGid);
    if (dst && !dst.check_ids.includes(cid)) {{ dst.check_ids.push(cid); dst.affected_resources = resourcesForCheckIds(dst.check_ids); }}
  }} else {{ if (!unassigned.includes(cid)) unassigned.push(cid); }}
  if (dragFrom === "__unassigned__") unassigned = unassigned.filter(c => c !== cid);

  groups = groups.filter(g => g.check_ids.length > 0);
  dragCid = null; dragFrom = null;
  render();
  setStatus("Moved " + cid, "ok");
}}

function renameGroup(gid, v) {{ const g = groups.find(x => x.id === gid); if (g) g.group_name = v.trim() || g.group_name; }}
function updateRationale(gid, v) {{ const g = groups.find(x => x.id === gid); if (g) g.rationale = v; }}

function updateRiskRating(gid, v, selectEl) {{
  const g = groups.find(x => x.id === gid);
  if (g) g.risk_rating = v;
  // Update select colour class
  selectEl.className = "gc-risk-select" + (v ? " risk-" + v : "");
  setStatus(v ? `Risk rating for "${{g ? g.group_name : gid}}" set to ${{v}}` : `Risk rating cleared — will compute from matrix`, "ok");
}}

function deleteGroup(gid) {{
  const g = groups.find(x => x.id === gid); if (!g) return;
  unassigned.push(...g.check_ids);
  groups = groups.filter(x => x.id !== gid);
  render();
}}

function addNewGroup() {{
  const id = "gnew_" + Date.now();
  groups.push({{
    id, group_name: "New Group — rename me", rationale: "",
    check_ids: [], is_merged: false, affected_resources: [],
    resources_open: false, output_section: "Other", ref_label: "", risk_rating: "",
  }});
  render();
  setTimeout(() => {{
    const card = document.querySelector(`[data-group-id="${{id}}"]`);
    if (card) card.scrollIntoView({{ behavior: "smooth", block: "center" }});
    const input = document.querySelector(`[data-group-id="${{id}}"] .gc-name-input`);
    if (input) {{ input.focus(); input.select(); }}
  }}, 50);
  setStatus("New empty group created.", "info");
}}

function resetToProposal() {{
  if (confirm("Reset all groups back to the AI proposal? Your changes will be lost.")) init();
}}

// ── Per-group AI regroup ────────────────────────────────────────────────
function regroupOne(gid) {{
  const g = groups.find(x => x.id === gid); if (!g) return;
  const instruction = document.getElementById("gai-" + gid).value.trim();
  if (!instruction) {{ setStatus("Enter an instruction first.", "err"); return; }}
  const btn = document.getElementById("gai-btn-" + gid);
  const status = document.getElementById("gai-status-" + gid);
  btn.disabled = true; status.innerHTML = '<span class="spinner"></span> Asking AI...';
  fetch(`http://localhost:${{PORT}}/regroup-one`, {{
    method: "POST", headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{
      instruction,
      target_group: {{ group_name: g.group_name, check_ids: g.check_ids, rationale: g.rationale }},
      all_groups: groups.map(x => ({{ group_name: x.group_name, check_ids: x.check_ids, rationale: x.rationale }})),
    }}),
  }})
  .then(r => r.json())
  .then(data => {{
    if (data.ok) {{ applyNewGrouping(data.groups); status.textContent = "✓ Applied"; status.style.color = "#16a34a"; document.getElementById("gai-" + gid).value = ""; }}
    else {{ status.textContent = "✗ " + (data.error || "Failed"); status.style.color = "#dc2626"; }}
    btn.disabled = false;
  }})
  .catch(err => {{ status.textContent = "✗ Server error"; status.style.color = "#dc2626"; btn.disabled = false; }});
}}

// ── Global AI regroup ──────────────────────────────────────────────────
function regroupGlobal() {{
  const instruction = document.getElementById("global-ai-input").value.trim();
  if (!instruction) {{ setStatus("Enter a board-wide instruction first.", "err"); return; }}
  const btn = document.getElementById("btn-global-ai");
  btn.disabled = true; setStatus("AI is re-grouping the entire board...", "info");
  fetch(`http://localhost:${{PORT}}/regroup-global`, {{
    method: "POST", headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{
      instruction,
      all_groups: groups.map(g => ({{ group_name: g.group_name, check_ids: g.check_ids, rationale: g.rationale }})),
      unassigned,
    }}),
  }})
  .then(r => r.json())
  .then(data => {{
    if (data.ok) {{ applyNewGrouping(data.groups); setStatus("✓ Board re-grouped.", "ok"); document.getElementById("global-ai-input").value = ""; }}
    else {{ setStatus("✗ " + (data.error || "Failed"), "err"); }}
    btn.disabled = false;
  }})
  .catch(err => {{ setStatus("✗ Server error: " + err, "err"); btn.disabled = false; }});
}}

function applyNewGrouping(newGroupsFromServer) {{
  // Snapshot current groups before overwriting — used to recover output_section
  // and resource context after the server response (which strips both fields).
  const prevGroups = groups.slice();
  const prevRiskByCheckId = {{}};
  prevGroups.forEach(g => g.check_ids.forEach(cid => {{ if (g.risk_rating) prevRiskByCheckId[cid] = g.risk_rating; }}));

  groups = newGroupsFromServer.map((g, i) => {{
    const resources = []; const seen = new Set();
    g.check_ids.forEach(cid => {{
      const oldGroup = prevGroups.find(og => og.check_ids.includes(cid));
      if (oldGroup) {{
        (oldGroup.affected_resources || []).forEach(r => {{
          const key = r.resource + "|" + r.check_id;
          if (r.check_id === cid && !seen.has(key)) {{ seen.add(key); resources.push(r); }}
        }});
      }}
    }});
    // Carry forward risk override if all chips in the new group had the same override
    const risks = [...new Set(g.check_ids.map(cid => prevRiskByCheckId[cid] || "").filter(Boolean))];
    const inheritedRisk = risks.length === 1 ? risks[0] : "";
    // Derive output_section from the first chip's original group — the server
    // response never includes output_section, so g.output_section is always
    // undefined here. Look it up from the pre-regroup group state instead.
    const firstCid = g.check_ids[0];
    const origGroup = prevGroups.find(og => og.check_ids.includes(firstCid));
    const derivedSection = origGroup ? origGroup.output_section : (g.output_section || "Other");
    return {{
      id: "g" + i + "_" + Date.now(),
      group_name: g.group_name, rationale: g.rationale || "",
      check_ids: g.check_ids, is_merged: g.check_ids.length > 1,
      affected_resources: resources, resources_open: false,
      output_section: derivedSection,
      ref_label: g.ref_label || "",
      risk_rating: inheritedRisk,
    }};
  }});
  unassigned = unassigned.filter(cid => !groups.some(g => g.check_ids.includes(cid)));
  render();
}}

// ── Stats + approve ────────────────────────────────────────────────────
function updateStats() {{
  const merged = groups.filter(g => g.check_ids.length > 1).length;
  const solo   = groups.filter(g => g.check_ids.length === 1).length;
  setText("s-current", groups.length);
  setText("s-merged", merged);
  setText("s-standalone", solo);
  setText("s-unassigned", unassigned.length);
  const btn = document.getElementById("approve-btn");
  if (btn) btn.disabled = unassigned.length > 0 || groups.length === 0;
}}

function approveGrouping() {{
  if (unassigned.length > 0) {{ setStatus(`⚠ ${{unassigned.length}} control(s) unassigned.`, "err"); return; }}
  if (groups.some(g => g.check_ids.length === 0)) {{ setStatus("⚠ Empty groups exist — delete them.", "err"); return; }}
  if (groups.some(g => !g.group_name.trim())) {{ setStatus("⚠ Unnamed groups exist.", "err"); return; }}

  const payload = {{
    run_id: RUN_ID,
    approved_at: new Date().toISOString(),
    groups: groups.map(g => ({{
      group_name:   g.group_name.trim(),
      check_ids:    g.check_ids,
      rationale:    g.rationale || "",
      analyst_note: "",
      risk_rating:  g.risk_rating || "",  // included in approval payload
    }})),
  }};

  setStatus("Sending approval to pipeline...", "info");
  document.getElementById("approve-btn").disabled = true;

  fetch(`http://localhost:${{PORT}}/approve`, {{
    method: "POST", headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify(payload),
  }})
  .then(r => r.json())
  .then(data => {{
    if (data.ok) {{
      setStatus("✓ Approved — pipeline continuing to enrichment and Excel render...", "ok");
      document.getElementById("approve-btn").textContent = "✓ Approved";
    }} else {{
      setStatus("✗ Error: " + data.error, "err");
      document.getElementById("approve-btn").disabled = false;
    }}
  }})
  .catch(err => {{ setStatus("✗ Could not reach pipeline: " + err, "err"); document.getElementById("approve-btn").disabled = false; }});
}}

// ── Helpers ────────────────────────────────────────────────────────────
function esc(s) {{ return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }}
function cap(s) {{ return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }}
function setText(id, v) {{ const el = document.getElementById(id); if (el) el.textContent = v; }}
function setStatus(msg, type) {{
  const el = document.getElementById("status-msg"); if (!el) return;
  el.textContent = msg;
  el.className = type === "ok" ? "status-ok" : type === "err" ? "status-err" : "status-info";
}}
function groupSev(ids) {{
  const o = {{ high: 0, medium: 1, low: 2 }};
  return ids.reduce((b, cid) => {{ const s = (ALL_CHECKS[cid]?.severity || "medium").toLowerCase(); return (o[s] ?? 5) < (o[b] ?? 5) ? s : b; }}, "medium");
}}
function groupInst(ids) {{ return ids.reduce((s, cid) => s + (ALL_CHECKS[cid]?.instance_count || 0), 0); }}
function groupAccts(ids) {{ const seen = new Set(); ids.forEach(cid => (ALL_CHECKS[cid]?.accounts || []).forEach(a => seen.add(a))); return [...seen]; }}

init();
</script>
</body>
</html>"""


# ── HTTP server ───────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):
    html_content:   str = ""
    approved_path:  Path = None
    approval_event: threading.Event = None
    llm_cfg:        dict = {}

    def log_message(self, fmt, *args):
        pass

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
                mime = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                        ".svg": "image/svg+xml", ".gif": "image/gif"}.get(ext, "application/octet-stream")
                body = file_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", len(body))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404); self.end_headers()
        else:
            self.send_response(404); self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)
        if self.path == "/regroup-global":
            self._handle_regroup_global(body)
        elif self.path == "/regroup-one":
            self._handle_regroup_one(body)
        elif self.path == "/approve":
            self._handle_approve(body)
        else:
            self.send_response(404); self.end_headers()

    def _json_response(self, status: int, data: dict):
        resp = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", len(resp))
        self.end_headers()
        self.wfile.write(resp)

    def _handle_regroup_global(self, body: bytes):
        from sg_grouping import _scaled_llm_cfg
        from sg_enrich import _call_llm
        try:
            req          = json.loads(body)
            instruction  = req.get("instruction", "")
            all_groups   = req.get("all_groups", [])
            unassigned   = req.get("unassigned", [])
            expected_ids = {cid for g in all_groups for cid in g["check_ids"]} | set(unassigned)
            n_items      = len(expected_ids) or 1
            scaled_cfg   = _scaled_llm_cfg(_Handler.llm_cfg, n_items, mode="regroup")
            prompt       = _build_global_regroup_prompt(instruction, all_groups, unassigned)
            raw          = _call_llm(prompt, scaled_cfg)
            parsed       = _extract_json_array(raw)
            errors       = _validate_regroup_response(parsed, expected_ids)
            if errors:
                correction = (prompt + "\n\n=== CORRECTION REQUIRED ===\n"
                    + "\n".join(f"- {e}" for e in errors)
                    + f"\n\nAll check_ids: {json.dumps(sorted(expected_ids))}"
                    + f"\n\nPrevious (first 400): {raw[:400]}"
                    + "\n\nRespond with ONLY a valid JSON array.")
                raw = _call_llm(correction, scaled_cfg)
                parsed = _extract_json_array(raw)
                errors = _validate_regroup_response(parsed, expected_ids)
            if errors:
                self._json_response(400, {"ok": False, "error": "; ".join(errors)}); return
            self._json_response(200, {"ok": True, "groups": parsed})
        except Exception as e:
            self._json_response(500, {"ok": False, "error": str(e)})

    def _handle_regroup_one(self, body: bytes):
        from sg_grouping import _scaled_llm_cfg
        from sg_enrich import _call_llm
        try:
            req          = json.loads(body)
            instruction  = req.get("instruction", "")
            target_group = req.get("target_group", {})
            all_groups   = req.get("all_groups", [])
            expected_ids = {cid for g in all_groups for cid in g["check_ids"]}
            n_items      = len(expected_ids) or 1
            scaled_cfg   = _scaled_llm_cfg(_Handler.llm_cfg, n_items, mode="regroup")
            prompt       = _build_one_group_regroup_prompt(instruction, target_group, all_groups)
            raw          = _call_llm(prompt, scaled_cfg)
            parsed       = _extract_json_array(raw)
            errors       = _validate_regroup_response(parsed, expected_ids)
            if errors:
                correction = (prompt + "\n\n=== CORRECTION REQUIRED ===\n"
                    + "\n".join(f"- {e}" for e in errors)
                    + f"\n\nAll check_ids: {json.dumps(sorted(expected_ids))}"
                    + f"\n\nPrevious (first 400): {raw[:400]}"
                    + "\n\nRespond with ONLY a valid JSON array.")
                raw = _call_llm(correction, scaled_cfg)
                parsed = _extract_json_array(raw)
                errors = _validate_regroup_response(parsed, expected_ids)
            if errors:
                self._json_response(400, {"ok": False, "error": "; ".join(errors)}); return
            self._json_response(200, {"ok": True, "groups": parsed})
        except Exception as e:
            self._json_response(500, {"ok": False, "error": str(e)})

    def _handle_approve(self, body: bytes):
        try:
            data = json.loads(body)
            if not data.get("groups"):
                raise ValueError("No groups in payload")
            _Handler.approved_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            self._json_response(200, {"ok": True})
            _Handler.approval_event.set()
        except Exception as e:
            self._json_response(400, {"ok": False, "error": str(e)})


# ── Apply approved grouping back to GroupingResult ────────────────────

def apply_approved_grouping(
    approved: ApprovedGrouping,
    grouping_result: GroupingResult,
) -> GroupingResult:
    from sg_grouping import (
        _best_representative, _highest_severity, _highest_likelihood,
    )

    original_by_check_id: dict[str, OutputGroup] = {}
    for grp in grouping_result.grouped_groups:
        for src in grp.source_groups:
            original_by_check_id[src.check_id] = src

    new_groups: list[GroupedOutputGroup] = []
    warnings:   list[GroupingWarning]    = []

    for ap in approved.groups:
        source_groups = []
        for cid in ap.check_ids:
            if cid in original_by_check_id:
                source_groups.append(original_by_check_id[cid])
            else:
                warnings.append(GroupingWarning(
                    code="UNKNOWN_CHECK_ID",
                    message=f"Approved group '{ap.group_name}' references unknown control_id '{cid}'. Skipped.",
                ))
        if not source_groups:
            continue

        is_merged  = len(source_groups) > 1
        rep        = _best_representative(source_groups)
        severity   = _highest_severity(source_groups)
        likelihood = _highest_likelihood(source_groups)

        all_instance_ids: list[str] = []
        all_tenant_ids:   list[str] = []
        total = 0
        for sg in source_groups:
            all_instance_ids.extend(sg.instance_ids)
            total += sg.instance_count
            for tid in sg.affected_tenant_ids:
                if tid not in all_tenant_ids:
                    all_tenant_ids.append(tid)

        rep.instance_count    = total
        rep.likelihood_rating = likelihood
        rep.add_audit(
            stage="sg_reviewer", field="semantic_group",
            old_value=", ".join(ap.check_ids), new_value=ap.group_name,
            reason=(f"Analyst-approved. {ap.analyst_note}" if ap.analyst_note else "Analyst-approved grouping."),
            actor="human",
        )

        # Apply analyst risk rating override if set
        analyst_risk = ap.risk_rating.strip() if ap.risk_rating else ""
        if analyst_risk in ("High", "Medium", "Low"):
            rep.risk_rating = analyst_risk
            rep.add_audit(
                stage="sg_reviewer", field="risk_rating",
                old_value=rep.risk_rating, new_value=analyst_risk,
                reason="Analyst override from review UI",
                actor="human",
            )

        new_groups.append(GroupedOutputGroup(
            group_name=ap.group_name,
            group_rationale=ap.rationale or ap.analyst_note,
            output_section=source_groups[0].output_section,
            is_merged=is_merged,
            check_ids=ap.check_ids,
            representative=rep,
            instance_ids=all_instance_ids,
            instance_count=total,
            affected_tenant_ids=all_tenant_ids,
            severity=severity,
            likelihood_rating=likelihood,
            source_groups=source_groups,
            risk_rating=analyst_risk if analyst_risk else None,
        ))

    from sg_grouping import GroupingResult as GR
    return GR(
        run_id=grouping_result.run_id,
        grouped_groups=new_groups,
        all_findings=grouping_result.all_findings,
        warnings=warnings,
        config=grouping_result.config,
        original_count=grouping_result.original_count,
        merged_count=len(new_groups),
        merges_applied=sum(1 for g in new_groups if g.is_merged),
        chunks_used=grouping_result.chunks_used,
        consolidation_applied=grouping_result.consolidation_applied,
    )


# ── Public entry point ────────────────────────────────────────────────

def start_review_server(
    grouping_result: GroupingResult,
    output_dir: Path,
    config: dict[str, Any],
    client_name: str = "",
    port: int = 8743,  # 8743 to avoid collision with Prowler pipeline on 8742
    open_browser: bool = True,
    timeout_seconds: int = 7200,
) -> ApprovedGrouping:
    """
    Start the M365 grouping review server and wait for analyst approval.
    Returns ApprovedGrouping once the analyst clicks Approve.
    Port 8743 (not 8742) avoids collision if both pipelines run simultaneously.
    """
    approved_path = output_dir / "m365_grouping_approved.json"
    if approved_path.exists():
        approved_path.unlink()

    html = generate_review_html(grouping_result, client_name, port)
    approval_event = threading.Event()
    _Handler.html_content   = html
    _Handler.approved_path  = approved_path
    _Handler.approval_event = approval_event
    _Handler.llm_cfg        = config.get("llm", {})

    server = HTTPServer(("localhost", port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://localhost:{port}/review"
    print(f"\n  {'─'*60}", flush=True)
    print(f"  🌐 M365 Grouping review: {url}", flush=True)
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
            return load_approved_grouping(approved_path)
        mins, secs = divmod(elapsed, 60)
        print(f"\r  {spinner[elapsed % len(spinner)]} Waiting... {mins:02d}:{secs:02d}  ", end="", flush=True)
        elapsed += 1

    server.shutdown()
    raise TimeoutError(f"No approval after {timeout_seconds // 60} minutes.")