"""
stage2_5_reviewer.py — HTML grouping review interface

Hosts a local HTTP server, opens the browser automatically,
and receives the analyst's approved grouping via POST — no manual
file handling required.

Workflow:
    1. generate_review_html() → builds the HTML string
    2. start_review_server()  → starts localhost server, opens browser
    3. Server waits for POST /approve with grouping JSON
    4. Writes grouping_approved.json to the run output folder
    5. Returns the approved grouping to the pipeline
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from stage2_5_grouping import (
    GroupedOutputGroup,
    GroupingResult,
    OutputGroup,
    _best_representative,
    _highest_likelihood,
    _highest_severity,
)


# ── Approved grouping schema ──────────────────────────────────────────

@dataclass
class ApprovedGroup:
    group_name:   str
    check_ids:    list[str]
    rationale:    str = ""
    analyst_note: str = ""


@dataclass
class ApprovedGrouping:
    run_id:      str
    approved_at: str
    groups:      list[ApprovedGroup] = field(default_factory=list)


def load_approved_grouping(path: Path) -> ApprovedGrouping:
    """Load and validate an approved grouping JSON file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    groups = []
    for g in data.get("groups", []):
        if not g.get("group_name") or not g.get("check_ids"):
            raise ValueError(
                f"Invalid group in approved file: missing group_name or "
                f"check_ids. Got: {g}"
            )
        groups.append(ApprovedGroup(
            group_name   = g["group_name"],
            check_ids    = g["check_ids"],
            rationale    = g.get("rationale", ""),
            analyst_note = g.get("analyst_note", ""),
        ))
    if not groups:
        raise ValueError("Approved grouping has no groups.")
    return ApprovedGrouping(
        run_id      = data.get("run_id", ""),
        approved_at = data.get("approved_at", ""),
        groups      = groups,
    )


# ── Data builder ──────────────────────────────────────────────────────

def _build_group_data(grouping_result: GroupingResult) -> list[dict]:
    result = []
    for g in grouping_result.grouped_groups:
        checks = []
        for src in g.source_groups:
            checks.append({
                "check_id":      src.check_id,
                "check_title":   src.representative.raw_check_title or src.check_id,
                "severity":      src.representative.raw_severity or "unknown",
                "instance_count": src.instance_count,
                "accounts":      src.affected_account_names,
                "likelihood":    src.likelihood_rating or "Unknown",
                "service":       src.representative.raw_service_name or "",
                "categories":    src.representative.categories_list or [],
            })
        result.append({
            "id":            g.group_name.lower().replace(" ", "_")
                             .replace("/", "_")[:40],
            "group_name":    g.group_name,
            "rationale":     g.group_rationale,
            "is_merged":     g.is_merged,
            "check_ids":     g.check_ids,
            "checks":        checks,
            "instance_count": g.instance_count,
            "accounts":      g.affected_account_names,
            "severity":      g.severity or "unknown",
            "likelihood":    g.likelihood_rating or "Unknown",
        })
    return result


# ── HTML generator ────────────────────────────────────────────────────

def generate_review_html(
    grouping_result: GroupingResult,
    output_path: Path,
    client_name: str = "",
    port: int = 8742,
) -> str:
    """
    Build and return the HTML string for the review interface.
    Does not write to disk — the server serves it directly.
    """
    groups_data  = _build_group_data(grouping_result)
    groups_json  = json.dumps(groups_data, indent=2)
    run_id       = grouping_result.run_id
    client_label = client_name or "Security Assessment"

    all_checks: dict[str, dict] = {}
    for g in groups_data:
        for c in g["checks"]:
            all_checks[c["check_id"]] = c
    all_checks_json = json.dumps(all_checks)

    total_checks    = sum(len(g["check_ids"]) for g in groups_data)
    total_instances = sum(g["instance_count"] for g in groups_data)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Automated Cloud Security Reporter</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=DM+Sans:wght@400;500;600&display=swap');
:root {{
  --bg:        #f4f6f9;
  --sidebar:   #1b2332;
  --sidebar-2: #232e42;
  --card:      #ffffff;
  --border:    #dde2ea;
  --accent:    #2563eb;
  --accent-bg: #eff4ff;
  --text:      #1a202c;
  --text-2:    #4a5568;
  --muted:     #8896a5;
  --success:   #16a34a;
  --danger:    #dc2626;
  --warning:   #d97706;
  --critical-bg: #faf5ff; --critical-fg: #7c3aed;
  --high-bg:   #fff1f2;   --high-fg:    #be123c;
  --medium-bg: #fffbeb;   --medium-fg:  #b45309;
  --low-bg:    #f0fdf4;   --low-fg:     #15803d;
  --info-bg:   #f8fafc;   --info-fg:    #64748b;
  --font: "DM Sans", -apple-system, BlinkMacSystemFont, sans-serif;
  --font-heading: "Plus Jakarta Sans", "DM Sans", sans-serif;
  --mono: "JetBrains Mono", "Fira Code", "Menlo", monospace;
}}
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
html, body {{ height: 100%; overflow: hidden; }}
body {{ font-family: var(--font); background: var(--bg); color: var(--text);
        display: flex; font-size: 13px; }}

/* ── Sidebar ── */
.sidebar {{
  width: 240px; min-width: 240px;
  background: var(--sidebar);
  display: flex; flex-direction: column;
  height: 100vh; overflow-y: auto;
}}
.sidebar-logo {{
  padding: 20px 18px 14px;
  border-bottom: 1px solid rgba(255,255,255,0.06);
}}
.logo-img-wrap {{
  margin-bottom: 12px;
}}
.logo-img {{
  height: 36px; width: auto; max-width: 160px;
  object-fit: contain; display: block;
}}
.logo-placeholder {{
  height: 36px; width: 120px;
  background: rgba(255,255,255,0.06);
  border: 1px dashed rgba(255,255,255,0.15);
  border-radius: 5px;
  display: flex; align-items: center; justify-content: center;
  font-size: 10px; color: #4a6080; letter-spacing: 0.04em;
  font-family: var(--font);
}}
.sidebar-logo .product {{ font-size: 11px; font-weight: 700; letter-spacing: 0.08em;
  text-transform: uppercase; color: #6b8cba; margin-bottom: 4px; font-family: var(--font-heading); }}
.sidebar-logo .client  {{ font-size: 14px; font-weight: 700; color: #e8edf5; line-height: 1.3; font-family: var(--font-heading); }}
.sidebar-logo .runid   {{ font-size: 10px; color: #4a6080; margin-top: 4px;
  font-family: var(--mono); word-break: break-all; }}

.sidebar-section {{ padding: 14px 18px 8px; }}
.sidebar-section-title {{ font-size: 10px; font-weight: 700; letter-spacing: 0.1em;
  text-transform: uppercase; color: #4a6080; margin-bottom: 10px; font-family: var(--font-heading); }}

.stat-row {{ display: flex; justify-content: space-between; align-items: center;
  padding: 5px 0; border-bottom: 1px solid rgba(255,255,255,0.04); }}
.stat-row:last-child {{ border-bottom: none; }}
.stat-label {{ font-size: 12px; color: #8896a5; }}
.stat-value {{ font-size: 13px; font-weight: 600; color: #c8d6e8; font-family: var(--mono); }}

.sidebar-actions {{ padding: 14px 18px; margin-top: auto;
  border-top: 1px solid rgba(255,255,255,0.06); display: flex; flex-direction: column; gap: 8px; }}
.btn-sidebar {{ width: 100%; padding: 8px 12px; border-radius: 5px; border: none;
  font-size: 12px; font-weight: 500; cursor: pointer; transition: all 0.15s;
  font-family: var(--font); text-align: left; display: flex; align-items: center; gap: 8px; }}
.btn-sidebar:hover {{ filter: brightness(1.1); }}
.btn-new      {{ background: rgba(37,99,235,0.15); color: #93b4f5; border: 1px solid rgba(37,99,235,0.3); }}
.btn-reset    {{ background: rgba(255,255,255,0.04); color: #8896a5; border: 1px solid rgba(255,255,255,0.08); }}
.btn-approve  {{ background: #16a34a; color: #fff; border: 1px solid #15803d;
  font-size: 13px; padding: 10px 12px; justify-content: center; font-weight: 600; }}
.btn-approve:disabled {{ background: #374151; color: #6b7280; border-color: #374151; cursor: not-allowed; }}
.btn-approve:not(:disabled):hover {{ background: #15803d; }}

/* ── Main area ── */
.main {{ flex: 1; display: flex; flex-direction: column; height: 100vh; overflow: hidden; }}

.topbar {{
  background: var(--card); border-bottom: 1px solid var(--border);
  padding: 12px 20px; display: flex; align-items: center; gap: 12px;
  flex-shrink: 0;
}}
.topbar-title {{ font-size: 14px; font-weight: 700; color: var(--text); font-family: var(--font-heading); }}
.topbar-sub   {{ font-size: 12px; color: var(--muted); margin-left: 4px; }}
.topbar-right {{ margin-left: auto; display: flex; align-items: center; gap: 10px; }}

.instruction-bar {{
  background: var(--accent-bg); border-bottom: 1px solid #bfdbfe;
  padding: 8px 20px; font-size: 12px; color: #1e40af;
  flex-shrink: 0; line-height: 1.5;
}}

.content {{ flex: 1; overflow-y: auto; padding: 16px 20px 80px; }}

/* ── Groups grid ── */
.groups-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
  gap: 12px;
}}

/* ── Group card ── */
.group-card {{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: visible;
  transition: box-shadow 0.15s, border-color 0.15s;
  display: flex; flex-direction: column;
}}
.group-card.drag-over {{
  border-color: var(--accent);
  box-shadow: 0 0 0 2px #bfdbfe;
}}
.group-card.merged    {{ border-top: 3px solid var(--accent); }}
.group-card.standalone{{ border-top: 3px solid var(--border); }}

.group-header {{
  padding: 10px 12px 8px;
  display: flex; align-items: flex-start; gap: 8px;
}}
.group-header-left {{ flex: 1; min-width: 0; }}
.group-name-wrap {{
  display: flex; align-items: center; gap: 6px; margin-bottom: 5px;
}}
.group-name-input {{
  font-size: 13px; font-weight: 700; color: var(--text); font-family: var(--font-heading);
  border: 1px solid transparent; border-radius: 4px;
  padding: 2px 5px; flex: 1; min-width: 0;
  background: transparent; font-family: var(--font);
  transition: border-color 0.12s, background 0.12s;
}}
.group-name-input:hover {{ border-color: var(--border); background: var(--bg); }}
.group-name-input:focus {{
  outline: none; border-color: var(--accent);
  background: white; box-shadow: 0 0 0 2px var(--accent-bg);
}}
.group-badges {{ display: flex; gap: 4px; flex-wrap: wrap; }}
.badge {{
  font-size: 10px; padding: 1px 6px; border-radius: 10px;
  font-weight: 600; white-space: nowrap; letter-spacing: 0.02em;
}}
.badge-merged     {{ background: #dbeafe; color: #1d4ed8; }}
.badge-standalone {{ background: var(--info-bg); color: var(--info-fg); }}
.badge-count      {{ background: #f0fdf4; color: #15803d; }}
.badge-accts      {{ background: #fef9c3; color: #92400e; }}
.badge-critical   {{ background: var(--critical-bg); color: var(--critical-fg); }}
.badge-high       {{ background: var(--high-bg);     color: var(--high-fg); }}
.badge-medium     {{ background: var(--medium-bg);   color: var(--medium-fg); }}
.badge-low        {{ background: var(--low-bg);      color: var(--low-fg); }}
.badge-informational {{ background: var(--info-bg);  color: var(--info-fg); }}
.badge-unknown    {{ background: var(--info-bg);     color: var(--info-fg); }}

.group-header-actions {{ display: flex; gap: 4px; flex-shrink: 0; padding-top: 2px; }}
.btn-xs {{
  padding: 3px 8px; border-radius: 4px; border: 1px solid var(--border);
  font-size: 11px; font-weight: 500; cursor: pointer; background: white;
  color: var(--text-2); font-family: var(--font); transition: all 0.12s;
}}
.btn-xs:hover {{ background: var(--bg); }}
.btn-xs-danger {{ border-color: #fecaca; color: var(--danger); }}
.btn-xs-danger:hover {{ background: #fff1f2; }}

/* ── Chips ── */
.checks-container {{
  padding: 6px 10px 8px;
  display: flex; flex-wrap: wrap; gap: 5px;
  min-height: 48px;
  border-top: 1px solid var(--border);
}}
.checks-container.drop-target {{
  border: 1px dashed #93c5fd; background: var(--accent-bg);
  border-radius: 4px; margin: 0 6px 6px;
}}

.check-chip {{
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 5px; padding: 4px 8px;
  font-size: 11px; cursor: grab; user-select: none;
  display: flex; align-items: center; gap: 5px;
  transition: all 0.12s; max-width: 100%;
}}
.check-chip:hover    {{ border-color: var(--accent); background: var(--accent-bg); }}
.check-chip:active   {{ cursor: grabbing; }}
.check-chip.dragging {{ opacity: 0.35; }}
.chip-sev  {{ flex-shrink: 0; width: 14px; height: 14px; border-radius: 2px;
  display: flex; align-items: center; justify-content: center;
  font-size: 9px; font-weight: 800; }}
.chip-sev-critical {{ background: var(--critical-bg); color: var(--critical-fg); }}
.chip-sev-high     {{ background: var(--high-bg);     color: var(--high-fg); }}
.chip-sev-medium   {{ background: var(--medium-bg);   color: var(--medium-fg); }}
.chip-sev-low      {{ background: var(--low-bg);      color: var(--low-fg); }}
.chip-sev-informational {{ background: var(--info-bg); color: var(--info-fg); }}
.chip-sev-unknown  {{ background: var(--info-bg);     color: var(--info-fg); }}
.chip-body  {{ display: flex; flex-direction: column; min-width: 0; }}
.chip-id    {{ font-family: var(--mono); font-size: 10px; font-weight: 600;
  color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  max-width: 220px; }}
.chip-title {{ font-size: 10px; color: var(--muted); white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis; max-width: 220px; }}
.chip-cnt   {{ font-size: 10px; color: var(--muted); flex-shrink: 0; margin-left: auto; }}

/* ── Rationale ── */
.rationale-row {{
  padding: 6px 10px; border-top: 1px solid var(--border);
}}
.rationale-input {{
  width: 100%; font-size: 11px; color: var(--text-2); resize: none;
  border: 1px solid transparent; border-radius: 4px; padding: 3px 5px;
  background: transparent; font-family: var(--font); min-height: 30px;
  transition: border-color 0.12s, background 0.12s;
}}
.rationale-input:hover  {{ border-color: var(--border); background: white; }}
.rationale-input:focus  {{ outline: none; border-color: var(--accent);
  background: white; box-shadow: 0 0 0 2px var(--accent-bg); }}

/* ── Unassigned ── */
.unassigned-bar {{
  background: #fffbeb; border: 1px solid #fde68a;
  border-radius: 6px; padding: 10px 14px; margin-bottom: 12px;
  position: sticky; top: 0; z-index: 40;
  box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}}
.unassigned-bar h4 {{
  font-size: 11px; font-weight: 700; letter-spacing: 0.06em;
  text-transform: uppercase; color: var(--warning); margin-bottom: 6px; font-family: var(--font-heading);
}}
.unassigned-pool {{
  display: flex; flex-wrap: wrap; gap: 5px; min-height: 32px;
  padding: 4px; border-radius: 4px;
}}
.unassigned-pool.drag-over {{
  background: #fef3c7; border: 1px dashed var(--warning);
}}

/* ── Status bar ── */
.statusbar {{
  position: fixed; bottom: 0; left: 240px; right: 0;
  background: white; border-top: 1px solid var(--border);
  padding: 8px 20px; display: flex; align-items: center; gap: 12px;
  z-index: 50;
}}
.status-ok  {{ font-size: 12px; color: var(--success); font-weight: 500; }}
.status-err {{ font-size: 12px; color: var(--danger); font-weight: 500; }}
.status-msg {{ font-size: 12px; color: var(--text-2); }}

/* ── Tooltip ── */
.tooltip {{
  position: fixed; background: #1e293b; color: #e2e8f0;
  font-size: 11px; padding: 6px 10px; border-radius: 5px;
  pointer-events: none; z-index: 1000; max-width: 280px;
  line-height: 1.4; display: none; box-shadow: 0 4px 12px rgba(0,0,0,0.2);
}}
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
    <div class="product">Automated Cloud Security Reporter</div>
    <div class="client">{client_label}</div>
    <div class="runid">Run: {run_id[:16]}...</div>
  </div>

  <div class="sidebar-section">
    <div class="sidebar-section-title">Summary</div>
    <div class="stat-row">
      <span class="stat-label">AI Proposed</span>
      <span class="stat-value" id="s-original">{len(groups_data)}</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Current Groups</span>
      <span class="stat-value" id="s-current">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Merged</span>
      <span class="stat-value" id="s-merged">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Standalone</span>
      <span class="stat-value" id="s-standalone">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Total Checks</span>
      <span class="stat-value">{total_checks}</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Total Instances</span>
      <span class="stat-value">{total_instances}</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Unassigned</span>
      <span class="stat-value" id="s-unassigned" style="color:#f59e0b">0</span>
    </div>
  </div>

  <div class="sidebar-actions">
    <button class="btn-sidebar btn-new"   onclick="addNewGroup()">＋ New Group</button>
    <button class="btn-sidebar btn-reset" onclick="resetToProposal()">↺ Reset to AI Proposal</button>
    <button class="btn-sidebar btn-approve" id="approve-btn" onclick="approveGrouping()">
      ✓ Approve &amp; Continue
    </button>
  </div>
</aside>

<!-- ── Main ── -->
<div class="main">
  <div class="topbar">
    <div>
      <span class="topbar-title">Grouping Review</span>
      <span class="topbar-sub">— drag checks between groups to reorganise</span>
    </div>
    <div class="topbar-right">
      <span style="font-size:12px;color:var(--muted)">
        <span id="t-groups">—</span> groups &nbsp;·&nbsp;
        <span id="t-checks">{total_checks}</span> checks
      </span>
    </div>
  </div>

  <div class="instruction-bar">
    <strong>Drag</strong> check chips between groups &nbsp;·&nbsp;
    <strong>Click group name</strong> to rename &nbsp;·&nbsp;
    <strong>Split</strong> to break a merged group &nbsp;·&nbsp;
    <strong>✕</strong> to delete a group (checks become unassigned) &nbsp;·&nbsp;
    <strong>Hover</strong> a chip for details &nbsp;·&nbsp;
    When ready, click <strong>Approve &amp; Continue</strong>
  </div>

  <div class="content" id="content">
    <div id="unassigned-bar" style="display:none" class="unassigned-bar">
      <h4>⚠ Unassigned — drag into a group before approving</h4>
      <div class="unassigned-pool" id="unassigned-pool"
           ondragover="onDragOver(event,'__unassigned__')"
           ondrop="onDrop(event,'__unassigned__')"
           ondragleave="onDragLeave(event)"></div>
    </div>
    <div class="groups-grid" id="groups-grid"></div>
  </div>
</div>

<!-- ── Status bar ── -->
<div class="statusbar">
  <div id="status-msg" class="status-msg">Ready for review</div>
</div>

<!-- ── Tooltip ── -->
<div class="tooltip" id="tooltip"></div>

<script>
const PROPOSAL     = {groups_json};
const ALL_CHECKS   = {all_checks_json};
const RUN_ID       = "{run_id}";
const SERVER_PORT  = {port};

let groups     = [];
let unassigned = [];
let dragCid    = null;
let dragFrom   = null;

// ── Init ──────────────────────────────────────────────────────────────
function init() {{
  groups = PROPOSAL.map((g,i) => ({{
    id:         g.id || `g${{i}}`,
    group_name: g.group_name,
    rationale:  g.rationale || "",
    check_ids:  [...g.check_ids],
    is_merged:  g.check_ids.length > 1,
  }}));
  unassigned = [];
  render();
}}

// ── Render ────────────────────────────────────────────────────────────
function render() {{
  const grid = document.getElementById("groups-grid");
  grid.innerHTML = "";
  groups.forEach(g => grid.appendChild(buildCard(g)));

  // Unassigned
  const pool = document.getElementById("unassigned-pool");
  const bar  = document.getElementById("unassigned-bar");
  pool.innerHTML = "";
  if (unassigned.length) {{
    bar.style.display = "block";
    unassigned.forEach(cid => pool.appendChild(buildChip(cid, "__unassigned__")));
  }} else {{
    bar.style.display = "none";
  }}

  updateStats();
}}

function buildCard(group) {{
  const merged = group.check_ids.length > 1;
  const sev    = groupSev(group.check_ids);
  const inst   = groupInst(group.check_ids);
  const accts  = groupAccts(group.check_ids);

  const card = document.createElement("div");
  card.className       = `group-card ${{merged ? "merged" : "standalone"}}`;
  card.dataset.groupId = group.id;
  card.ondragover      = e => onDragOver(e, group.id);
  card.ondrop          = e => onDrop(e, group.id);
  card.ondragleave     = e => onDragLeave(e);

  const chipsHtml = group.check_ids.map(cid => buildChip(cid, group.id).outerHTML).join("");

  card.innerHTML = `
    <div class="group-header">
      <div class="group-header-left">
        <div class="group-name-wrap">
          <input class="group-name-input" type="text"
            value="${{esc(group.group_name)}}"
            onchange="renameGroup('${{group.id}}',this.value)"
            title="Click to rename" />
        </div>
        <div class="group-badges">
          <span class="badge ${{merged?"badge-merged":"badge-standalone"}}">${{merged?"Merged":"Standalone"}}</span>
          <span class="badge badge-${{sev}}">${{cap(sev)}}</span>
          <span class="badge badge-count">${{inst}} instance${{inst!==1?"s":""}}</span>
          ${{accts.length?`<span class="badge badge-accts">${{accts.length}} account${{accts.length!==1?"s":""}}</span>`:""}}
        </div>
      </div>
      <div class="group-header-actions">
        ${{merged?`<button class="btn-xs" onclick="splitGroup('${{group.id}}')" title="Split back to individual checks">Split</button>`:""}}
        <button class="btn-xs btn-xs-danger" onclick="deleteGroup('${{group.id}}')" title="Remove group">✕</button>
      </div>
    </div>
    <div class="checks-container" id="cc-${{group.id}}">${{chipsHtml}}</div>
    <div class="rationale-row">
      <textarea class="rationale-input" rows="1"
        placeholder="Rationale / analyst note..."
        onchange="updateRationale('${{group.id}}',this.value)"
      >${{esc(group.rationale)}}</textarea>
    </div>
  `;
  return card;
}}

function buildChip(cid, groupId) {{
  const m   = ALL_CHECKS[cid] || {{}};
  const sev = (m.severity || "unknown").toLowerCase();
  const lbl = sev.charAt(0).toUpperCase();
  const cnt = m.instance_count || 0;

  const chip = document.createElement("div");
  chip.className       = "check-chip";
  chip.draggable       = true;
  chip.dataset.checkId = cid;
  chip.dataset.groupId = groupId;
  chip.innerHTML = `
    <span class="chip-sev chip-sev-${{sev}}">${{lbl}}</span>
    <span class="chip-body">
      <span class="chip-id">${{esc(cid)}}</span>
      <span class="chip-title">${{esc(m.check_title||"")}}</span>
    </span>
    <span class="chip-cnt">${{cnt?"×"+cnt:""}}</span>
  `;
  chip.ondragstart = e => onDragStart(e, cid, groupId);
  chip.ondragend   = e => {{ e.currentTarget.classList.remove("dragging"); _stopAutoScroll(); document.removeEventListener("dragover", _startAutoScroll); }};
  chip.onmouseenter= e => showTip(e, cid);
  chip.onmouseleave= () => hideTip();
  return chip;
}}

// ── Drag ──────────────────────────────────────────────────────────────
// Auto-scroll when dragging near viewport edges
let _scrollInterval = null;
function _startAutoScroll(e) {{
  const content  = document.getElementById("content");
  const zone     = 80; // px from edge triggers scroll
  const speed    = 12; // px per tick
  const rect     = content.getBoundingClientRect();
  const y        = e.clientY;
  if (_scrollInterval) {{ clearInterval(_scrollInterval); _scrollInterval = null; }}
  if (y < rect.top + zone) {{
    _scrollInterval = setInterval(() => content.scrollBy(0, -speed), 20);
  }} else if (y > rect.bottom - zone) {{
    _scrollInterval = setInterval(() => content.scrollBy(0, speed), 20);
  }}
}}
function _stopAutoScroll() {{
  if (_scrollInterval) {{ clearInterval(_scrollInterval); _scrollInterval = null; }}
}}

function onDragStart(e, cid, from) {{
  dragCid  = cid; dragFrom = from;
  e.currentTarget.classList.add("dragging");
  e.dataTransfer.effectAllowed = "move";
  document.addEventListener("dragover", _startAutoScroll);
}}
function onDragOver(e, toId) {{
  e.preventDefault();
  const el = toId==="__unassigned__"
    ? document.getElementById("unassigned-pool")
    : document.querySelector(`[data-group-id="${{toId}}"]`);
  if (el) el.classList.add("drag-over");
}}
function onDragLeave(e) {{
  const el = e.currentTarget;
  if (el) el.classList.remove("drag-over");
}}
function onDrop(e, toId) {{
  e.preventDefault();
  document.querySelectorAll(".drag-over").forEach(el=>el.classList.remove("drag-over"));
  if (!dragCid || dragFrom===toId) {{ dragCid=null; dragFrom=null; return; }}

  // Remove from source
  if (dragFrom==="__unassigned__") {{ unassigned=unassigned.filter(c=>c!==dragCid); }}
  else {{ const g=groups.find(x=>x.id===dragFrom); if(g) g.check_ids=g.check_ids.filter(c=>c!==dragCid); }}

  // Add to dest
  if (toId==="__unassigned__") {{ unassigned.push(dragCid); }}
  else {{ const g=groups.find(x=>x.id===toId); if(g&&!g.check_ids.includes(dragCid)) {{ g.check_ids.push(dragCid); g.is_merged=g.check_ids.length>1; }} }}

  groups = groups.filter(g=>g.check_ids.length>0);
  dragCid=null; dragFrom=null;
  _stopAutoScroll();
  document.removeEventListener("dragover", _startAutoScroll);
  render();
}}

// ── Group ops ─────────────────────────────────────────────────────────
function renameGroup(id,v)    {{ const g=groups.find(x=>x.id===id); if(g) g.group_name=v.trim()||g.group_name; updateStats(); }}
function updateRationale(id,v){{ const g=groups.find(x=>x.id===id); if(g) g.rationale=v; }}
function deleteGroup(id) {{
  const g=groups.find(x=>x.id===id); if(!g) return;
  unassigned.push(...g.check_ids);
  groups=groups.filter(x=>x.id!==id); render();
}}
function splitGroup(id) {{
  const g=groups.find(x=>x.id===id); if(!g||g.check_ids.length<=1) return;
  const idx=groups.indexOf(g);
  const news=g.check_ids.map((cid,i)=>({{
    id:`split_${{id}}_${{i}}`, group_name:ALL_CHECKS[cid]?.check_title||cid,
    rationale:`Split from: ${{g.group_name}}`, check_ids:[cid], is_merged:false,
  }}));
  groups.splice(idx,1,...news); render();
}}
function addNewGroup() {{
  const id=`new_${{Date.now()}}`;
  groups.push({{id, group_name:"New Group", rationale:"", check_ids:[], is_merged:false}});
  render();
  setTimeout(()=>{{
    const inp=document.querySelector(`[data-group-id="${{id}}"] .group-name-input`);
    if(inp){{inp.focus();inp.select();}}
  }},50);
}}
function resetToProposal() {{
  if(confirm("Reset to AI proposal? Your changes will be lost.")) init();
}}

// ── Stats ──────────────────────────────────────────────────────────────
function updateStats() {{
  const merged=groups.filter(g=>g.check_ids.length>1).length;
  const solo  =groups.filter(g=>g.check_ids.length===1).length;
  const total =groups.reduce((s,g)=>s+g.check_ids.length,0);
  document.getElementById("s-current").textContent   = groups.length;
  document.getElementById("s-merged").textContent    = merged;
  document.getElementById("s-standalone").textContent= solo;
  document.getElementById("s-unassigned").textContent= unassigned.length;
  document.getElementById("t-groups").textContent    = groups.length;
  document.getElementById("t-checks").textContent    = total;
  const btn=document.getElementById("approve-btn");
  btn.disabled = unassigned.length>0;
}}

// ── Tooltip ───────────────────────────────────────────────────────────
const tip = document.getElementById("tooltip");
function showTip(e, cid) {{
  const m=ALL_CHECKS[cid]||{{}};
  tip.innerHTML=`<strong>${{esc(cid)}}</strong><br>${{esc(m.check_title||"")}}<br>
    Severity: ${{cap(m.severity||"?")}}&nbsp;·&nbsp;Instances: ${{m.instance_count||0}}<br>
    Service: ${{esc(m.service||"?")}}&nbsp;·&nbsp;Likelihood: ${{m.likelihood||"?"}}
    ${{m.categories?.length?`<br>Categories: ${{m.categories.join(", ")}}`:""}}`;
  tip.style.display="block";
  moveTip(e);
}}
function moveTip(e) {{
  tip.style.left=(e.clientX+12)+"px";
  tip.style.top =(e.clientY+12)+"px";
}}
function hideTip() {{ tip.style.display="none"; }}
document.addEventListener("mousemove", e=>{{ if(tip.style.display!=="none") moveTip(e); }});

// ── Approve — POST to local server ────────────────────────────────────
function approveGrouping() {{
  const msg = document.getElementById("status-msg");

  if (unassigned.length>0) {{
    msg.className="status-err";
    msg.textContent=`⚠ ${{unassigned.length}} check(s) unassigned — assign them before approving.`;
    return;
  }}
  const unnamed=groups.filter(g=>!g.group_name.trim()||g.group_name==="New Group");
  if (unnamed.length>0) {{
    msg.className="status-err";
    msg.textContent=`⚠ ${{unnamed.length}} group(s) have no name.`;
    return;
  }}
  const empty=groups.filter(g=>g.check_ids.length===0);
  if (empty.length>0) {{
    msg.className="status-err";
    msg.textContent=`⚠ ${{empty.length}} empty group(s) — delete them.`;
    return;
  }}

  const payload = {{
    run_id:       RUN_ID,
    approved_at:  new Date().toISOString(),
    groups: groups.map(g=>({{
      group_name:   g.group_name.trim(),
      check_ids:    g.check_ids,
      rationale:    g.rationale||"",
      analyst_note: "",
    }})),
  }};

  msg.className="status-msg";
  msg.textContent="Sending approval to pipeline...";

  fetch(`http://localhost:${{SERVER_PORT}}/approve`, {{
    method: "POST",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify(payload),
  }})
  .then(r => r.json())
  .then(data => {{
    if (data.ok) {{
      msg.className="status-ok";
      msg.textContent=`✓ Approved — ${{groups.length}} groups saved. Pipeline is continuing...`;
      document.getElementById("approve-btn").disabled=true;
      document.getElementById("approve-btn").textContent="✓ Approved";
    }} else {{
      msg.className="status-err";
      msg.textContent="Error: "+data.error;
    }}
  }})
  .catch(err => {{
    msg.className="status-err";
    msg.textContent="Could not reach pipeline server. Is it still running? — "+err;
  }});
}}

// ── Helpers ───────────────────────────────────────────────────────────
function esc(s) {{ return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }}
function cap(s) {{ return s?s.charAt(0).toUpperCase()+s.slice(1):s; }}
function groupSev(ids) {{
  const o={{critical:0,high:1,medium:2,low:3,informational:4}};
  return ids.reduce((b,cid)=>{{ const s=(ALL_CHECKS[cid]?.severity||"informational").toLowerCase(); return (o[s]??5)<(o[b]??5)?s:b; }},"informational");
}}
function groupInst(ids) {{ return ids.reduce((s,cid)=>s+(ALL_CHECKS[cid]?.instance_count||0),0); }}
function groupAccts(ids) {{
  const seen=new Set();
  ids.forEach(cid=>(ALL_CHECKS[cid]?.accounts||[]).forEach(a=>seen.add(a)));
  return [...seen];
}}

init();
</script>
</body>
</html>"""


# ── HTTP server ───────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):
    """Minimal HTTP handler — serves the HTML and receives the approval POST."""

    html_content: str = ""
    approved_path: Path = None
    approval_received: threading.Event = None

    def log_message(self, format, *args):
        pass  # suppress server access logs

    def do_GET(self):
        if self.path in ("/", "/review"):
            body = _Handler.html_content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/static/"):
            # Serve logo and other static files
            static_dir = Path(__file__).resolve().parent / "static"
            file_path  = static_dir / self.path[8:]  # strip /static/
            if file_path.exists() and file_path.is_file():
                ext  = file_path.suffix.lower()
                mime = {"png": "image/png", "jpg": "image/jpeg",
                    "jpeg": "image/jpeg", "svg": "image/svg+xml",
                    "gif": "image/gif", "webp": "image/webp"}.get(ext[1:], "application/octet-stream")
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

    def do_POST(self):
        if self.path == "/approve":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            try:
                data = json.loads(body)
                # Validate minimally
                if not data.get("groups"):
                    raise ValueError("No groups in payload")
                # Write to disk
                _Handler.approved_path.write_text(
                    json.dumps(data, indent=2), encoding="utf-8"
                )
                resp = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", len(resp))
                self.end_headers()
                self.wfile.write(resp)
                # Signal the waiting thread
                _Handler.approval_received.set()
            except Exception as e:
                resp = json.dumps({"ok": False, "error": str(e)}).encode("utf-8")
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", len(resp))
                self.end_headers()
                self.wfile.write(resp)

    def do_OPTIONS(self):
        # CORS preflight
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


def start_review_server(
    grouping_result: GroupingResult,
    output_dir: Path,
    client_name: str = "",
    port: int = 8742,
    open_browser: bool = True,
    timeout_seconds: int = 3600,
) -> ApprovedGrouping:
    """
    Start a localhost HTTP server, open the browser, and wait for approval.

    Args:
        grouping_result:  Stage 2.5 output.
        output_dir:       Where to write grouping_approved.json.
        client_name:      For display in the header.
        port:             Localhost port (default 8742).
        open_browser:     Set False when running over SSH.
        timeout_seconds:  How long to wait before giving up.

    Returns:
        ApprovedGrouping once the analyst clicks Approve.
    """
    approved_path = output_dir / "grouping_approved.json"

    # Remove stale approval from previous run
    if approved_path.exists():
        approved_path.unlink()

    # Build HTML
    html = generate_review_html(
        grouping_result, output_dir, client_name, port
    )

    # Wire into handler class
    approval_event = threading.Event()
    _Handler.html_content      = html
    _Handler.approved_path     = approved_path
    _Handler.approval_received = approval_event

    # Start server
    server = HTTPServer(("localhost", port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://localhost:{port}/review"

    print(f"\n  {'─'*60}", flush=True)
    print(f"  ⏳ Grouping review server started", flush=True)
    print(f"  🌐 URL: {url}", flush=True)
    if not open_browser:
        print(f"  ℹ --no-browser: open the URL manually in a browser", flush=True)
    print(f"  {'─'*60}", flush=True)
    print(flush=True)

    if open_browser:
        # Small delay so server is ready
        time.sleep(0.4)
        try:
            webbrowser.open(url)
            print(f"  ✓ Browser opened", flush=True)
        except Exception:
            print(f"  ⚠ Could not open browser — open manually: {url}", flush=True)

    # Wait for approval
    spinner  = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    elapsed  = 0
    spin_i   = 0
    interval = 1

    while elapsed < timeout_seconds:
        if approval_event.wait(timeout=interval):
            print(f"\r  ✓ Approval received                              ", flush=True)
            server.shutdown()
            return load_approved_grouping(approved_path)

        mins, secs = divmod(elapsed, 60)
        print(
            f"\r  {spinner[spin_i % len(spinner)]} Waiting for approval... "
            f"{mins:02d}:{secs:02d}  ",
            end="", flush=True,
        )
        spin_i  += 1
        elapsed += interval

    server.shutdown()
    raise TimeoutError(
        f"No approval received after {timeout_seconds // 60} minutes."
    )


# ── Apply approved grouping ───────────────────────────────────────────

def apply_approved_grouping(
    approved: ApprovedGrouping,
    grouping_result: GroupingResult,
) -> GroupingResult:
    """Rebuild GroupingResult from analyst-approved grouping."""
    from stage2_5_grouping import (
        GroupingResult as GR,
        GroupingWarning,
    )

    original_by_check_id: dict[str, OutputGroup] = {}
    for grp in grouping_result.grouped_groups:
        for src in grp.source_groups:
            original_by_check_id[src.check_id] = src

    new_groups = []
    warnings   = []

    for ap in approved.groups:
        source_groups = []
        for cid in ap.check_ids:
            if cid in original_by_check_id:
                source_groups.append(original_by_check_id[cid])
            else:
                warnings.append(GroupingWarning(
                    code="UNKNOWN_CHECK_ID",
                    message=(
                        f"Approved group '{ap.group_name}' references "
                        f"unknown check_id '{cid}'. Skipped."
                    ),
                ))

        if not source_groups:
            continue

        is_merged  = len(source_groups) > 1
        rep        = _best_representative(source_groups)
        severity   = _highest_severity(source_groups)
        likelihood = _highest_likelihood(source_groups)

        all_instance_ids: list[str] = []
        all_account_names: list[str] = []
        all_account_uids:  list[str] = []
        total = 0
        for sg in source_groups:
            all_instance_ids.extend(sg.instance_ids)
            total += sg.instance_count
            for n in sg.affected_account_names:
                if n not in all_account_names:
                    all_account_names.append(n)
            for u in sg.affected_account_uids:
                if u not in all_account_uids:
                    all_account_uids.append(u)

        rep.instance_count    = total
        rep.likelihood_rating = likelihood
        rep.add_audit(
            stage="stage2_5_reviewer",
            field="semantic_group",
            old_value=", ".join(ap.check_ids),
            new_value=ap.group_name,
            reason=(
                f"Analyst-approved. {ap.analyst_note}"
                if ap.analyst_note else "Analyst-approved grouping."
            ),
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
            affected_account_names=all_account_names,
            affected_account_uids=all_account_uids,
            severity=severity,
            likelihood_rating=likelihood,
            source_groups=source_groups,
        ))

    return GR(
        run_id=grouping_result.run_id,
        grouped_groups=new_groups,
        all_findings=grouping_result.all_findings,
        warnings=warnings,
        config=grouping_result.config,
        original_count=grouping_result.original_count,
        merged_count=len(new_groups),
        merges_applied=sum(1 for g in new_groups if g.is_merged),
    )