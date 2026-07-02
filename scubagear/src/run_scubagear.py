"""
run_scubagear.py — ScubaGear pipeline orchestrator + CLI

Usage:
    python run_scubagear.py \\
        --action-plan path/to/ActionPlan.csv \\
        --tenant-id   <azure-tenant-uuid> \\
        [--config     path/to/scubagear_config.toml] \\
        [--output-dir path/to/output/] \\
        [--no-browser]

Environment:
    PIPELINE_LLM_CACHE_DIR=.llm_cache   cache Bedrock responses to disk
                                        (subsequent runs reuse cached responses
                                        at zero cost — essential for dev/testing)

Pipeline stages:
    Stage 1 — sg_ingest:   CSV → ScubaFinding objects
    Stage 2 — sg_process:  filter, dedup, build OutputGroups, assign ref numbers
    Stage 2.5 — sg_grouping:  LLM semantic grouping (chunked + consolidated)
    Review UI — sg_reviewer: localhost browser for analyst approval
    Stage 3 — sg_enrich:  LLM enrichment per approved group
    Stage 5 — sg_render_excel: write enriched groups to Output_Template.xlsx

Note: Stage numbering matches the Prowler pipeline for conceptual alignment.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

# ── Path setup ────────────────────────────────────────────────────────
# Allow running from any directory
_SRC_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SRC_DIR))

import tomllib  # Python 3.11+; for 3.9/3.10 use tomli (pip install tomli)

from sg_ingest import ingest
from sg_process import process
from sg_grouping import group_semantically
from sg_reviewer import start_review_server, apply_approved_grouping
from sg_enrich import enrich_grouped
from sg_render_excel import render_excel

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("run_scubagear")


# ── Config loader ─────────────────────────────────────────────────────

def load_config(config_path: Path) -> dict[str, Any]:
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    with config_path.open("rb") as f:
        return tomllib.load(f)


# ── Output directory ──────────────────────────────────────────────────

def _output_dir(config: dict[str, Any], base: Optional[Path] = None) -> Path:
    """Resolve output directory: CLI arg > config client_name > default."""
    if base:
        d = base
    else:
        client = config.get("engagement", {}).get("client_name", "output").replace(" ", "_")
        d = _SRC_DIR.parent / "data" / "output" / client
    d.mkdir(parents=True, exist_ok=True)
    return d


# ── Run summary writer ────────────────────────────────────────────────

def _write_run_summary(
    output_dir: Path,
    run_id: str,
    stages: dict[str, Any],
    config: dict[str, Any],
) -> None:
    summary = {
        "run_id":     run_id,
        "completed_at": datetime.utcnow().isoformat(),
        "engagement": config.get("engagement", {}),
        "stages":     stages,
    }
    path = output_dir / "run_summary.json"
    path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(f"\n  Run summary → {path}", flush=True)


# ── CLI ───────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="ScubaGear M365 Security Report Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--action-plan",
        metavar="PATH",
        help="Path to ActionPlan.csv (or ScubaResults.csv). "
             "Defaults to config [processing] input_file setting.",
    )
    p.add_argument(
        "--tenant-id",
        metavar="UUID",
        default="",
        help="Azure tenant UUID. Overrides config [engagement] tenant_id.",
    )
    p.add_argument(
        "--config",
        metavar="PATH",
        default=str(_SRC_DIR.parent / "config" / "scubagear_config.toml"),
        help="Path to scubagear_config.toml.",
    )
    p.add_argument(
        "--output-dir",
        metavar="PATH",
        default=None,
        help="Output directory. Defaults to data/output/<client_name>/.",
    )
    p.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not auto-open the review UI in a browser.",
    )
    p.add_argument(
        "--skip-grouping",
        action="store_true",
        help="Skip Stage 2.5 semantic grouping (enrich each control individually).",
    )
    p.add_argument(
        "--skip-review",
        action="store_true",
        help="Skip the review UI (auto-approve the AI's proposed grouping).",
    )
    p.add_argument(
        "--port",
        type=int,
        default=8743,
        help="Port for the review UI server (default: 8743).",
    )
    p.add_argument(
        "--run-id",
        metavar="UUID",
        default=None,
        help="Force a specific run ID (for re-runs or testing).",
    )
    return p


# ── Main pipeline ─────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> int:
    """
    Full pipeline execution.
    Returns 0 on success, 1 on error.
    """
    run_id = args.run_id or str(uuid.uuid4())
    print(f"\n{'='*64}", flush=True)
    print(f"  ScubaGear M365 Security Report Pipeline", flush=True)
    print(f"  Run ID: {run_id}", flush=True)
    print(f"{'='*64}", flush=True)

    # ── Config ────────────────────────────────────────────────────────
    config_path = Path(args.config)
    print(f"\n  Loading config: {config_path}", flush=True)
    config = load_config(config_path)
    engagement = config.get("engagement", {})
    print(f"  Client: {engagement.get('client_name')} | Period: {engagement.get('assessment_period')}", flush=True)

    output_dir = _output_dir(config, Path(args.output_dir) if args.output_dir else None)
    print(f"  Output dir: {output_dir}", flush=True)

    # ── Resolve input file ────────────────────────────────────────────
    if args.action_plan:
        csv_path = Path(args.action_plan)
    else:
        # Try to find the file relative to the working directory
        input_file_name = config.get("processing", {}).get("input_file", "ActionPlan")
        csv_path = Path(f"{input_file_name}.csv")
        if not csv_path.exists():
            print(
                f"\n  ✗ No input file supplied and '{csv_path}' not found.\n"
                f"  Use --action-plan <path> to specify the CSV file.\n",
                flush=True,
            )
            return 1

    stages: dict[str, Any] = {}

    # ── Stage 1: Ingest ───────────────────────────────────────────────
    ingest_result = ingest(
        csv_path=csv_path,
        config=config,
        tenant_id=args.tenant_id,
        run_id=run_id,
    )
    stages["ingest"] = {
        "findings": ingest_result.finding_count,
        "warnings": len(ingest_result.warnings),
    }

    if ingest_result.finding_count == 0:
        print("\n  ✗ No findings parsed from input file. Check the CSV path and format.", flush=True)
        return 1

    # ── Stage 2: Process ──────────────────────────────────────────────
    process_result = process(ingest_result, config)
    stages["process"] = {
        "included": process_result.included_count,
        "excluded": process_result.excluded_count,
        "groups":   process_result.group_count,
    }

    if process_result.group_count == 0:
        print(
            "\n  ✗ No findings passed the filter. Check [processing] include_criticality "
            "in scubagear_config.toml and verify the input file contains failing controls.",
            flush=True,
        )
        return 1

    # ── Stage 2.5: Semantic grouping ──────────────────────────────────
    if args.skip_grouping:
        print("\n  [ Stage 2.5 ] Skipped (--skip-grouping)", flush=True)
        # Wrap OutputGroups as trivial GroupedOutputGroups for compatibility
        from sg_grouping import GroupedOutputGroup, GroupingResult
        trivial_groups = [
            GroupedOutputGroup(
                group_name=g.check_id,
                group_rationale="",
                output_section=g.output_section,
                is_merged=False,
                check_ids=[g.check_id],
                representative=g.representative,
                instance_ids=g.instance_ids,
                instance_count=g.instance_count,
                affected_tenant_ids=g.affected_tenant_ids,
                severity=g.severity,
                likelihood_rating=g.likelihood_rating,
                source_groups=[g],
            )
            for g in process_result.output_groups
        ]
        grouping_result = GroupingResult(
            run_id=run_id,
            grouped_groups=trivial_groups,
            all_findings=process_result.all_findings,
            warnings=[],
            config=config,
            original_count=process_result.group_count,
            merged_count=len(trivial_groups),
        )
    else:
        grouping_result = group_semantically(process_result, config)
        stages["grouping"] = {
            "original_controls": grouping_result.original_count,
            "groups_proposed":   grouping_result.group_count,
            "merges_applied":    grouping_result.merges_applied,
            "chunks_used":       grouping_result.chunks_used,
            "consolidation":     grouping_result.consolidation_applied,
            "warnings":          len(grouping_result.warnings),
        }

    # ── Review UI ─────────────────────────────────────────────────────
    if args.skip_grouping or args.skip_review:
        print(f"\n  [ Review UI ] Skipped — using AI-proposed grouping as-is", flush=True)
        approved_grouping_result = grouping_result
    else:
        approved = start_review_server(
            grouping_result=grouping_result,
            output_dir=output_dir,
            config=config,
            client_name=engagement.get("client_name", ""),
            port=args.port,
            open_browser=not args.no_browser,
        )
        approved_grouping_result = apply_approved_grouping(approved, grouping_result)
        stages["review"] = {
            "approved_groups": len(approved.groups),
            "approved_at":     approved.approved_at,
        }
        print(
            f"\n  ✓ Approved grouping: {len(approved.groups)} group(s)",
            flush=True,
        )

    # ── Stage 3: Enrich ───────────────────────────────────────────────
    enrich_result = enrich_grouped(approved_grouping_result, config)
    stages["enrich"] = {
        "enriched": enrich_result.enriched_count,
        "failed":   enrich_result.failed_count,
        "risk_counts": enrich_result.risk_rating_counts,
    }

    # ── Stage 5: Excel render ─────────────────────────────────────────
    template_path = Path(config.get("output", {}).get("template_path", "templates/Output_Template.xlsx"))
    if not template_path.is_absolute():
        template_path = _SRC_DIR.parent / template_path

    output_filename = engagement.get("output_filename", "M365_SecurityReport.xlsx")
    output_excel    = output_dir / output_filename

    render_result = render_excel(
        enrich_result=enrich_result,
        template_path=template_path,
        output_path=output_excel,
        config=config,
    )
    stages["render"] = {
        "output_file":    str(render_result.output_path),
        "groups_written": render_result.groups_written,
        "warnings":       render_result.warnings,
    }

    # ── Run summary ───────────────────────────────────────────────────
    _write_run_summary(output_dir, run_id, stages, config)

    # ── Final summary ─────────────────────────────────────────────────
    risk = enrich_result.risk_rating_counts
    print(f"\n{'='*64}", flush=True)
    print(f"  ✓ Pipeline complete", flush=True)
    print(f"  Controls processed: {process_result.included_count}", flush=True)
    print(f"  Report findings:    {render_result.groups_written}", flush=True)
    print(f"  Risk distribution:  High={risk.get('High',0)}  Medium={risk.get('Medium',0)}  Low={risk.get('Low',0)}", flush=True)
    print(f"  Output:             {output_excel}", flush=True)
    if enrich_result.failed_count:
        print(f"  ⚠ {enrich_result.failed_count} finding(s) need human review (LLM enrichment failed)", flush=True)
    print(f"{'='*64}\n", flush=True)

    return 0


# ── Entry point ───────────────────────────────────────────────────────

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()