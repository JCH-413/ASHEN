"""
Variance study for E1: are the grounding conclusions stable across random seeds,
or an artifact of one seed? Runs every grounding condition on every target across
N seeds at non-zero temperature and reports mean +/- stdev per condition.

Pure LLM generation — uses the per-target ground truth from `expected_vulnerable`
(no oracle, no VMs touched). Writes incrementally so a crash loses nothing.
"""
from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path

from eval import metrics
from eval.harness import CONDITIONS, build_scan_context
from eval.parse import extract_cve_ids, parse_ranked_exploit_types
from eval.recommend import recommend

SEEDS = [1, 2, 3, 4, 5]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--out", type=Path, default=Path("eval/variance_results.json"))
    args = ap.parse_args()
    TEMPERATURE = args.temperature
    OUT = args.out
    cfg = json.loads(Path("eval/targets.json").read_text())
    rows = []  # one row per (target, seed, condition)

    for target in cfg["targets"]:
        relevant = {f["exploit_type"] for f in target["findings"]
                    if f.get("expected_vulnerable")}
        valid = {c.upper() for c in target.get("valid_cves", [])}
        sc = build_scan_context(target)
        for seed in SEEDS:
            for cond in CONDITIONS:
                rec = recommend(sc, grounding=cond,
                                options={"temperature": TEMPERATURE, "seed": seed})
                ranked = parse_ranked_exploit_types(rec["recommendation"])
                cves = extract_cve_ids(rec["recommendation"])
                row = {
                    "target": target["name"], "seed": seed, "condition": cond,
                    "top1": ranked[0] if ranked else None,
                    "precision_at_1": metrics.precision_at_1(ranked, relevant),
                    "reciprocal_rank": metrics.reciprocal_rank(ranked, relevant),
                    "fabrication_rate": metrics.fabrication_rate(cves, valid),
                }
                rows.append(row)
                print(f"  {target['name']:<22} seed={seed} {cond:<13} "
                      f"P@1={row['precision_at_1']} MRR={round(row['reciprocal_rank'],3)} "
                      f"fab={row['fabrication_rate']}")
                OUT.write_text(json.dumps({"rows": rows}, indent=2))  # incremental

    # Aggregate per condition (across all targets x seeds).
    print("\n=== AGGREGATE (mean +/- stdev across targets x seeds) ===")
    summary = {}
    for cond in CONDITIONS:
        sub = [r for r in rows if r["condition"] == cond]
        p1 = [r["precision_at_1"] for r in sub if r["precision_at_1"] is not None]
        mrr = [r["reciprocal_rank"] for r in sub]
        fab = [r["fabrication_rate"] for r in sub if r["fabrication_rate"] is not None]

        def ms(xs):
            return (round(statistics.mean(xs), 3),
                    round(statistics.pstdev(xs), 3)) if xs else (None, None)

        summary[cond] = {"p1": ms(p1), "mrr": ms(mrr), "fab": ms(fab), "n": len(sub)}
        p1m, p1s = summary[cond]["p1"]; mrm, mrs = summary[cond]["mrr"]
        fbm, fbs = summary[cond]["fab"]
        print(f"  {cond:<13}: P@1={p1m}±{p1s}  MRR={mrm}±{mrs}  fab={fbm}±{fbs}  (n={len(sub)})")

    OUT.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "seeds": SEEDS, "temperature": TEMPERATURE,
        "summary": summary, "rows": rows,
    }, indent=2))
    print(f"\nWrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
