"""
ASHEN evaluation harness — the closed detect -> recommend -> remediate ->
re-validate loop, driven from a JSON config, emitting scorable rows.

It drives the real services directly (no web/auth/DB layer) so a run is
reproducible and self-contained:

  1. ORACLE: run each configured exploit type against the target; its
     `vulnerable` verdict is the ground truth.                       -> E2
  2. RECOMMEND under three grounding conditions (off / plain / action_aware),
     parse the prose into a ranked list of exploit types, record cited CVEs.
                                                                     -> E1, E2
  3. REMEDIATE each confirmed-vulnerable finding, PAUSE for the operator to
     apply the fix by hand, then re-run the oracle and check the verdict
     flipped (and the service is still up).                          -> headline

Memory: a full live run loads torch (retrieval), Ollama, and msfconsole, which
OOM-kills on small hosts because Python never releases torch. To prevent this,
a full run is split into three PHASES, each executed as its own subprocess so
the OS reclaims memory between them — torch is only ever loaded in the recommend
phase, never alongside msfconsole. State is passed through a JSON file.

Usage (from ashen/backend, with the repo-root venv and Ollama running):

    # Full closed loop — phase-split, OOM-safe; pauses for manual remediation:
    OLLAMA_TIMEOUT=600 python -m eval.harness --config eval/targets.json --out eval/results

    # E1/E2 only, no manual remediation (single process):
    python -m eval.harness --config eval/targets.json --skip-remediation

    # Pipeline dry-run, no VMs touched:
    python -m eval.harness --config eval/targets.json --no-exploit --skip-remediation
"""
from __future__ import annotations

import argparse
import csv
import json
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from app.services.exploits import REGISTRY, get_runner

from eval import metrics
from eval.parse import extract_cve_ids, parse_ranked_exploit_types

# NOTE: eval.recommend (which imports torch via rag_store) and
# app.services.remediation_service are imported LAZILY inside the phases that
# need them, so the oracle and remediate phases never load torch.

DEFAULT_OPTIONS = {"temperature": 0.0, "seed": 42}

# The grounding conditions compared per target, in report order.
CONDITIONS = ("off", "plain", "action_aware")


# ── context builders ──────────────────────────────────────────────────

def build_scan_context(target: dict) -> str:
    """Reconstruct the attack-recommendation context in the app's text shape."""
    parts = [f"Target: {target['ip']}", "Open ports and vulnerabilities:"]
    parts.extend(f"- {line}" for line in target.get("scan_context_lines", []))
    parts.append("Available exploit types in ASHEN: " + ", ".join(REGISTRY.keys()))
    return "\n".join(parts)


def build_remediation_context(ip: str, finding: dict, oracle: dict) -> str:
    """Mirror app._build_rich_remediation_context for one confirmed finding.

    `oracle` is the serialized verdict dict (so this works across the phase
    process boundary).
    """
    parts = [
        f"Vulnerability: {finding['exploit_type']} on port {finding['port']}",
        f"Severity: {finding.get('severity', 'unknown')}",
    ]
    if finding.get("description"):
        parts.append(f"Description: {finding['description']}")
    parts.append(f"Target: {ip}")
    parts.append(
        f"Exploit: {oracle['exploit_type']} via {oracle['tool']} — "
        f"{'VULNERABLE' if oracle['vulnerable'] else 'not vulnerable'}: {oracle['summary']}"
    )
    return "\n".join(parts)


# ── oracle ────────────────────────────────────────────────────────────

def _oracle_to_dict(res) -> dict:
    """Serialize the bits of an ExploitResult later phases need."""
    return {
        "exploit_type": res.exploit_type,
        "tool": res.tool,
        "port": res.port,
        "ran": res.ran,
        "vulnerable": bool(res.vulnerable),
        "summary": res.summary,
    }


def run_oracle(ip: str, port: int, exploit_type: str):
    """Run one exploit type; its verdict is ground truth. None if type unknown."""
    runner = get_runner(exploit_type)
    if runner is None:
        print(f"  ! unknown exploit_type '{exploit_type}', skipping", file=sys.stderr)
        return None
    return runner.run(ip, port)


def service_up(ip: str, port: int, timeout: float = 3.0) -> bool:
    """Cheap reachability check: can we open a TCP connection to the port?"""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


# ── scoring one recommendation ────────────────────────────────────────

def _recommend_condition(scan_context: str, grounding: str, relevant: set[str],
                         valid_cves: set[str], options: dict) -> dict:
    """One recommendation + its parsed, scored result under a fixed condition."""
    from eval.recommend import recommend  # lazy: loads torch only in this phase
    rec = recommend(scan_context, grounding=grounding, options=options)
    ranked = parse_ranked_exploit_types(rec["recommendation"])
    cves = extract_cve_ids(rec["recommendation"])
    return {
        "condition": grounding,
        "ranked": ranked,
        "cited_cves": cves,
        "precision_at_1": metrics.precision_at_1(ranked, relevant),
        "reciprocal_rank": metrics.reciprocal_rank(ranked, relevant),
        "fabrication_rate": metrics.fabrication_rate(cves, valid_cves),
        "recommendation": rec["recommendation"],
    }


def _remediate_and_revalidate(ip: str, finding: dict, oracle: dict, options: dict) -> dict:
    """Generate a fix, pause for the operator to apply it, then re-test."""
    from app.services.remediation_service import get_remediation  # lazy: no torch
    et, port = finding["exploit_type"], finding["port"]
    print(f"\n  [remediate] {et} on {ip}:{port}")
    context = build_remediation_context(ip, finding, oracle)
    guidance = get_remediation(context)
    print("  ---------------- GENERATED REMEDIATION ----------------")
    print("  " + guidance.replace("\n", "\n  "))
    print("  -------------------------------------------------------")
    print(f"  >> SNAPSHOT the VM, then apply the fix above to {ip}.")
    try:
        input("  >> Press Enter once the fix is applied (or Ctrl-C to abort)... ")
    except EOFError:
        raise SystemExit(
            "\n  remediation needs an interactive terminal — run the harness "
            "directly (do not pipe stdin) so you can apply each fix and press Enter."
        )

    print(f"  [re-validate] re-running {et} on {ip}:{port} ...")
    after = run_oracle(ip, port, et)
    vuln_after = bool(after and after.vulnerable)
    up_after = service_up(ip, port)
    outcome = metrics.remediation_outcome(
        vuln_before=bool(oracle["vulnerable"]),
        vuln_after=vuln_after,
        service_up_after=up_after,
    )
    print(f"  [re-validate] vuln_after={vuln_after} service_up={up_after} -> {outcome.upper()}")
    return {
        "exploit_type": et,
        "port": port,
        "vuln_before": bool(oracle["vulnerable"]),
        "vuln_after": vuln_after,
        "service_up_after": up_after,
        "outcome": outcome,
        "guidance": guidance,
    }


# ── phases (each runs as its own process for full live runs) ───────────

def _load_state(path: Path) -> dict:
    return json.loads(path.read_text())


def _save_state(path: Path, state: dict) -> None:
    path.write_text(json.dumps(state, indent=2))


def phase_oracle(cfg: dict, state_path: Path, *, do_exploit: bool) -> None:
    """Phase 1: establish ground truth. Loads NO torch (msfconsole/hydra only)."""
    targets = []
    for target in cfg["targets"]:
        ip = target["ip"]
        print(f"\n=== [oracle] {ip} ({target.get('name', '')}) ===")
        oracle, relevant = {}, []
        if do_exploit:
            for f in target["findings"]:
                print(f"  running {f['exploit_type']} on {ip}:{f['port']} ...")
                res = run_oracle(ip, f["port"], f["exploit_type"])
                if res is None:
                    continue
                oracle[f["exploit_type"]] = _oracle_to_dict(res)
                print(f"    -> {'VULNERABLE' if res.vulnerable else 'not vulnerable'} ({res.summary})")
                if res.vulnerable:
                    relevant.append(f["exploit_type"])
        else:
            relevant = [f["exploit_type"] for f in target["findings"]
                        if f.get("expected_vulnerable")]
            for f in target["findings"]:
                oracle[f["exploit_type"]] = {
                    "exploit_type": f["exploit_type"], "tool": "(assumed)",
                    "port": f["port"], "ran": True,
                    "vulnerable": bool(f.get("expected_vulnerable")),
                    "summary": "assumed from config (--no-exploit)",
                }
            print(f"  skipped (--no-exploit); assumed relevant: {relevant or '∅'}")
        targets.append({"ip": ip, "name": target.get("name", ""),
                        "relevant": relevant, "oracle": oracle,
                        # Per-target valid CVE set (falls back to the global one)
                        # so fabrication is scored against what applies to THIS
                        # host — e.g. EternalBlue is valid on a Windows box but a
                        # fabrication on a Linux one.
                        "valid_cves": target.get("valid_cves", cfg.get("valid_cves", [])),
                        "conditions": [], "remediations": []})
    _save_state(state_path, {"valid_cves": cfg.get("valid_cves", []), "targets": targets})


def phase_recommend(cfg: dict, state_path: Path, *, options: dict) -> None:
    """Phase 2: recommend under each grounding. Loads torch + Ollama, no msfconsole."""
    state = _load_state(state_path)
    cfg_by_ip = {t["ip"]: t for t in cfg["targets"]}
    for t in state["targets"]:
        print(f"\n=== [recommend] {t['ip']} ===")
        scan_context = build_scan_context(cfg_by_ip[t["ip"]])
        relevant = set(t["relevant"])
        valid_cves = {c.upper() for c in t.get("valid_cves", state.get("valid_cves", []))}
        conds = []
        for grounding in CONDITIONS:
            print(f"  grounding={grounding} ...")
            conds.append(_recommend_condition(scan_context, grounding, relevant,
                                               valid_cves, options))
        t["conditions"] = conds
    _save_state(state_path, state)


def phase_remediate(cfg: dict, state_path: Path, *, options: dict) -> None:
    """Phase 3: remediate + re-validate. Ollama then msfconsole, no torch."""
    state = _load_state(state_path)
    cfg_by_ip = {t["ip"]: t for t in cfg["targets"]}
    for t in state["targets"]:
        findings = {f["exploit_type"]: f for f in cfg_by_ip[t["ip"]]["findings"]}
        rems = []
        for et in sorted(t["relevant"]):
            rems.append(_remediate_and_revalidate(t["ip"], findings[et],
                                                  t["oracle"][et], options))
        t["remediations"] = rems
    _save_state(state_path, state)


def orchestrate(config: Path, options: dict, out: Path, *,
                do_exploit: bool, do_remediation: bool) -> list[dict]:
    """Run the phases as separate subprocesses so memory is reclaimed between them."""
    state_path = out.with_suffix(".state.json")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    common = ["--config", str(config), "--state", str(state_path),
              "--temperature", str(options["temperature"]), "--seed", str(options["seed"])]

    # The memory-heavy phases run as subprocesses so the OS reclaims their RAM
    # (torch, msfconsole) before the next phase starts.
    subprocess_phases = [("oracle", [] if do_exploit else ["--no-exploit"]),
                         ("recommend", [])]
    for name, extra in subprocess_phases:
        print(f"\n>>>>>> phase: {name} (subprocess) >>>>>>")
        proc = subprocess.run(
            [sys.executable, "-m", "eval.harness", "--phase", name, *common, *extra]
        )
        if proc.returncode != 0:
            raise SystemExit(f"phase '{name}' failed (exit {proc.returncode}); "
                             f"state preserved at {state_path}")

    # Remediation runs IN-PROCESS: the orchestrator never loaded torch (lazy
    # import) and the oracle/recommend subprocesses have exited, so memory is
    # already free; and stdin stays the real terminal so the operator's Enter is
    # read directly (no fragile stdin inheritance across a subprocess).
    if do_remediation and do_exploit:
        print("\n>>>>>> phase: remediate (in-process) >>>>>>")
        phase_remediate(json.loads(config.read_text()), state_path, options=options)

    return _load_state(state_path)["targets"]


# ── outputs ───────────────────────────────────────────────────────────

def write_outputs(results: list[dict], out_prefix: Path) -> None:
    """Write the full JSON record and flat CSVs for the tables."""
    out_prefix.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat()

    out_prefix.with_suffix(".json").write_text(
        json.dumps({"generated": stamp, "targets": results}, indent=2))

    csv_path = out_prefix.with_suffix(".csv")
    with csv_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "name", "condition", "relevant", "ranked", "top1",
                    "precision_at_1", "reciprocal_rank", "cited_cves", "fabrication_rate"])
        for t in results:
            for c in t["conditions"]:
                w.writerow([t["ip"], t["name"], c["condition"], "|".join(t["relevant"]),
                            "|".join(c["ranked"]), c["ranked"][0] if c["ranked"] else "",
                            c["precision_at_1"], round(c["reciprocal_rank"], 4),
                            "|".join(c["cited_cves"]), c["fabrication_rate"]])

    rem_path = out_prefix.parent / (out_prefix.name + "_remediation.csv")
    with rem_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "exploit_type", "port", "vuln_before", "vuln_after",
                    "service_up_after", "outcome"])
        for t in results:
            for r in t["remediations"]:
                w.writerow([t["ip"], r["exploit_type"], r["port"], r["vuln_before"],
                            r["vuln_after"], r["service_up_after"], r["outcome"]])

    print(f"\nWrote {out_prefix.with_suffix('.json')}\n      {csv_path}\n      {rem_path}")


def print_summary(results: list[dict]) -> None:
    """One-screen rollup of the experiments."""
    for cond in CONDITIONS:
        conds = [c for t in results for c in t["conditions"] if c["condition"] == cond]
        if not conds:
            continue
        p1 = metrics.mean([c["precision_at_1"] for c in conds])
        mrr = metrics.mean([c["reciprocal_rank"] for c in conds])
        fab = metrics.mean([c["fabrication_rate"] for c in conds])
        print(f"  {cond:<13}: P@1={_fmt(p1)}  MRR={_fmt(mrr)}  fabrication={_fmt(fab)}  (n={len(conds)})")

    outcomes = [r["outcome"] for t in results for r in t["remediations"]]
    if outcomes:
        eff = metrics.remediation_efficacy(outcomes)
        valid = [o for o in outcomes if o != "invalid"]
        print(f"  Remediation efficacy (re-validated) = {_fmt(eff)}  "
              f"({outcomes.count('fixed')}/{len(valid)} fixed)")


def _fmt(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.3f}"


# ── single-process path (lean E1/E2 + dry runs) ───────────────────────

def run_single_process(cfg: dict, options: dict, out: Path, *,
                       do_exploit: bool, do_remediation: bool) -> list[dict]:
    """Run all phases in one process. Used when there is no OOM risk
    (--no-exploit and/or --skip-remediation)."""
    state_path = out.with_suffix(".state.json")
    phase_oracle(cfg, state_path, do_exploit=do_exploit)
    phase_recommend(cfg, state_path, options=options)
    if do_remediation and do_exploit:
        phase_remediate(cfg, state_path, options=options)
    return _load_state(state_path)["targets"]


# ── entrypoint ────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ASHEN closed-loop evaluation harness")
    ap.add_argument("--config", required=True, type=Path, help="targets JSON")
    ap.add_argument("--out", type=Path, default=Path("eval/results"),
                    help="output path prefix (default eval/results)")
    ap.add_argument("--no-exploit", action="store_true",
                    help="skip live exploits; use config's expected_vulnerable")
    ap.add_argument("--skip-remediation", action="store_true",
                    help="run E1/E2 only, no manual remediation loop")
    ap.add_argument("--temperature", type=float, default=DEFAULT_OPTIONS["temperature"])
    ap.add_argument("--seed", type=int, default=DEFAULT_OPTIONS["seed"])
    ap.add_argument("--phase", choices=["oracle", "recommend", "remediate"],
                    help="internal: run a single phase against --state (set by the orchestrator)")
    ap.add_argument("--state", type=Path, help="internal: phase state file")
    args = ap.parse_args(argv)

    cfg = json.loads(args.config.read_text())
    options = {"temperature": args.temperature, "seed": args.seed}

    # Internal single-phase invocation (spawned by orchestrate()).
    if args.phase:
        if args.phase == "oracle":
            phase_oracle(cfg, args.state, do_exploit=not args.no_exploit)
        elif args.phase == "recommend":
            phase_recommend(cfg, args.state, options=options)
        elif args.phase == "remediate":
            phase_remediate(cfg, args.state, options=options)
        return 0

    do_exploit = not args.no_exploit
    do_remediation = not args.skip_remediation

    # A full live run (real exploits + remediation) is the OOM case -> phase-split
    # across subprocesses. Everything else is safe to run in one process.
    if do_exploit and do_remediation:
        results = orchestrate(args.config, options, args.out,
                              do_exploit=do_exploit, do_remediation=do_remediation)
    else:
        results = run_single_process(cfg, options, args.out,
                                     do_exploit=do_exploit, do_remediation=do_remediation)

    print("\n=== SUMMARY ===")
    print_summary(results)
    write_outputs(results, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
