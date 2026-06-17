# ASHEN Evaluation Harness

The closed **detect → recommend → remediate → re-validate** loop used to produce
the paper's numbers. It drives ASHEN's real services directly (no web/auth/DB
layer) so runs are reproducible.

## Experiments produced

| ID | Claim | Metric | Ground truth |
|----|-------|--------|--------------|
| **Headline** | ASHEN's generated fixes actually eliminate confirmed vulnerabilities | remediation efficacy = % of confirmed vulns that no longer validate after the fix is applied (and service still up) | re-running the exploit (oracle) |
| **E2** | The recommended exploitation order ranks the working exploit first | Precision@1, MRR | exploit runner `vulnerable` verdict |
| **E1** | Grounding affects ranking + hallucination | Precision@1, MRR, fabrication across 3 conditions | oracle verdict + `valid_cves` |

E1 compares three grounding conditions (`CONDITIONS` in `harness.py`):
`off` (no retrieval), `plain` (dump retrieved CVEs into the prompt — current app
behaviour), and `action_aware` (map retrieved CVEs onto available exploit types
via `eval/grounding.py` before prompting).

## Prerequisites

- Run from `ashen/backend`. The backend deps live in the repo-root venv:
  `/home/jch413/Documents/fyp-2/.venv` (not `ashen/backend/.venv`).
- Ollama running with the model pulled (`llama3.2` by default; `OLLAMA_MODEL` to override).
- **CPU-only inference is slow** (~90s per generation on this box). Set
  `OLLAMA_TIMEOUT` (seconds) above the default 120, e.g. `OLLAMA_TIMEOUT=600`.
  For a faster (weaker) baseline model, `OLLAMA_MODEL=tinyllama`.
- Exploit tools installed (`nmap`, `hydra`, `msfconsole`) — already present on Kali.
- One or more vulnerable target VMs reachable on the network. **Snapshot each VM
  before running the remediation loop** — applying fixes is destructive.

## Run

```bash
cd ashen/backend
cp eval/targets.example.json eval/targets.json   # then edit IPs/findings
PY=/home/jch413/Documents/fyp-2/.venv/bin/python

# Pipeline dry-run — no VMs touched, exercises recommendation + parsing + metrics:
OLLAMA_TIMEOUT=600 $PY -m eval.harness --config eval/targets.json --no-exploit --skip-remediation

# E1 + E2 only (live exploits as oracle, no manual remediation):
OLLAMA_TIMEOUT=600 $PY -m eval.harness --config eval/targets.json --skip-remediation

# Full closed loop (pauses for you to apply each fix by hand, then re-tests):
OLLAMA_TIMEOUT=600 $PY -m eval.harness --config eval/targets.json --out eval/results
```

## Memory: full runs are phase-split (OOM-safe)

A full live run loads torch (retrieval), Ollama, and msfconsole. On a small host
(≈6 GB) those together OOM-kill the process, because Python never releases torch
once loaded. So a **full run** (live exploits **and** remediation) is split into
three phases, each executed as its own subprocess, so the OS reclaims memory
between them — torch is only ever loaded in the recommend phase, never alongside
msfconsole:

1. `oracle`    — run exploits, establish ground truth (no torch).
2. `recommend` — retrieve + generate under the 3 conditions (torch + Ollama).
3. `remediate` — generate fix, pause for the operator, re-validate (Ollama then
   msfconsole, no torch).

The orchestration is automatic; `--phase`/`--state` are internal flags it sets
on the subprocesses. Lean runs (`--no-exploit` and/or `--skip-remediation`) have
no OOM risk and run in a single process. If a phase fails, the state file
(`<out>.state.json`) is preserved so the run can be inspected/resumed.

## Output

- `eval/results.json` — full record (prompts, raw model output, every verdict).
- `eval/results.csv` — one row per (target, grounding condition): ranking + fabrication.
- `eval/results_remediation.csv` — one row per remediation trial: the headline.
- `eval/results.state.json` — intermediate phase state (safe to delete after a run).

## Config

`targets.json` (see `targets.example.json`):

- `valid_cves` — CVE ids that are real **and** apply to your targets' services.
  A recommended CVE outside this set counts as a fabrication.
- per target: `scan_context_lines` (the open-port facts fed to the recommender)
  and `findings` (the `exploit_type` + `port` the oracle runs).
- `expected_vulnerable` on a finding is only used by `--no-exploit` dry-runs.

## Reproducibility & the variance study

Generation defaults to `temperature=0, seed=42`. For the variance study (each
condition ≥5×), loop over `--seed` with a non-zero `--temperature`, e.g.:

```bash
for s in 1 2 3 4 5; do
  python -m eval.harness --config eval/targets.json --skip-remediation \
    --temperature 0.7 --seed $s --out eval/run_seed_$s
done
```

## Limitations (state these in the paper)

- Only 4 exploit types ⇒ ranking depth is shallow; statistical power comes from
  many targets, not deep rankings. With 1–2 VMs this is a **feasibility pilot**,
  not a significance claim.
- Remediation is applied **manually**; the system generates prose, it does not
  auto-remediate. Outcome scoring (`fixed` / `not_fixed` / `broke_service`) is in
  `metrics.remediation_outcome`.
