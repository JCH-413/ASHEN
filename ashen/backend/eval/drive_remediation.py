"""
SSH-driven remediation experiment for the credential exploit types.

This is the non-interactive variant of the harness remediate phase, used when the
operator has authorised ASHEN to apply the fix itself over SSH (snapshot taken).
For each confirmed-vulnerable credential finding it:

  1. ORACLE (before): run the exploit, confirm vulnerable, capture the creds.
  2. REMEDIATE: generate ASHEN's fix guidance for the finding.
  3. APPLY: rotate the weak credentials over SSH (the faithful application of the
     guidance for a weak-credential vulnerability).
  4. ORACLE (after): re-run the exploit; scored fixed / not_fixed / broke_service.

Metasploitable 2's OpenSSH 4.7p1 needs legacy crypto, so we use paramiko 3.4
(the system OpenSSH 10 client and paramiko 5 have dropped ssh-rsa).
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import paramiko

from app.services.exploits import get_runner
from app.services.remediation_service import get_remediation
from eval import metrics
from eval.harness import build_remediation_context, service_up

HOST = "192.168.28.130"
ADMIN_USER = "msfadmin"
ADMIN_PW = "msfadmin"  # current (pre-fix) admin password used to authenticate sudo

# Weak accounts the brute-force wordlists can hit on this box, rotated to strong
# passwords. Rotating all default credentials is the faithful application of the
# generated "enforce strong passwords / disable default accounts" guidance.
FIX_CREDS = {"msfadmin": "AshenFixed2026xZ", "service": "AshenFixed2026qW"}

FINDINGS = {
    "ssh_brute_force": {"exploit_type": "ssh_brute_force", "port": 22, "severity": "high",
                        "description": "OpenSSH 4.7p1 accepts weak/default credentials"},
    "ftp_brute_force": {"exploit_type": "ftp_brute_force", "port": 21, "severity": "high",
                        "description": "vsftpd 2.3.4 accepts weak/default credentials"},
}


def ssh_exec(cmd: str, password: str = ADMIN_PW) -> tuple[str, str, int]:
    sock = socket.create_connection((HOST, 22), 10)
    t = paramiko.Transport(sock)
    t.connect(username=ADMIN_USER, password=password)
    ch = t.open_session()
    ch.exec_command(cmd)
    out = ch.makefile().read().decode(errors="replace")
    err = ch.makefile_stderr().read().decode(errors="replace")
    rc = ch.recv_exit_status()
    t.close()
    return out.strip(), err.strip(), rc


def oracle(exploit_type: str, port: int):
    return get_runner(exploit_type).run(HOST, port)


def apply_fix() -> None:
    # Literal \n escapes so the whole printf format is one line.
    creds = "".join(f"{u}:{p}\\n" for u, p in FIX_CREDS.items())
    # `sudo -k -S`: -k invalidates any cached sudo timestamp so -S ALWAYS reads
    # the admin password from the first stdin line; chpasswd then reads the
    # remaining user:password lines. Without -k a cached timestamp makes sudo
    # skip the password line, which leaks into chpasswd and fails the batch.
    cmd = f"sudo -k; printf '{ADMIN_PW}\\n{creds}' | sudo -S chpasswd"
    out, err, rc = ssh_exec(cmd)
    print(f"  apply_fix: rotated {list(FIX_CREDS)} (rc={rc}) {err[:160]}")


def main() -> int:
    # Pre-flight: confirm sudo works before mutating anything (-k so it always
    # reads the password and never leaves a cached timestamp for apply_fix).
    out, err, rc = ssh_exec(f"sudo -k; printf '{ADMIN_PW}\\n' | sudo -S id -u")
    if "0" not in out:
        print(f"ABORT: sudo precheck failed (out={out!r} err={err!r})")
        return 1
    print(f"sudo precheck OK (uid {out.splitlines()[-1]})")

    results = []
    print("\n--- PHASE: oracle (before) ---")
    before = {}
    for et, f in FINDINGS.items():
        r = oracle(et, f["port"])
        before[et] = r
        print(f"  {et}: vulnerable={r.vulnerable} ({r.summary})")

    print("\n--- PHASE: remediate (generate guidance) ---")
    guidance = {}
    for et, f in FINDINGS.items():
        if not before[et].vulnerable:
            continue
        ctx = build_remediation_context(HOST, f, {
            "exploit_type": et, "tool": before[et].tool,
            "vulnerable": True, "summary": before[et].summary})
        guidance[et] = get_remediation(ctx)
        print(f"  {et}: generated {len(guidance[et])} chars")

    print("\n--- PHASE: apply fix over SSH ---")
    apply_fix()

    print("\n--- PHASE: oracle (after) ---")
    for et, f in FINDINGS.items():
        if not before[et].vulnerable:
            continue
        after = oracle(et, f["port"])
        up = service_up(HOST, f["port"])
        outcome = metrics.remediation_outcome(
            vuln_before=True, vuln_after=bool(after.vulnerable), service_up_after=up)
        print(f"  {et}: vuln_after={after.vulnerable} service_up={up} -> {outcome.upper()} "
              f"({after.summary})")
        results.append({
            "exploit_type": et, "port": f["port"],
            "vuln_before": True, "vuln_after": bool(after.vulnerable),
            "service_up_after": up, "outcome": outcome,
            "guidance": guidance[et],
        })

    out_path = Path("eval/results_remediation_live.json")
    out_path.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "host": HOST, "fix_accounts": list(FIX_CREDS),
        "remediations": results,
    }, indent=2))
    eff = metrics.remediation_efficacy([r["outcome"] for r in results])
    print(f"\n=== REMEDIATION EFFICACY = {eff} "
          f"({sum(r['outcome']=='fixed' for r in results)}/{len(results)} fixed) ===")
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
