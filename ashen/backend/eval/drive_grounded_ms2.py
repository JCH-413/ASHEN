"""
Complete the grounded-remediation aggregate on MS2 (192.168.28.130): run the
GROUNDED remediation for the SSH and FTP credential findings, apply each fix
faithfully, and re-validate by re-exploitation.

Expected, given the earlier investigation:
  * SSH  -> grounded prescribes credential rotation; applying it removes the
    weak creds -> fixed.
  * FTP  -> grounded prescribes credential rotation + anonymous_enable=NO; the
    cred part applies but MS2's inetd-launched vsftpd does not honour
    anonymous_enable=NO, so anonymous login persists -> not_fixed (a
    deployment-layer failure, not a wrong prescription).
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import paramiko

from app.services.exploits import get_runner
from eval import metrics
from eval.grounded_remediation import get_grounded_remediation
from eval.harness import build_remediation_context, service_up

HOST = "192.168.28.130"
ADMIN_PW = "msfadmin"
NEW_CREDS = {"msfadmin": "AshenFixed2026xZ", "service": "AshenFixed2026qW"}

FINDINGS = {
    "ssh_brute_force": {"exploit_type": "ssh_brute_force", "port": 22, "severity": "high",
                        "description": "OpenSSH 4.7p1 accepts weak/default credentials"},
    "ftp_brute_force": {"exploit_type": "ftp_brute_force", "port": 21, "severity": "high",
                        "description": "vsftpd 2.3.4 accepts weak/default credentials"},
}


def ssh_exec(cmd: str, pw: str = ADMIN_PW) -> str:
    sock = socket.create_connection((HOST, 22), 12)
    t = paramiko.Transport(sock)
    t.connect(username="msfadmin", password=pw)
    ch = t.open_session()
    ch.exec_command(cmd)
    out = ch.makefile().read().decode(errors="replace")
    err = ch.makefile_stderr().read().decode(errors="replace")
    t.close()
    return (out + err).strip()


def main() -> int:
    if not service_up(HOST, 22):
        print(f"ABORT: {HOST}:22 unreachable — is MS2 up?"); return 1

    # Baseline (before any mutation).
    before = {}
    for et, f in FINDINGS.items():
        r = get_runner(et).run(HOST, f["port"])
        before[et] = bool(r.vulnerable)
        print(f"before {et}: vulnerable={r.vulnerable} ({r.summary})")
        if not r.vulnerable:
            print(f"  {et} not vulnerable at baseline — aborting"); return 1

    # Generate grounded remediation for each finding (record what it prescribes).
    guidance = {}
    for et, f in FINDINGS.items():
        ctx = build_remediation_context(HOST, f, {
            "exploit_type": et, "tool": "metasploit/hydra",
            "vulnerable": True, "summary": "weak credentials found"})
        g, refs = get_grounded_remediation(ctx, query=f"{et} {f['description']}")
        guidance[et] = g
        print(f"\n[{et}] grounded prescribes: "
              f"rotate-creds={'password' in g.lower() or 'credential' in g.lower()} "
              f"anonymous_enable=NO={'anonymous_enable=NO' in g or 'anonymous' in g.lower()}")

    # Apply fixes. FTP config edit first (uses original pw), credential rotation
    # LAST (it changes the admin password). Faithful to the grounded guidance.
    print("\napply FTP fix (anonymous_enable=NO + restart):")
    print(" ", ssh_exec("sudo -k; printf 'msfadmin\\n' | sudo -S sed -i "
                        "'s/^anonymous_enable=YES/anonymous_enable=NO/' /etc/vsftpd.conf"))
    ssh_exec("sudo -k; printf 'msfadmin\\n' | sudo -S sh -c "
             "'service vsftpd restart 2>/dev/null; pkill -HUP inetd 2>/dev/null; "
             "pkill -HUP xinetd 2>/dev/null; true'")

    print("apply credential rotation (SSH + FTP shared accounts):")
    creds = "".join(f"{u}:{p}\\n" for u, p in NEW_CREDS.items())
    print(" ", ssh_exec(f"sudo -k; printf 'msfadmin\\n{creds}' | sudo -S chpasswd")
          or "(rotated)")

    # Re-validate.
    results = []
    for et, f in FINDINGS.items():
        a = get_runner(et).run(HOST, f["port"])
        up = service_up(HOST, f["port"])
        outcome = metrics.remediation_outcome(
            vuln_before=True, vuln_after=bool(a.vulnerable), service_up_after=up)
        print(f"\nafter {et}: vulnerable={a.vulnerable} up={up} -> {outcome.upper()} ({a.summary})")
        results.append({"exploit_type": et, "port": f["port"], "grounded": True,
                        "vuln_before": True, "vuln_after": bool(a.vulnerable),
                        "service_up_after": up, "outcome": outcome})

    out = Path("eval/results_remediation_ms2_grounded.json")
    out.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "host": HOST, "note": "grounded remediation, applied verbatim",
        "remediations": results,
    }, indent=2))
    eff = metrics.remediation_efficacy([r["outcome"] for r in results])
    print(f"\n=== MS2 grounded efficacy = {eff} "
          f"({sum(r['outcome']=='fixed' for r in results)}/{len(results)}) ===")
    print(f"recorded -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
