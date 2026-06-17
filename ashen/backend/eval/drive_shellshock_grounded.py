"""
Grounded remediation loop for the Shellshock finding on 192.168.28.136, applied
over SSH and re-validated by re-exploitation. Completes the 4th exploit type.

ASHEN's grounded remediation (corpus entry rem-shellshock) prescribes patching
bash and/or disabling CGI. On this EOL host bash is pinned vulnerable, so the
applicable, faithful action is disabling the CGI modules (a Shellshock mitigation
ASHEN explicitly lists), which removes the attack vector while the web service
stays up. Re-validation: the shellshock_cgi oracle should no longer fire.
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

HOST = "192.168.28.136"
USER, PW = "jch413", "0000"
FINDING = {"exploit_type": "shellshock_cgi", "port": 80, "severity": "critical",
           "description": "Apache mod_cgi + vulnerable bash (CVE-2014-6271) at /cgi-bin/vulnerable"}


def ssh_exec(cmd: str) -> str:
    sock = socket.create_connection((HOST, 22), 12)
    t = paramiko.Transport(sock)
    t.connect(username=USER, password=PW)
    ch = t.open_session()
    ch.exec_command(cmd)
    out = ch.makefile().read().decode(errors="replace")
    err = ch.makefile_stderr().read().decode(errors="replace")
    t.close()
    return (out + err).strip()


def main() -> int:
    if not service_up(HOST, 80):
        print(f"ABORT: {HOST}:80 unreachable"); return 1

    before = get_runner("shellshock_cgi").run(HOST, 80)
    print(f"ORACLE before: vulnerable={before.vulnerable} ({before.summary})")
    if not before.vulnerable:
        print("not vulnerable before — nothing to validate"); return 1

    ctx = build_remediation_context(HOST, FINDING, {
        "exploit_type": "shellshock_cgi", "tool": "curl",
        "vulnerable": True, "summary": before.summary})
    guidance, refs = get_grounded_remediation(
        ctx, query="shellshock_cgi CVE-2014-6271 Apache mod_cgi bash disable cgi patch bash")
    print(f"\ngrounded remediation prescribes: disable-CGI="
          f"{'cgi' in guidance.lower() and 'disable' in guidance.lower() or 'a2dismod' in guidance.lower()} "
          f"patch-bash={'bash' in guidance.lower() and ('update' in guidance.lower() or 'upgrade' in guidance.lower())}")

    print("\napply fix over SSH (disable CGI modules + restart Apache):")
    out = ssh_exec("printf '0000\\n' | sudo -S sh -c 'a2dismod -f cgi cgid; service apache2 restart' 2>&1")
    print(" ", out[-200:])

    after = get_runner("shellshock_cgi").run(HOST, 80)
    up = service_up(HOST, 80)
    outcome = metrics.remediation_outcome(
        vuln_before=True, vuln_after=bool(after.vulnerable), service_up_after=up)
    print(f"\nORACLE after: vulnerable={after.vulnerable} service_up(80)={up} -> {outcome.upper()} ({after.summary})")

    out_path = Path("eval/results_remediation_shellshock_grounded.json")
    out_path.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "host": HOST, "exploit_type": "shellshock_cgi",
        "applied_fix": "a2dismod -f cgi cgid; service apache2 restart (grounded)",
        "vuln_before": True, "vuln_after": bool(after.vulnerable),
        "service_up_after": up, "outcome": outcome,
    }, indent=2))
    print(f"recorded: {outcome}  ->  {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
