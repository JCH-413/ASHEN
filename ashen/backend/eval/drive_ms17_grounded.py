"""
Re-validate the GROUNDED MS17-010 remediation on MS3 (192.168.28.132).

The grounded remediation (eval.grounded_remediation, backed by the curated
remediation corpus) prescribes the correct, effective control:
    reg add "...\\LanmanServer\\Parameters" /v SMB1 /t REG_DWORD /d 0 /f  + reboot
We apply that verbatim and re-run the ms17_010 oracle. Expected: the host is no
longer vulnerable -> `fixed` (vs the ungrounded fix, which scored `not_fixed`).
"""
from __future__ import annotations

import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

import paramiko

from app.services.exploits import get_runner
from eval import metrics
from eval.harness import service_up

HOST = "192.168.28.132"
USER, PW = "vagrant", "vagrant"

# The GROUNDED remediation's prescribed command (correct SMB1=0 control).
GROUNDED_FIX = (
    r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" '
    r'/v SMB1 /t REG_DWORD /d 0 /f'
)


def ssh(cmd: str) -> str:
    sock = socket.create_connection((HOST, 22), 12)
    t = paramiko.Transport(sock)
    t.connect(username=USER, password=PW)
    ch = t.open_session()
    ch.exec_command(cmd)
    out = ch.makefile().read().decode(errors="replace")
    err = ch.makefile_stderr().read().decode(errors="replace")
    t.close()
    return (out + err).strip()


def wait_for_reboot() -> bool:
    t0 = time.time()
    while time.time() - t0 < 120:
        if not service_up(HOST, 445):
            break
        time.sleep(5)
    t0 = time.time()
    while time.time() - t0 < 420:
        if service_up(HOST, 445):
            time.sleep(20)
            return True
        time.sleep(5)
    return False


def main() -> int:
    # Reachability guard: a down host makes the oracle report "not vulnerable",
    # which would be a false negative. Confirm 445 is reachable first.
    if not service_up(HOST, 445):
        print(f"ABORT: {HOST}:445 unreachable — is MS3 powered on? "
              "(a down host would falsely read as 'not vulnerable')")
        return 1
    r = get_runner("ms17_010_check").run(HOST, 445)
    print(f"ORACLE before: vulnerable={r.vulnerable} ({r.summary})")
    if not r.vulnerable:
        print("not vulnerable before — nothing to validate "
              "(host reachable, so this is a genuine verdict)"); return 1

    print(f"\napply GROUNDED fix verbatim:\n  {GROUNDED_FIX}")
    print("  result:", ssh(GROUNDED_FIX))
    print("  verify key:", ssh(
        r'reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1'))

    print("\nrebooting MS3 ...")
    try:
        ssh("shutdown /r /t 0")
    except Exception as e:
        print("  (ssh dropped on reboot, expected):", str(e)[:60])
    if not wait_for_reboot():
        print("ABORT: MS3 did not come back within timeout"); return 1
    print("MS3 back up.")

    after = get_runner("ms17_010_check").run(HOST, 445)
    up = service_up(HOST, 445)
    outcome = metrics.remediation_outcome(
        vuln_before=True, vuln_after=bool(after.vulnerable), service_up_after=up)
    print(f"\nORACLE after: vulnerable={after.vulnerable} service_up={up} -> {outcome.upper()} ({after.summary})")

    out = Path("eval/results_remediation_ms3_grounded.json")
    out.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "host": HOST, "exploit_type": "ms17_010_check",
        "applied_fix": GROUNDED_FIX, "note": "GROUNDED remediation (SMB1=0), verbatim",
        "vuln_before": True, "vuln_after": bool(after.vulnerable),
        "service_up_after": up, "outcome": outcome,
    }, indent=2))
    print(f"recorded: {outcome}  ->  {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
