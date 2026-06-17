"""
SSH-driven MS17-010 remediation on MS3 (192.168.28.132), applying ASHEN's
EXACT prescribed fix verbatim, then re-validating by re-exploitation.

ASHEN's generated remediation prescribes:
    reg add "...\\LanmanServer\\Parameters" /v DisableSMBv1 /t REG_DWORD /d 1 /f
We apply that literal command (faithful application), reboot so any SMB server
change would take effect, and re-run the ms17_010 oracle. The honest measurement
is whether ASHEN's fix-as-written removes the vulnerability.
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

# ASHEN's exact prescribed command (verbatim, including the wrong value name).
ASHEN_FIX = (
    r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" '
    r'/v DisableSMBv1 /t REG_DWORD /d 1 /f'
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
    """Wait for 445 to drop (reboot starting) then return (back up)."""
    t0 = time.time()
    while time.time() - t0 < 120:          # wait until it goes down
        if not service_up(HOST, 445):
            break
        time.sleep(5)
    t0 = time.time()
    while time.time() - t0 < 420:          # wait until it comes back
        if service_up(HOST, 445):
            time.sleep(20)                 # settle
            return True
        time.sleep(5)
    return False


def main() -> int:
    r = get_runner("ms17_010_check").run(HOST, 445)
    print(f"ORACLE before: vulnerable={r.vulnerable} ({r.summary})")
    if not r.vulnerable:
        print("not vulnerable before — aborting"); return 1

    print(f"\napply ASHEN fix verbatim:\n  {ASHEN_FIX}")
    print("  result:", ssh(ASHEN_FIX))
    print("  verify key:", ssh(
        r'reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v DisableSMBv1'))

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

    out = Path("eval/results_remediation_ms3.json")
    out.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "host": HOST, "exploit_type": "ms17_010_check",
        "applied_fix": ASHEN_FIX, "note": "ASHEN's exact prescribed command (verbatim)",
        "vuln_before": True, "vuln_after": bool(after.vulnerable),
        "service_up_after": up, "outcome": outcome,
    }, indent=2))
    print(f"recorded: {outcome}  ->  {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
