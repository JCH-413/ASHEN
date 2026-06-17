"""
process.py
The one deep module that owns external-process lifecycle.

Every tool ASHEN shells out to — nmap, msfconsole, hydra, curl — runs through
`run()`, which owns the Popen + communicate(timeout) + kill-on-timeout dance and
registers the process for external cancellation under a caller-supplied `token`.

The module owns the *process*, not the caller's temp files: nmap's XML and the
exploit adapters' credential files are cleaned up by whoever created them. The
token is an opaque, namespaced string (e.g. "scan:42", "exploit:7") so the two
id spaces never collide in the registry.
"""
from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass
from typing import Optional

# ── cancellation registry ────────────────────────────────────────────
_lock = threading.Lock()
_active: dict[str, subprocess.Popen] = {}   # token → live Popen
_cancelled: set[str] = set()                # tokens whose run was cancelled


@dataclass
class ProcOutcome:
    """Result of one external process run. Callers interpret it per tool."""

    stdout: str
    stderr: str
    returncode: int
    timed_out: bool
    cancelled: bool


def register(token: str, proc: subprocess.Popen) -> None:
    with _lock:
        _active[token] = proc


def unregister(token: str) -> None:
    with _lock:
        _active.pop(token, None)


def cancel(token: str) -> bool:
    """Terminate the process registered under `token`. True if one was killed."""
    with _lock:
        proc = _active.pop(token, None)
        if proc is not None:
            _cancelled.add(token)
    if proc is None:
        return False
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        return True
    except OSError:
        return False


def run(cmd: list[str], *, timeout: int, token: Optional[str] = None) -> ProcOutcome:
    """Run `cmd`, enforcing `timeout` and (if `token` given) honouring cancellation."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if token is not None:
        register(token, proc)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        timed_out = True
    finally:
        was_cancelled = False
        if token is not None:
            with _lock:
                was_cancelled = token in _cancelled
                _cancelled.discard(token)
            unregister(token)
    return ProcOutcome(
        stdout=out.decode(errors="replace") if out else "",
        stderr=err.decode(errors="replace") if err else "",
        returncode=proc.returncode,
        timed_out=timed_out,
        cancelled=was_cancelled,
    )
