# ADR 0002 — A deep process module owns external-process lifecycle

- **Status:** Accepted
- **Date:** 2026-06-12

## Context

Timeout, cancellation, and subprocess cleanup were re-implemented in every
external-tool caller: `nmap_scanner` had its own PID registry + timeout + XML
cleanup, while each Exploit adapter called `subprocess.run` with its own timeout
and no cancellation at all. Only the Scan path could actually be cancelled;
Exploit Runs could not, and their temp files leaked.

## Decision

A single module, `app/services/process.py`, owns external-process lifecycle behind
`run(cmd, *, timeout, token) -> ProcOutcome`. It registers the process for
cancellation, enforces the timeout, and reports a structured outcome
(`stdout/stderr/returncode/timed_out/cancelled`). `NmapScanner` and the Exploit
adapters become command-builders that cross this one interface.

Cancellation is keyed by a **namespaced token** (`scan:<id>` / `exploit:<id>`) so
the two pipelines can't collide on a shared integer id. `nmap_scanner` keeps thin
`register_scan_process` / `kill_scan_process` shims that delegate to `process`, so
the scan-cancel route and existing tests are unchanged.

## Consequences

- Cancellation and cleanup are fixed once and apply everywhere; Exploit Runs
  become cancellable for free.
- One internal seam to fake in tests (`process.run`), so runner timeout/cancel
  behaviour is tested hermetically.
- A cancelled run reports `cancelled` rather than a bogus verdict.
- One more module in the call path for every external tool — accepted because the
  lifecycle logic would otherwise be duplicated five times.
- Builds on [ADR 0001](0001-exploit-type-seam.md); the Scan-status side is governed
  by [ADR 0005](0005-scan-lifecycle.md).
