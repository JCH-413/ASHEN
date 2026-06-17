# ADR 0005 — A Scan lifecycle module owns transitions and extraction

- **Status:** Accepted
- **Date:** 2026-06-12

## Context

Scan status was written in three places. `_update_scan_status` and `_finalize_scan`
(in `scan_executor`) each carried the same cancel-race guard — "a user cancellation
is terminal; a worker update must never flip it back" — yet the cancel route wrote
`scan.status = "cancelled"` **directly**, bypassing both. Vulnerability extraction
was welded into finalisation and was append-only, so re-running Severity inference
required re-scanning *and* would have duplicated rows.

## Decision

Introduce `app/services/scan_lifecycle.py` as the one owner of status transitions
and extraction:

- `mark_status()`, `finalize()`, and `cancel()` share a single guard helper
  (`_cancel_is_sticky`); the cancel route now calls `cancel()` instead of writing
  status directly, so there is no bypass.
- `extract_vulnerabilities(..., replace=True)` is a re-runnable, idempotent step
  keyed by Scan: it clears the Scan's prior `Vulnerability` rows, re-reads stored
  results (unwrapping the `completed_with_errors` envelope), re-infers Severity, and
  re-inserts. A new `POST /scan/{id}/re-extract` route exposes this so a
  Severity-logic fix can be applied to a stored Scan without re-scanning.

`scan_executor` keeps `_update_scan_status` / `_finalize_scan` /
`_extract_vulnerabilities` as aliases to the new module, preserving its internal
call sites and existing imports.

## Consequences

- The cancel-race guard lives in one place; adding a new status writer can't
  reintroduce the bypass.
- Severity logic is testable on stored output, and re-extraction is dedup-safe.
- `/re-extract` is owner/admin-only and valid only for completed scans; on success
  it promotes `completed_with_errors` back to `completed`.
- Status side governed here; the subprocess side is [ADR 0002](0002-process-module.md).
