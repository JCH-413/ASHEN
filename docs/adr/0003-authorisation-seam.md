# ADR 0003 — Authorisation enforced at one seam (require_action)

- **Status:** Accepted
- **Date:** 2026-06-12

## Context

Four checks guarded the offensive and AI endpoints:

1. **Actor** — the caller must be an Analyst (offensive actions are Analyst-only).
2. **Target gate** — the target IP (or a Scan's target) must be an *authorised*
   `TargetSystem`.
3. **Disclaimer** — the ethical-use acknowledgement must be present.
4. **Rate** — a per-Analyst sliding window.

These were copy-pasted preambles across `scans` / `exploits` / `ai` / `reports`,
and they had already **drifted**: the AI routes skipped the actor check, the target
gate, and rate limiting entirely, and `reports` skipped actor + rate. Policy lived
in N routes and was diverging.

## Decision

A single FastAPI dependency factory, `app/core/authz.py::require_action(...)`,
enforces the requested subset of the four checks in a fixed order (actor →
disclaimer → target gate → rate). Each route declares exactly what it needs via one
`Depends(require_action(...))`; its body carries business logic only. The target
gate has two flavours: `_gate_target_ip` (raw IP, rejects malformed IPs with 422)
and `_gate_scan_target` (resolves a Scan to its authorised target). Disclaimer
truthiness is normalised across JSON bools and query-string strings.

We **closed the drift**: the AI generation routes and `reports.generate` were
brought up to full policy — Analyst-only + rate-limited, and the
`recommend-attacks` routes additionally gate on the Scan's target.

## Consequences

- Security policy stops leaking into routes; it is audited by reading one module.
- New routes opt into policy by construction, so the drift cannot silently recur.
- **Contract change (intentional):** Admins can no longer call the AI or reports
  endpoints (they now receive 403), and AI advice requires the Scan's target to
  still be authorised. This is deliberate — do not "fix" the 403 by loosening the
  actor check. If an admin-facing feature needs AI/reports, give it an explicit,
  separately-reasoned policy rather than reverting this seam.
- The seam is tested once (actor/gate/disclaimer/rate in isolation) plus thin
  per-route wiring assertions, instead of repeating the four assertions per route.
