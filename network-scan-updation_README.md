# Network Scan Module Updation and Minor Changes

Main focus today: Network Scan module.

## Quick Scope

- Meaningful tracked files changed: 28
- Meaningful new files/folders added: 8
- Main areas touched: scan lifecycle, scan UX, vulnerability/exploit API contracts, security hardening (CSRF + rate limit), and tests

## Main Focus: Network Scan Module

### Backend scan lifecycle improvements

- Added scan progress and error details to the data model:
  - `progress` (0-100)
  - `error_detail` (safe/truncated message)
- Added migration for scan and exploit schema updates:
  - adds `scan.progress`
  - adds `scan.error_detail`
  - changes `exploit.raw_output` from `JSONB` to `JSON` for compatibility
- `POST /scan/start` now:
  - enforces per-user rate limiting
  - prevents duplicate active scans (`queued`/`running`) for the same target
- `GET /scan/status/{scan_id}` now:
  - enforces ownership for non-admin users
  - returns lightweight payload while queued/running
  - includes `progress` and `error_detail`
- Added `POST /scan/cancel/{scan_id}`:
  - owner/admin only
  - allowed only for `queued`/`running`
  - marks scan `cancelled`
  - attempts to terminate active nmap subprocess
- `GET /scan/history` now supports pagination and returns:
  - `items`, `total`, `skip`, `limit`

### Scan execution and scanner engine

- `scan_executor` now:
  - tracks cancellation safely during retries and status updates
  - updates progress across phases (queued/running/completed)
  - preserves cancellation as terminal state in race conditions
  - surfaces extraction failures by switching to `completed_with_errors`
  - appends extraction failure details into results payload
  - writes audit entries for attempts, completion, cancellation, and extraction outcomes
- `nmap_scanner` now:
  - uses unique temp XML file per run (prevents collisions)
  - tracks subprocesses by `scan_id` for cancellation
  - uses `Popen` for process control
  - exposes kill helpers (`register`, `unregister`, `kill`)
  - guarantees temp file cleanup on success/failure/parse issues

### Frontend network scan UX and controls

- `NetworkScans` page major refactor:
  - client-side IP validation for scan start, scan request, and exploit target
  - paginated scan history with next/prev controls
  - click running/queued rows to jump into live monitor
  - live monitor now uses backend progress percentage
  - cancel button for active scans
  - better polling resilience with retry/error notice
  - supports `completed_with_errors` and displays extraction warnings
  - vulnerability table now supports:
    - pagination
    - filters (`severity`, `port`, `scan_id`)
    - expandable raw output details
  - exploit type list now fetched from backend (`/exploit/types`) with fallback

## Related API and Contract Changes

- Frontend API client updates:
  - base URL now supports:
    - `VITE_API_BASE_URL`, or
    - `/api` in dev mode, or
    - same-host `:8000` fallback in prod
  - adds `X-CSRF-Token` header for JSON and SSE requests
  - scan status type includes `progress` and `error_detail`
  - scan history and vuln list now use paginated response shape
  - added `scans.cancel()` and `exploits.types()`
  - vuln listing supports query filters/pagination

- Vulnerability endpoints:
  - ownership checks for `by-scan`
  - paginated/filterable `/vulns/all`
  - returns `raw_output` for detail expansion

- Exploit endpoints:
  - exploit rate limiting
  - target IP format validation
  - exploit target must be admin-authorized
  - analysts can only view their own exploit history/results
  - added backend-driven exploit types endpoint

## Security Hardening Added Today

- Added CSRF middleware:
  - requires `X-CSRF-Token` for state-changing methods
  - exempts login endpoints
  - can be disabled for tests via env (`CSRF_ENABLED=false`)
- Added rate limiter module:
  - scan and exploit limits per user email
  - Redis backend when available
  - in-memory fallback when Redis is absent/fails
- Added Redis dependency in backend requirements
- Expanded CORS allowlist entries for localhost/127.0.0.1 variants and LAN dev host

## Database and Alembic Updates

- Alembic environment now imports `Exploit` and `Report` models
- Added migration:
  - `a90596a1457f_add_scan_progress_and_error_detail.py`

## Tests Added/Updated

- Updated existing tests for paginated API responses and cancellation race behavior
- Added new phase-based coverage:
  - Phase 1 security behaviors
  - Phase 2 validation and cancellation flows
  - Phase 3 pagination/filter/progress/exploit types
  - Risk mitigation tests (rate fallback, subprocess kill, CSRF behavior)

## Frontend Secondary Updates

- Added custom app icon and wired it in:
  - favicon link updated in `index.html`
  - sidebar logo uses `frontend/icon/ashen-icon.png`
- Added Vite dev proxy:
  - `/api` -> backend `127.0.0.1:8000`
- Updated pages (`Dashboard`, `DataLogs`, `AttackRecommendations`, `RemediationGuidance`, `Reports`) to consume paginated APIs

## Full Meaningful File Inventory

### Modified

- `ashen/backend/ai_logs.json`
- `ashen/backend/alembic/env.py`
- `ashen/backend/app/api/exploits.py`
- `ashen/backend/app/api/scans.py`
- `ashen/backend/app/api/vulns.py`
- `ashen/backend/app/main.py`
- `ashen/backend/app/models/exploit.py`
- `ashen/backend/app/models/scan.py`
- `ashen/backend/app/schemas/admin_schema.py`
- `ashen/backend/app/schemas/scan_schema.py`
- `ashen/backend/app/services/scan_executor.py`
- `ashen/backend/app/services/scanner/nmap_scanner.py`
- `ashen/backend/requirements.txt`
- `ashen/backend/tests/conftest.py`
- `ashen/backend/tests/test_scan_executor.py`
- `ashen/backend/tests/test_scans.py`
- `ashen/backend/tests/test_vulns.py`
- `ashen/frontend/index.html`
- `ashen/frontend/package-lock.json`
- `ashen/frontend/src/components/AppSidebar.tsx`
- `ashen/frontend/src/lib/api.ts`
- `ashen/frontend/src/pages/AttackRecommendations.tsx`
- `ashen/frontend/src/pages/Dashboard.tsx`
- `ashen/frontend/src/pages/DataLogs.tsx`
- `ashen/frontend/src/pages/NetworkScans.tsx`
- `ashen/frontend/src/pages/RemediationGuidance.tsx`
- `ashen/frontend/src/pages/Reports.tsx`
- `ashen/frontend/vite.config.ts`

### Added

- `ashen/backend/alembic/versions/a90596a1457f_add_scan_progress_and_error_detail.py`
- `ashen/backend/app/core/csrf.py`
- `ashen/backend/app/core/rate_limit.py`
- `ashen/backend/tests/test_phase1_security.py`
- `ashen/backend/tests/test_phase2_error_handling.py`
- `ashen/backend/tests/test_phase3_ux.py`
- `ashen/backend/tests/test_risk_mitigations.py`
- `ashen/frontend/icon/ashen-icon.png`

## Notes Before Commit

- Current working tree also contains generated/runtime artifacts (`__pycache__`, `.pyc`, local `.db`) that are not listed above.
- Review staging carefully so only intended source/config/test/icon changes are committed.
