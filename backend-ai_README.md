# ```backend-ai``` Branch   

## What Was Built: 

This branch adds the AI engine layer to ASHEN, connecting a locally-running LLM (Ollama + tinyllama) to the existing scan and vulnerability data to provide attack recommendations, remediation guidance, and follow-up chat. It also delivers the reports subsystem (generate, list, preview, download) and refactors the frontend pages that use AI to use persistent singleton stores with SSE streaming.

---

## Commits

| Hash | Summary |
|------|---------|
| `8269727` | Add AI services layer: attack recommender, remediation, safety filter, governance logging |
| `9cb5037` | Upgrade AI engine: SSE streaming, persistent state, exploit-aware attack recommendations |

---

## Backend: New Files

### `app/services/` (new directory)

| File | What it does |
|------|-------------|
| `ollama_client.py` | HTTP client for Ollama. Exposes `generate()` (blocking, returns full string) and `generate_stream()` (yields tokens as they arrive via `httpx` streaming). Raises `AIServiceUnavailableError` when Ollama is not running. Model and URL are configurable via `OLLAMA_MODEL` / `OLLAMA_URL` env vars (defaults: `tinyllama`, `http://localhost:11434/api/generate`). |
| `prompt_templates.py` | Prompt strings for attack recommendation and remediation. Keeps prompt construction out of the route layer. |
| `attack_recommender.py` | `recommend_attacks(context)` and `stream_attack_recommendation(context)`   wrap the Ollama client with the attack prompt template. |
| `remediation_service.py` | `get_remediation(context)` and `stream_remediation(context)`   same pattern for remediation guidance. |
| `safety_filter.py` | Two filter functions: `filter_response()` (strict, for attack output   strips links, "attack technique N" boilerplate, unsafe keywords) and `filter_remediation_response()` (lenient, for remediation   strips only links and unsafe keywords). Blocked responses return a warning string instead. |
| `governance_logger.py` | `log_event(prompt, response, action)`   appends every AI interaction as a JSON record to `ai_logs.json` with a UTC timestamp. |
| `feedback_service.py` | `handle_feedback(prompt, response, action)`   accepts `"accept"`, `"reject"`, or `"regenerate"`. Foundation for a future RLHF loop. |
| `report_builder.py` | `build_report_data(db, scan_id)` assembles scan + target + vulnerabilities + exploits into a dict. `generate_html_report(data)` renders a styled HTML page. `generate_csv_report(data)` renders a CSV string. |

### `app/api/ai.py` (new file)

All routes live under `/ai` and require a valid JWT.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/ai/recommend-attacks` | One-shot attack recommendation. Builds context from scan/vuln DB rows (including prior exploit attempts and the list of ASHEN-available exploits), calls tinyllama, filters output, logs the event, returns JSON. |
| `POST` | `/ai/recommend-attacks/stream` | Same as above but streams tokens back as Server-Sent Events (`event: token`). Governance log and audit log are written after the final token. Ends with `event: done`. |
| `POST` | `/ai/remediate` | One-shot remediation guidance. Context includes vuln details, CVE/state lines from raw scan output, and exploit result summaries. |
| `POST` | `/ai/remediate/stream` | SSE streaming version of remediation. |
| `POST` | `/ai/chat` | One-shot follow-up Q&A. Accepts optional `vuln_id`, `exploit_id`, and `remediation_context` to ground the question. |
| `POST` | `/ai/chat/stream` | SSE streaming version of chat. |
| `POST` | `/ai/review` | Accept / reject / regenerate AI output. Regenerate re-runs the recommendation and returns the new result. |

Context building is done by two helpers:

- `_build_rich_attack_context`   includes target IP, all open ports and vulnerability descriptions, prior exploit results, and the four available ASHEN exploit types so the LLM can recommend only what the system can actually run.
- `_build_rich_remediation_context`   includes vuln details, a filtered subset of raw scan output (CVE lines, state lines), and exploit result summaries.

### `app/api/reports.py` (new file)

Routes under `/reports`, JWT-protected.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/reports/generate` | Builds report from scan data, saves to `Report` DB table, returns metadata. Supports `html` and `csv` formats. |
| `GET` | `/reports/` | List all reports (metadata only, no content). |
| `GET` | `/reports/{report_id}` | Fetch a single report including full content. |
| `GET` | `/reports/{report_id}/download` | Download as `text/html` or `text/csv` with a `Content-Disposition` attachment header. |

### Other backend changes

| File | Change |
|------|--------|
| `app/models/report.py` | New `Report` ORM model (`report_id`, `scan_id`, `generated_by`, `format`, `content`, `created_at`). |
| `app/schemas/ai_schema.py` | Pydantic schemas: `AttackRecommendRequest`, `RemediationRequest`, `ReviewRequest`, `AIChatRequest`. |
| `app/schemas/report_schema.py` | `ReportGenerateRequest` (`scan_id`, `format`). |
| `app/main.py` | Registers `ai` and `reports` routers. |
| `app/core/db.py` | Minor adjustment. |
| `app/utils/logging_utils.py` | Extended audit log utilities. |
| `requirements.txt` | Added `httpx` (needed by `OllamaClient` for streaming HTTP). |
| `ai_logs.json` | Auto-created at runtime; stores governance log records. |

---

## Frontend   New / Changed Files

### `src/lib/attack-recommendation-store.ts` (new)

Singleton store for AI attack recommendation state. Survives page navigation so the generated text is not lost when the user switches tabs.

- State: `scanId`, `vulnId`, `recommendation`, `generating`, `lastError`
- `startGeneration(scanId, vulnId?)`   opens an SSE connection to `/ai/recommend-attacks/stream`, appends tokens as they arrive, then marks `generating: false` on `event: done`.
- Exposed via `useSyncExternalStore` in the component.

### `src/lib/remediation-store.ts` (new)

Same pattern as the attack store but for `/ai/remediate/stream`.

- State includes `vulnId`, `exploitId`, `description`, `guidance`, `generating`, `lastError`.

### `src/lib/api.ts` (extended)

Added API wrappers for the new backend routes:

- `ai.recommendAttacks(scanId, vulnId?)`   POST to `/ai/recommend-attacks`
- `ai.streamRecommendAttacks(scanId, vulnId?)`   returns `EventSource` URL
- `ai.remediate(...)` / `ai.streamRemediate(...)`
- `ai.chat(...)` / `ai.streamChat(...)`
- `ai.review(action, scanId?, vulnId?)`
- `reports.generate(scanId, format)` / `reports.list()` / `reports.get(id)` / `reports.download(id)`
- Added `ReportItem`, `ReportDetail` TypeScript types.

### `src/pages/AttackRecommendations.tsx` (refactored)

- AI state (recommendation text, generating flag, errors) moved entirely into the singleton `attackRecommendationStore`.
- Component reads store via `useSyncExternalStore`   no prop drilling.
- Shows streaming tokens as they arrive.
- Accept / Reject / Regenerate buttons call `ai.review()` and re-trigger generation on regenerate.

### `src/pages/RemediationGuidance.tsx` (refactored)

- Same refactor pattern: AI state lives in `remediationStore`.
- Accepts `vuln_id`, `exploit_id`, or freetext `description` to ground the remediation prompt.

### `src/pages/Reports.tsx` (refactored)

- Generate reports by selecting a completed scan and format (HTML / CSV).
- Lists all past reports.
- Preview modal shows rendered HTML or plain CSV inline.
- Download button triggers the `/reports/{id}/download` endpoint.

---

## Tests

| File | Coverage |
|------|---------|
| `tests/test_attack_recommender.py` | Unit tests for `recommend_attacks` and `stream_attack_recommendation`   mocks `OllamaClient`, tests happy path, unavailable service, and streaming. |
| `tests/test_remediation.py` | Unit tests for `get_remediation` and `stream_remediation`   same mocking strategy. |

---

## Architecture Overview

```
Frontend (React)
  └── Singleton Stores (SSE consumers)
        ├── attack-recommendation-store.ts  ──► POST /api/ai/recommend-attacks/stream
        └── remediation-store.ts            ──► POST /api/ai/remediate/stream

Backend (FastAPI)
  ├── /api/ai/*          ──► app/services/ollama_client.py ──► Ollama (tinyllama, local)
  │                               └── safety_filter.py (post-process)
  │                               └── governance_logger.py (ai_logs.json)
  └── /api/reports/*     ──► app/services/report_builder.py ──► Report DB table
```

## Prerequisites

- **Ollama** must be running locally: `ollama serve` + `ollama pull tinyllama`
- `OLLAMA_URL` defaults to `http://localhost:11434/api/generate`
- `OLLAMA_MODEL` defaults to `tinyllama`

---

## What Was Intentionally Left Out

- The AI pages were wired to real backend data in this branch; no mock/dummy data remains.
- No authentication changes were made   all AI and report routes inherit the existing JWT middleware.
- No new database migrations were generated for the `Report` model in this branch (model was added; migration may need to be run separately).
