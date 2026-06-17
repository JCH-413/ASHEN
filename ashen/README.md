# ASHEN

**Automated Security & Host Exploitation Navigator**

ASHEN is an AI-assisted penetration testing platform that automates the standard security assessment workflow — network scanning, vulnerability detection, exploit validation, attack recommendation, remediation guidance, and reporting — into a single guided dashboard. It is designed for authorised security analysts working against pre-approved targets in lab or controlled environments (e.g. Metasploitable2).

> Final Year Project — FAST National University of Computer & Emerging Sciences, Chiniot Faisalabad Campus (2025).
> Team: Sumit Jethani, Maheen Naeem, Junaid Aamir Chaudhary. Supervisors: Dr. Ammar Rafiq, Mr. Talha Arif.

---

## Table of Contents

1. [Concept](#concept)
2. [Workflow](#workflow)
3. [Tech Stack](#tech-stack)
4. [Project Structure](#project-structure)
5. [Core Features](#core-features)
6. [Architecture & Logic](#architecture--logic)
7. [Prerequisites](#prerequisites)
8. [Running the Project](#running-the-project)
9. [Default Credentials](#default-credentials)
10. [Security & Governance Controls](#security--governance-controls)
11. [Ethical Use](#ethical-use)

---

## Concept

Manual penetration testing pipelines stitch together many tools — Nmap, Metasploit, Hydra, custom scripts — and the analyst is responsible for moving results between them, deciding what to try next, and writing up findings. ASHEN replaces that hand-rolled glue with:

- A **role-based web dashboard** (Admin / Analyst) backed by a REST API.
- **Authorised-target enforcement**: scans and exploits can only run against IPs an Admin has explicitly whitelisted.
- A **local LLM (Ollama)** acting as both an *attack recommender* (ranking which built-in exploits are most likely to succeed given the scan output) and a *remediation expert* (Root Cause → Containment → Permanent Fix → Validation → Hardening).
- **Retrieval-Augmented Generation** using ChromaDB seeded with sample CVEs and live data pulled from the NVD API, so recommendations are grounded in known vulnerabilities for the discovered services.
- A **governance layer** (rate limits, audit log, AI safety filter, ethical-disclaimer acknowledgements, signed JWT sessions, CSRF middleware) so the platform is safe to operate on a shared network.

The result: one click takes the analyst from "scan this IP" → ranked exploit plan → exploit execution → AI-generated remediation → downloadable HTML/CSV report, with every action logged.

---

## Workflow

```
 Admin                              Analyst
   │                                   │
   │ 1. Add authorised target IP       │
   │ 2. Approve scan request           │
   │ (creates user accounts)           │
   ▼                                   ▼
[Target whitelist]            ┌──→ 3. Start scan (Nmap -sV --script vuln)
                              │       │
                              │       ▼
                              │   4. Vulnerabilities extracted & stored
                              │       │
                              │       ▼
                              │   5. AI Attack Recommendation
                              │      (RAG over CVEs + scan context → ranked exploit plan)
                              │       │
                              │       ▼
                              │   6. Run validated exploit
                              │      (SSH brute / FTP brute / MS17-010 check / Shellshock)
                              │       │
                              │       ▼
                              │   7. AI Remediation Guidance (streamed)
                              │       │
                              │       ▼
                              └── 8. Generate HTML / CSV report
                                      │
                                      ▼
                                 Audit log (every step)
```

---

## Tech Stack

### Backend
- **Python 3.13** + **FastAPI 0.115** (REST + Server-Sent Events for streaming AI tokens)
- **SQLAlchemy 2.0** + **Alembic** migrations (SQLite for dev, PostgreSQL ready via `psycopg2-binary`)
- **Passlib (bcrypt)** for password hashing, **PyJWT** for stateless auth, custom **CSRF middleware**
- **Redis** (optional) for sliding-window rate limiting; falls back to in-memory
- **Ollama** local LLM runtime (default model: `llama3.2`)
- **ChromaDB** + **sentence-transformers (all-MiniLM-L6-v2)** for CVE retrieval (RAG)
- **httpx** for streaming LLM responses; **NVD API** integration for live CVE enrichment

### Frontend
- **React 18** + **TypeScript** + **Vite**
- **TailwindCSS** + **shadcn/ui** (Radix UI primitives)
- **React Router v6** with protected routes (analyst vs admin)
- **TanStack Query** for server state, **React Hook Form** + **Zod** for validation
- **Recharts** for dashboard visualisations, **Lucide** icons, **Sonner** toasts
- **Vitest** + **Testing Library** for unit tests

### Security Tooling (system dependencies)
- **Nmap** (with `vuln` NSE scripts) — network discovery & vulnerability detection
- **Metasploit Framework** (`msfconsole`) — SSH brute-force, MS17-010 check
- **Hydra** — FTP brute-force
- **curl** — Shellshock (CVE-2014-6271) proof-of-concept

---

## Project Structure

```
ASHEN/ashen/
├── backend/
│   ├── alembic/                    # DB migrations
│   ├── alembic.ini
│   ├── requirements.txt
│   └── app/
│       ├── main.py                 # FastAPI entry — routers, CORS, CSRF
│       ├── core/
│       │   ├── config.py           # env loading, JWT secret
│       │   ├── db.py               # SQLAlchemy engine, seed admin
│       │   ├── security.py         # bcrypt, JWT deps, RBAC guards
│       │   ├── csrf.py             # X-CSRF-Token middleware
│       │   └── rate_limit.py       # Redis / in-memory sliding window
│       ├── api/                    # Route layer
│       │   ├── auth.py             # login / signup / logout
│       │   ├── users.py            # analyst self-service
│       │   ├── admin.py            # audit logs, target mgmt, scan-request review
│       │   ├── scan_requests.py    # analyst requests → admin approval
│       │   ├── scans.py            # start / status / cancel / history
│       │   ├── vulns.py            # vulnerability listing
│       │   ├── exploits.py         # run / results — exploit validation
│       │   ├── ai.py               # recommend-attacks / remediate / chat (SSE)
│       │   └── reports.py          # generate / download HTML & CSV
│       ├── models/                 # SQLAlchemy ORM
│       │   ├── admin.py, user.py, user_session.py
│       │   ├── target_system.py, scan_request.py
│       │   ├── scan.py, vulnerability.py, exploit.py
│       │   ├── report.py, audit_log.py
│       ├── schemas/                # Pydantic request / response models
│       ├── services/
│       │   ├── scanner/nmap_scanner.py    # subprocess + XML parsing + cancel
│       │   ├── scan_executor.py           # background runner, retries, vuln extraction
│       │   ├── exploits/
│       │   │   ├── msf_ssh.py             # Metasploit ssh_login
│       │   │   ├── hydra_ftp.py           # Hydra FTP brute
│       │   │   ├── msf_ms17010.py         # SMB MS17-010 non-destructive check
│       │   │   └── shellshock.py          # CVE-2014-6271 PoC
│       │   ├── ollama_client.py           # LLM client (generate + stream)
│       │   ├── rag_store.py               # ChromaDB CVE retrieval + NVD fetcher
│       │   ├── attack_recommender.py      # prompt + RAG + filter
│       │   ├── remediation_service.py     # remediation prompt + echo-detection
│       │   ├── prompt_templates.py
│       │   ├── safety_filter.py           # banned-keyword filter, URL stripping
│       │   ├── feedback_service.py        # accept / reject / regenerate
│       │   ├── governance_logger.py       # JSONL audit of every AI call
│       │   └── report_builder.py          # HTML / CSV report renderer
│       ├── utils/
│       │   ├── jwt_handler.py
│       │   └── logging_utils.py           # audit log + session helpers
│       └── tests/                  # pytest — auth, scans, exploits, rate limit, etc.
│
├── frontend/
│   ├── package.json
│   ├── vite.config.ts, tailwind.config.ts, tsconfig*.json
│   └── src/
│       ├── App.tsx                 # router + providers
│       ├── main.tsx
│       ├── contexts/AuthContext.tsx        # JWT rehydration, role parsing
│       ├── layouts/DashboardLayout.tsx
│       ├── components/
│       │   ├── AppSidebar.tsx, AppHeader.tsx
│       │   ├── ProtectedRoute.tsx          # requires auth / role
│       │   ├── EthicalDisclaimer.tsx       # must be ack'd before scan / exploit
│       │   ├── PageShell.tsx, EmptyState.tsx, ErrorBanner.tsx
│       │   └── ui/                         # shadcn primitives
│       ├── pages/
│       │   ├── Login.tsx, SignUp.tsx
│       │   ├── Dashboard.tsx               # severity pie + workflow tiles
│       │   ├── NetworkScans.tsx            # start / track / cancel scans
│       │   ├── AttackRecommendations.tsx   # streamed LLM output
│       │   ├── RemediationGuidance.tsx     # streamed remediation + chat
│       │   ├── Reports.tsx                 # generate + download
│       │   ├── DataLogs.tsx                # audit log viewer
│       │   ├── UserManagement.tsx          # admin
│       │   ├── AdminTargets.tsx            # admin — whitelist IPs
│       │   └── AdminScanRequests.tsx       # admin — approve scans
│       ├── lib/api.ts                      # typed API client (JWT + CSRF)
│       └── hooks/, config/, test/
│
└── documents/                              # SRS + Sprint Roadmap (extracted)
```

---

## Core Features

### 1. Role-Based Access (Admin / Analyst)
- Admin is seeded on first boot (`admin@ashen.dev` / `Admin123!`).
- Admins create Analyst accounts, whitelist target IPs, approve scan requests, and view the full audit log.
- Analysts can only see and act on their own scans, exploits, and reports.

### 2. Network Scanning
- Wraps `nmap -sV --script vuln`, parses the XML output, and streams progress (queued → running 10/20/70/90 → completed).
- Each scan runs as a `BackgroundTask` with a tracked `Popen` so it can be **cancelled** mid-run (SIGTERM/SIGKILL).
- Per-scan UUID temp files prevent collisions; cleanup is guaranteed.
- Up to 3 retries with backoff for transient failures; non-retryable errors (invalid IP, unreachable host) short-circuit.

### 3. Vulnerability Detection
- Findings flagged by Nmap NSE scripts (`VULNERABLE` / `Exploitable`) are persisted to the `vulnerability` table with inferred severity (critical / high / medium / low / unknown).

### 4. Exploit Validation
Four built-in exploit modules, each gated by authorised-target + ethical disclaimer + rate limit:

| Type              | Tool       | Target               | Behaviour                  |
| ----------------- | ---------- | -------------------- | -------------------------- |
| `ssh_brute_force` | Metasploit | SSH (port 22)        | Tries common cred pairs    |
| `ftp_brute_force` | Hydra      | FTP (port 21)        | Tries common cred pairs    |
| `ms17_010_check`  | Metasploit | SMB (port 445)       | Non-destructive vuln check |
| `shellshock_cgi`  | curl       | HTTP CGI (port 80)   | CVE-2014-6271 PoC          |

### 5. AI Attack Recommender (RAG + LLM)
- Builds context from open ports, prior exploit attempts, and available ASHEN exploit types.
- Retrieves the top-k most relevant CVEs from ChromaDB (seeded with sample CVEs + live NVD data).
- Prompts the local LLM (Ollama / `llama3.2` by default) for a prioritised exploitation order.
- Output is streamed token-by-token over Server-Sent Events to the React UI, filtered for unsafe content and URLs.

### 6. AI Remediation Guidance
- Structured prompt enforces a fixed format: **Root Cause / Immediate Containment / Permanent Fix / Validation / Hardening**.
- Echo-detection: if the small model parrots the input context back, the request is retried with a focused nudge.
- Streamed via SSE; supports follow-up chat with vulnerability + exploit context attached.

### 7. Reporting
- HTML report — styled executive summary (severity counts), vulnerability table, exploit results.
- CSV report — flat tabular export.
- Each report is persisted in DB and downloadable with `Content-Disposition: attachment`.

### 8. Audit Log & AI Governance Log
- Every login, scan, exploit, AI call, and report generation is written to the `audit_log` table with actor email and timestamp.
- All AI prompts + responses are appended to `ai_logs.json` for separate governance review.

---

## Architecture & Logic

```
┌──────────────────────────────────────────────────────────────────────┐
│                          React Frontend                              │
│   AuthContext (JWT in localStorage)  →  api.ts (fetch + CSRF token)  │
└─────────────┬────────────────────────────────────────────────────────┘
              │ HTTPS (CORS-restricted)
              ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     FastAPI Backend                                  │
│   CORSMiddleware → CSRFMiddleware → Route → JWT dep → RBAC guard     │
│                                                                      │
│  /auth   /users  /admin  /scan-requests  /scan  /vulns  /exploit     │
│                          /ai  /reports                               │
└──────┬─────────┬─────────┬──────────────────────────┬────────────────┘
       │         │         │                          │
       ▼         ▼         ▼                          ▼
  SQLAlchemy   BackgroundTasks               services/ai
  (SQLite /    ├─ scan_executor              ├─ ollama_client (httpx stream)
   Postgres)   │  └─ NmapScanner (subprocess)├─ rag_store (ChromaDB + NVD)
               └─ exploit runner             ├─ attack_recommender
                  ├─ msf_ssh                 ├─ remediation_service
                  ├─ hydra_ftp               ├─ safety_filter
                  ├─ msf_ms17010             └─ governance_logger
                  └─ shellshock
```

**Key design choices:**

- **Background execution** — scans/exploits return `scan_id` / `exploit_id` immediately and run via FastAPI `BackgroundTasks`. The UI polls `/scan/status/{id}` (and progress %) and can cancel mid-run.
- **Streaming AI** — both attack recommendation and remediation use SSE so users see tokens as they generate (similar UX to ChatGPT), with `event: token` / `event: done` / `event: error` semantics.
- **Authorised-target gate** — every state-changing scan/exploit endpoint re-checks `target_system.authorized == True` before doing anything.
- **Rate limiting** — sliding window of 5 scans/min and 10 exploits/min per analyst email, Redis-backed when `REDIS_URL` is set, otherwise thread-safe in-memory.
- **CSRF** — custom `X-CSRF-Token` header required on all non-safe methods; login endpoints are exempt.
- **Stateless auth** — HS256 JWT with `sub` + `role` claims; 60-min expiry; frontend rehydrates session from `localStorage` on reload.

---

## Prerequisites

- **Python 3.13**
- **Node.js 18+** and **npm**
- **Nmap** (`sudo apt install nmap`)
- **Metasploit Framework** (`msfconsole` at `/usr/bin/msfconsole`)
- **Hydra** (`sudo apt install hydra`)
- **curl**
- **Ollama** running locally with the `llama3.2` model pulled:
  ```bash
  curl -fsSL https://ollama.com/install.sh | sh
  ollama pull llama3.2
  ollama serve     # listens on http://localhost:11434
  ```
- (Optional) **Redis** for distributed rate limiting
- (Optional) A vulnerable practice target — **Metasploitable2** VM works out of the box

> The platform is designed for **Kali Linux** or a similar pentesting distro where these tools are already present.

---

## Running the Project

### 1. Backend

```bash
cd ASHEN/ashen/backend

# Create venv and install
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Optional .env — set a real JWT secret
cat > .env <<'EOF'
JWT_SECRET=change-me-to-a-long-random-string
JWT_ALGORITHM=HS256
DATABASE_URL=sqlite:///./ashen_dev.db
OLLAMA_URL=http://localhost:11434/api/generate
OLLAMA_MODEL=llama3.2
# REDIS_URL=redis://localhost:6379/0
# CSRF_ENABLED=true
EOF

# Apply migrations (creates tables and seeds the root admin)
alembic upgrade head

# Run the API
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Backend is now at `http://localhost:8000` — interactive docs at `http://localhost:8000/docs`.

### 2. Frontend

```bash
cd ASHEN/ashen/frontend
npm install
npm run dev
```

Frontend is now at `http://localhost:5173` (already whitelisted in the backend CORS config).

### 3. First-time flow

1. Log in as the seeded admin (see below).
2. Go to **Admin → Targets** and add an authorised IP (e.g. your Metasploitable2 VM).
3. Go to **Admin → Users** and create an Analyst account.
4. Log out, log in as the Analyst.
5. **Network Scans** → enter the authorised IP → acknowledge the disclaimer → **Start Scan**.
6. Once complete, open **Attack Recommendations** to get the LLM-ranked exploitation plan.
7. Run an exploit, then open **Remediation Guidance** for the AI-generated fix steps.
8. Generate an HTML/CSV report from the **Reports** page.

### 4. Tests

```bash
# Backend
cd ASHEN/ashen/backend
pytest

# Frontend
cd ASHEN/ashen/frontend
npm test
```

---

## Default Credentials

The backend seeds a root admin on first boot:

| Role  | Email             | Password    |
| ----- | ----------------- | ----------- |
| Admin | `admin@ashen.dev` | `Admin123!` |

**Change this immediately** in any non-throwaway environment.

---

## Security & Governance Controls

| Control                 | Where                                     |
| ----------------------- | ----------------------------------------- |
| Bcrypt password hashing | `app/core/security.py`                    |
| JWT (HS256, 60 min)     | `app/utils/jwt_handler.py`                |
| CSRF (`X-CSRF-Token`)   | `app/core/csrf.py`                        |
| CORS allowlist          | `app/main.py`                             |
| RBAC (`require_admin`)  | `app/core/security.py`                    |
| Authorised-target gate  | `scans.py`, `exploits.py`                 |
| Per-user rate limiting  | `app/core/rate_limit.py`                  |
| Ethical disclaimer ack  | required on `/scan/start`, `/exploit/run` |
| Subprocess cancellation | `scanner/nmap_scanner.py` (PID registry)  |
| Audit log               | every route writes via `create_audit_log` |
| AI safety filter        | `services/safety_filter.py`               |
| AI governance log       | `services/governance_logger.py`           |

---

## Ethical Use

ASHEN is a research / educational tool. **Use it only against systems you own or have explicit written authorisation to test.** The platform enforces this by requiring an admin to whitelist target IPs and requiring every analyst to acknowledge an ethical disclaimer before launching scans or exploits, but the legal responsibility rests with the operator. Do not point ASHEN at production systems, third-party networks, or any host outside your authorised scope.
