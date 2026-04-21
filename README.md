# ASHEN - Automated Security & Host Exploitation Navigator

ASHEN is a full-stack penetration testing platform that combines automated network scanning, exploit validation, and AI-powered attack recommendations with remediation guidance. Built as a Final Year Project at FAST-NUCES, it provides security analysts with an end-to-end workflow: **Scan > Detect > Exploit > Recommend > Remediate > Report**.

> **Disclaimer:** ASHEN is designed exclusively for authorized security testing on targets you own or have explicit written permission to test. Unauthorized use against systems you do not own is illegal.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [Default Credentials](#default-credentials)
- [Workflow](#workflow)
- [API Overview](#api-overview)
- [Security Controls](#security-controls)
- [Testing](#testing)
- [Team](#team)

---

## Features

### Network Scanning
- Nmap-based vulnerability scanning with XML output parsing
- Background scan execution with real-time progress tracking (queued/running/completed/failed)
- Scan cancellation with subprocess termination
- Automatic retry (up to 3 attempts) with exponential backoff
- Duplicate scan prevention per target

### Vulnerability Detection
- Automated extraction of vulnerabilities from Nmap script output
- Severity classification (Critical / High / Medium / Low)
- Per-port vulnerability records with raw script output stored

### Exploit Validation
- **SSH Brute Force** - Metasploit `ssh_login` scanner
- **FTP Brute Force** - Hydra credential testing
- **MS17-010 (EternalBlue)** - Non-destructive SMB vulnerability check via Metasploit
- **Shellshock (CVE-2014-6271)** - CGI-based RCE verification via curl
- All exploits run as background tasks with status tracking

### AI Engine (Ollama + LLaMA)
- **Attack Recommendations** - AI-generated prioritized exploitation plans based on scan results
- **Remediation Guidance** - Structured fix instructions (Root Cause, Containment, Fix, Validation, Hardening)
- **Follow-up Chat** - Contextual Q&A with vulnerability/exploit context
- **RAG-enhanced** - CVE knowledge base via ChromaDB + sentence-transformers, enriched from NVD API
- Server-Sent Events (SSE) streaming for real-time AI responses
- Safety filtering to block unsafe content and strip URLs from AI output
- AI governance logging for all generated responses

### Reporting
- HTML and CSV report generation per scan
- Executive summary with severity breakdown
- Vulnerability details and exploit validation results
- Downloadable report files

### Admin Controls
- Target IP authorization (only admin-approved IPs can be scanned/exploited)
- User management (admin creates analyst accounts)
- Scan request approval workflow
- Full audit log with filtering by user, action, and date range

### Dashboard
- Real-time overview with severity distribution pie chart
- Scan history, vulnerability counts, and exploit results
- Guided workflow navigation (Scan > Recommend > Remediate > Logs)

---

## Architecture

```
┌──────────────────────────────────┐
│         React Frontend           │
│  (Vite + TypeScript + Tailwind)  │
│     Port 5173 (dev server)       │
└──────────────┬───────────────────┘
               │ REST API + SSE
               ▼
┌────────────────────────────────────┐
│        FastAPI Backend             │
│       Port 8000 (uvicorn)          │
│                                    │
│  ┌────────┐  ┌────────────────────┐│
│  │  Auth  │  │  Scan Engine       │|
│  │  JWT   │  │  (Nmap subprocess) │|
│  └────────┘  └────────────────────┘│
│  ┌────────────────────────────┐    │
│  │     Exploit Modules        │    |
│  │  MSF / Hydra / curl        │    │
│  └────────────────────────────┘    │
│  ┌────────────────────────────┐    │
│  │      AI Service Layer      │    │
│  │  Ollama Client + RAG       │    │
│  │  ChromaDB + NVD enrichment │    │
│  └────────────────────────────┘    │
└──────────────┬─────────────────────┘
               │
     ┌─────────┼──────────┐
     ▼         ▼          ▼
┌─────────┐ ┌──────┐ ┌────────┐
│ SQLite/ │ │Ollama│ │ChromaDB│
│ Postgres│ │(LLM) │ │ (RAG)  │
└─────────┘ └──────┘ └────────┘
```

---

## Tech Stack

### Backend
| Component | Technology |
|---|---|
| Framework | FastAPI (Python) |
| Database | SQLite (dev) / PostgreSQL (prod) |
| ORM | SQLAlchemy + Alembic migrations |
| Auth | JWT (PyJWT) + bcrypt password hashing |
| Scanner | Nmap (subprocess with XML parsing) |
| Exploits | Metasploit Framework, Hydra, curl |
| AI/LLM | Ollama (LLaMA 3.2 default) |
| RAG | ChromaDB + sentence-transformers (all-MiniLM-L6-v2) |
| CVE Data | NVD API integration |
| Rate Limiting | Redis (optional) / In-memory fallback |
| HTTP Client | httpx |

### Frontend
| Component | Technology |
|---|---|
| Framework | React 18 + TypeScript |
| Build Tool | Vite |
| Styling | Tailwind CSS + shadcn/ui (Radix primitives) |
| Routing | React Router v6 |
| State/Data | TanStack React Query |
| Charts | Recharts |
| Forms | React Hook Form + Zod validation |

---

## Project Structure

```
ASHEN/ashen/
├─ backend/
│   ├── app/
│   │   ├── api/              # Route handlers
│   │   │   ├── auth.py       # Login/logout/signup
│   │   │   ├── scans.py      # Scan start/status/cancel/history
│   │   │   ├── vulns.py      # Vulnerability queries
│   │   │   ├── exploits.py   # Exploit execution & results
│   │   │   ├── ai.py         # Attack recommendations, remediation, chat
│   │   │   ├── reports.py    # Report generation & download
│   │   │   ├── admin.py      # Audit logs, targets, user mgmt
│   │   │   └── users.py      # User profile
│   │   ├── core/
│   │   │   ├── config.py     # Environment & JWT config
│   │   │   ├── db.py         # SQLAlchemy engine, session, seed
│   │   │   ├── security.py   # Password hashing, JWT guards
│   │   │   ├── csrf.py       # CSRF middleware
│   │   │   └── rate_limit.py # Per-user rate limiting
│   │   ├── models/           # SQLAlchemy ORM models
│   |   ├── schemas/          # Pydantic request/response schemas
│   │   ├── services/
│   │   │   ├── scanner/
│   │   │   │   └── nmap_scanner.py      # Nmap wrapper + process registry
│   │   │   ├── exploits/
│   │   │   │   ├── msf_ssh.py           # SSH brute force (Metasploit)
│   │   │   │   ├── hydra_ftp.py         # FTP brute force (Hydra)
│   │   │   │   ├── msf_ms17010.py       # EternalBlue check (Metasploit)
│   │   │   │   └── shellshock.py        # Shellshock CGI check (curl)
│   │   │   ├── ollama_client.py         # LLM integration (Ollama)
│   │   │   ├── attack_recommender.py    # AI attack recommendations
|   │   │   ├── remediation_service.py   # AI remediation guidance
│   │   |   ├── rag_store.py             # ChromaDB CVE knowledge base
│   │   │   ├── safety_filter.py         # AI output filtering
│   │   │   ├── report_builder.py        # HTML/CSV report generation
│   |   │   ├── governance_logger.py     # AI governance audit trail
│   │   │   ├── feedback_service.py      # Accept/reject/regenerate
│   │   │   |── prompt_templates.py      # LLM prompt engineering
│   │   └── utils/
│   │       ├── jwt_handler.py
│   │       └── logging_utils.py
│   ├── alembic/              # Database migrations
│   ├── tests/                # Backend test suite
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Login.tsx / SignUp.tsx
│   │   │   ├── Dashboard.tsx
│   │   │   ├── NetworkScans.tsx
│   │   |   ├── AttackRecommendations.tsx
│   │   │   ├── RemediationGuidance.tsx
│   │   │   ├── Reports.tsx
│   │   │   ├── DataLogs.tsx
│   |   │   ├── AdminTargets.tsx
│   │   │   ├── AdminScanRequests.tsx
│   │   │   └── UserManagement.tsx
│   │   ├── components/       # Reusable UI components (shadcn/ui)
│   │   ├── contexts/         # AuthContext (JWT-based session)
│   │   ├── layouts/          # DashboardLayout with sidebar
│   |   ├── hooks/            # Custom React hooks
│   │   ├── lib/              # API client, stores, utilities
│   │   └── config/           # Navigation config
│   ├── package.json
│   └── vite.config.ts
│
└── documents/                # SRS and sprint roadmap
```

---

## Prerequisites

- **Python 3.12+**
- **Node.js 18+** and npm
- **Nmap** installed and in PATH
- **Metasploit Framework** (`msfconsole`) for exploit modules
- **Hydra** for FTP brute-force
- **Ollama** running locally with a model pulled (default: `llama3.2`)
- **Redis** (optional, for distributed rate limiting)

### Installing External Tools (Kali Linux)

```bash
# Nmap, Hydra, Metasploit are pre-installed on Kali
# If needed:
sudo apt install nmap hydra metasploit-framework curl

# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2
```

---

## Installation

### Backend

```bash
cd ASHEN/ashen/backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Frontend

```bash
cd ASHEN/ashen/frontend

npm install
```

---

## Configuration

Create a `.env` file in the `backend/` directory:

```env
# Database (defaults to SQLite if not set)
DATABASE_URL=sqlite:///./ashen_dev.db
# For PostgreSQL:
# DATABASE_URL=postgresql://user:pass@localhost:5432/ashen

# JWT Secret (CHANGE THIS in production)
JWT_SECRET=your-strong-secret-key-here
JWT_ALGORITHM=HS256

# Ollama AI
OLLAMA_URL=http://localhost:11434/api/generate
OLLAMA_MODEL=llama3.2

# Redis (optional, for rate limiting)
# REDIS_URL=redis://localhost:6379

# CSRF (disable for testing if needed)
# CSRF_ENABLED=false
```

---

## Running the Application

### 1. Start Ollama (AI Engine)

```bash
ollama serve
# In another terminal, ensure model is available:
ollama pull llama3.2
```

### 2. Start the Backend

```bash
cd ASHEN/ashen/backend
source .venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The database is auto-created on first run with a seeded admin account.

### 3. Start the Frontend

```bash
cd ASHEN/ashen/frontend
npm run dev
```

Open **http://localhost:5173** in your browser.

---

## Default Credentials

| Role | Email | Password |
|---|---|---|
| Admin | `admin@ashen.dev` | `Admin123!` |

Analysts are created by the admin through the User Management page.

---

## Workflow

```
1. Admin Setup
   └─> Add authorized target IPs
   └─> Create analyst accounts

2. Analyst Login
   └─> Acknowledge ethical disclaimer

3. Network Scan
   └─> Select authorized target IP
   └─> Nmap runs in background (-sV --script vuln)
   └─> Vulnerabilities auto-extracted from results

4. Attack Recommendations (AI)
   └─> Select completed scan
   └─> AI generates prioritized exploitation plan
   └─> RAG enrichment with CVE knowledge base

5. Exploit Validation
   └─> Run specific exploits against discovered services
   └─> SSH/FTP brute force, MS17-010, Shellshock
   └─> Results tracked with success/failure status

6. Remediation Guidance (AI)
   └─> Select vulnerability or exploit result
   └─> AI generates structured fix instructions
   └─> Follow-up chat for clarifications

7. Reporting
   └─> Generate HTML or CSV report per scan
   └─> Includes severity summary, vulns, exploit results
   └─> Download for offline use

8. Audit Trail
   └─> Every action logged with timestamp and user
   └─> Admin can filter and review all activity
```

---

## API Overview

Base URL: `http://localhost:8000`

| Prefix | Description |
|---|---|
| `POST /auth/admin-login` | Admin authentication |
| `POST /auth/user-login` | Analyst authentication |
| `POST /auth/create-user` | Admin creates analyst account |
| `POST /scan/start` | Start Nmap scan (background) |
| `GET  /scan/status/{id}` | Poll scan progress |
| `POST /scan/cancel/{id}` | Cancel running scan |
| `GET  /scan/history` | Paginated scan history |
| `GET  /vulns/scan/{id}` | Vulnerabilities for a scan |
| `POST /exploit/run` | Execute exploit (background) |
| `GET  /exploit/results/{id}` | Exploit result |
| `POST /ai/recommend-attacks` | AI attack recommendations |
| `POST /ai/remediate` | AI remediation guidance |
| `POST /ai/chat` | AI follow-up Q&A |
| `POST /ai/*/stream` | SSE streaming variants |
| `POST /reports/generate` | Generate HTML/CSV report |
| `GET  /reports/{id}/download` | Download report |
| `GET  /admin/audit-logs` | Filtered audit logs |
| `POST /admin/targets` | Add authorized target IP |

Interactive docs: **http://localhost:8000/docs** (Swagger UI)

---

## Security Controls

- **JWT Authentication** on all routes (admin + analyst roles)
- **RBAC**: Admins manage targets/users; Analysts run scans/exploits
- **Target Authorization**: Only admin-approved IPs can be scanned or exploited
- **CSRF Protection**: Custom `X-CSRF-Token` header required on state-changing requests
- **Rate Limiting**: 5 scans/min and 10 exploits/min per user (Redis or in-memory)
- **Ethical Disclaimer**: Must acknowledge before scanning or exploiting
- **Ownership Isolation**: Analysts can only view their own scan/exploit results
- **Duplicate Prevention**: Only one active scan per target at a time
- **AI Safety Filtering**: Banned keyword blocking, URL stripping, echo detection
- **AI Governance Logging**: All AI prompts and responses logged to file
- **Bcrypt Password Hashing**: Secure credential storage
- **Audit Trail**: Every action logged with user attribution

---

## Testing

### Backend

```bash
cd ASHEN/ashen/backend
source .venv/bin/activate

# Run all tests
pytest

# Run specific test module
pytest tests/test_scans.py -v
```

### Frontend

```bash
cd ASHEN/ashen/frontend

# Run tests
npm run test

# Watch mode
npm run test:watch
```

---

## Team

| Name | Roll Number |
|---|---|
| Sumit Jethani | 22F-3852 |
| Maheen Naeem | 22F-3145 |
| Junaid Aamir Chaudhary | 22F-3332 |

**Supervised by:** Dr. Ammar Rafiq & Mr. Talha Arif
**Department of Computer Science**, FAST-NUCES, Chiniot-Faisalabad Campus, 2025

---

## License

This project was developed as a Final Year Project (FYP) for academic purposes.
