# ASHEN

ASHEN (Automated Security & Host Exploitation Navigator) is an AI-assisted penetration-testing platform that guides an authorised operator through scanning, vulnerability detection, exploit validation, AI recommendation, remediation, and reporting against pre-approved targets.

## Language

### Actors

**Analyst**:
A security professional who runs scans and exploits against authorised targets and can only see and act on their own work. Stored in the `user` table; `role` is always `Analyst`.
_Avoid_: User, operator, pentester

**Admin**:
The governance actor who whitelists target IPs, approves scan requests, creates Analyst accounts, and reads the full audit log. A distinct entity from Analyst (separate `admin` table), not a role of it.
_Avoid_: Superuser, manager

### Scope

**Target**:
An IPv4 address that an Admin has placed in ASHEN's authorised scope. A Target is the IP itself — there is no separate machine/host concept. Persisted as a `TargetSystem` row, keyed by a unique IP. An IP becomes a Target either by an Admin whitelisting it directly or by an Admin approving a Target Request.
_Avoid_: Host, Machine, Asset, System, TargetSystem (in prose)

**Target Request**:
An Analyst's request for an Admin to authorise an IP as a Target. Approving it is an authorisation decision — it does **not** launch a Scan. Implemented as the `ScanRequest` class.
_Avoid_: Scan request (misnomer — no scan is requested)

### Assessment workflow

**Scan**:
A single Nmap execution (`nmap -sV --script vuln`) against one Target, run in the background and tracked through `queued → running → completed`. Produces Vulnerabilities.
_Avoid_: Scan request (a different concept)

**Vulnerability**:
A weakness **detected** on a Target's port by a Scan's Nmap NSE script. It is an unvalidated detection, not a confirmed weakness — an Exploit is what confirms or refutes it. Severity may be `unknown`.
_Avoid_: Finding, Weakness, Issue

**CVE**:
A publicly catalogued vulnerability class (from the NVD), stored in ChromaDB and retrieved to ground AI output. Distinct from a Vulnerability, which is a detection on a specific Target.
_Avoid_: Calling a CVE a "Vulnerability"

**Severity**:
A heuristic rank — `critical / high / medium / low / unknown` — attached to a Vulnerability or CVE. For a Vulnerability it is keyword-inferred from the NSE output (not authoritative CVSS); for a CVE it comes from the NVD CVSS `baseSeverity`. `unknown` means it could not be inferred.
_Avoid_: Risk, Criticality, CVSS score (when meaning this label)

### Exploitation

**Exploit Type**:
One of the four built-in techniques: `ssh_brute_force`, `ftp_brute_force`, `ms17_010_check`, `shellshock_cgi`. Technique-level and reusable. Comes in two families: a **Credential** Exploit Type (brute-force — its evidence is found credentials) and a **Check** Exploit Type (a non-destructive check or PoC — its evidence is a yes/no verdict). Both confirm or refute a Vulnerability; the family only changes the shape of the evidence.
_Avoid_: Module, Attack, Technique

**Exploit Run**:
A single execution of an Exploit Type against a Target, with a status (`pending/running/success/failed/no_credentials_found`) and a `vulnerable` verdict. Persisted as the `Exploit` row. This is what validates or refutes a Vulnerability.
_Avoid_: Exploit (bare, when meaning the execution), Attack

### AI guidance

**Attack Recommendation**:
The AI-generated, RAG-grounded prioritised plan of what to try against a Target, given its open ports and Vulnerabilities. Streamed over SSE and safety-filtered; its body is labelled "Exploitation Order". References Exploit Types but is LLM prose, not a structured selection.
_Avoid_: Attack (bare — only valid inside this compound), Attack Plan

**Remediation**:
The AI-generated fix guidance for a Vulnerability or Exploit Run, produced in the fixed five-part structure: Root Cause / Immediate Containment / Permanent Fix / Validation / Hardening. Streamed over SSE.
_Avoid_: Fix, Mitigation (when meaning the whole guidance)

### Reporting

**Report**:
A generated artefact summarising one Scan's Vulnerabilities and Exploit Runs, rendered in a chosen `format` (HTML or CSV), persisted, and downloadable. A single Scan may have many Reports; HTML and CSV are formats of the same concept.
_Avoid_: Export, Document, Summary

### Governance

**Audit Log**:
The chronological record of operator actions (login, scan, Exploit Run, report generation), each with actor email and timestamp. Persisted in the `audit_log` table; read by Admins.
_Avoid_: Log, Logs (bare)

**AI Governance Log**:
The separate record of every AI prompt and response, kept for AI-governance review. Written as JSONL to `ai_logs.json` by the governance logger. Distinct from the Audit Log.
_Avoid_: Log, Logs (bare), AI log
