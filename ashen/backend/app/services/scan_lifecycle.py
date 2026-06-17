"""
scan_lifecycle.py — the one module that owns Scan status transitions and
Vulnerability extraction.

Before this module the cancel-race guard ("a user cancellation is terminal — a
worker update must never flip it back to running/completed") lived in *two*
functions, and the cancel route bypassed both by writing ``scan.status``
directly. Vulnerability extraction was welded into finalisation, so re-running
Severity inference meant re-scanning — and would have duplicated rows.

Now every status write goes through ``mark_status`` / ``finalize`` / ``cancel``,
which share one guard, and ``extract_vulnerabilities`` is a re-runnable step
keyed by Scan.
"""
import json
import re
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.models.exploit import Exploit
from app.utils.logging_utils import create_audit_log

# A user cancellation is terminal; queued/running are the only states a Scan may
# be cancelled *from*.
CANCELLABLE = ("queued", "running")


def _cancel_is_sticky(scan: Scan, to: str) -> bool:
    """The single race guard: once cancelled, only 'cancelled' may be written."""
    return scan.status == "cancelled" and to != "cancelled"


# ── status transitions ──────────────────────────────────────────────────


def mark_status(db: Session, scan_id: int, to: str, *, progress: int | None = None) -> bool:
    """Move a Scan to ``to`` unless that would override a user cancellation.

    Returns True if the write happened, False if it was a no-op (scan missing or
    cancellation preserved). start_time is never touched here.
    """
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        return False
    if _cancel_is_sticky(scan, to):
        return False

    scan.status = to
    if progress is not None:
        scan.progress = progress
    db.commit()
    return True


def cancel(db: Session, scan: Scan, user_email: str) -> bool:
    """Transition a queued/running Scan to cancelled.

    Returns False if the Scan is in a non-cancellable (terminal) state, so the
    caller can surface a 409. Ownership is the caller's concern.
    """
    if scan.status not in CANCELLABLE:
        return False
    scan.status = "cancelled"
    scan.end_time = datetime.utcnow()
    db.commit()
    return True


def finalize(
    db: Session,
    scan_id: int,
    status: str,
    result_output: str,
    error_message: str,
    user_email: str,
    completion_note: str | None = None,
) -> None:
    """Write a Scan's terminal state and, on success, extract Vulnerabilities."""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        return

    # If the user cancelled in parallel, cancelled stays terminal.
    if _cancel_is_sticky(scan, status):
        status = "cancelled"

    scan.status = status
    if status == "completed":
        scan.progress = 90
    elif status in ("failed", "cancelled"):
        scan.progress = 0
    scan.end_time = datetime.utcnow()
    scan.results_json = result_output if result_output else json.dumps({"error": error_message or status})
    if error_message:
        scan.error_detail = error_message[:500]
    elif status == "completed" and completion_note:
        scan.error_detail = completion_note
    db.commit()

    if status == "completed":
        msg = f"Scan {scan_id} completed successfully"
    elif status == "cancelled":
        msg = f"Scan {scan_id} cancelled"
    else:
        msg = f"Scan {scan_id} failed after retries"
    create_audit_log(db, msg, user_email)

    if status == "completed" and result_output:
        extraction_error = extract_vulnerabilities(db, scan_id, result_output)
        if not extraction_error:
            scan.progress = 100
            db.commit()
        else:
            # P1.6: record the failure on the Scan and preserve the raw results.
            scan.status = "completed_with_errors"
            try:
                parsed_results = json.loads(result_output)
            except (json.JSONDecodeError, TypeError):
                parsed_results = {"raw": result_output}
            scan.results_json = json.dumps({
                "scan_results": parsed_results,
                "extraction_error": extraction_error,
            })
            db.commit()
            create_audit_log(
                db,
                f"Scan {scan_id} completed but vulnerability extraction failed: {extraction_error}",
                user_email,
            )


# ── Vulnerability extraction (re-runnable, keyed by Scan) ────────────────


def _infer_severity(output: str) -> str:
    """Infer a severity from an Nmap vuln-script's output.

    Findings only reach us when their output already contains "VULNERABLE" or
    "Exploitable" (see NmapScanner), so "unknown" is rarely the honest answer.
    Priority: an explicit ``Risk factor`` / CVSS line, then severity keywords,
    then the confirmed-vulnerable state itself (Exploitable ⇒ critical).
    """
    risk = re.search(r"risk factor:\s*(critical|high|medium|low)", output, re.IGNORECASE)
    if risk:
        return risk.group(1).lower()

    cvss = re.search(r"cvss(?:v\d)?(?:\s*base)?(?:\s*score)?:\s*(\d+(?:\.\d+)?)", output, re.IGNORECASE)
    if cvss:
        score = float(cvss.group(1))
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"

    for level in ("critical", "high", "medium", "low"):
        if re.search(rf"\b{level}\b", output, re.IGNORECASE):
            return level

    # Confirmed vulnerable but no stated rating: an exploitable finding is the
    # most serious; an otherwise-vulnerable one is high, not "unknown".
    if re.search(r"exploitable", output, re.IGNORECASE):
        return "critical"
    if re.search(r"vulnerable", output, re.IGNORECASE):
        return "high"
    return "unknown"


_CVE_RE = re.compile(r"CVE[-:]\s?(\d{4}-\d{4,7})", re.IGNORECASE)


def _summarize_vuln(output: str, script_id: str | None) -> str:
    """Build a human-readable one-line description from a vuln-script's output.

    Nmap output's first line is usually the script-id header, which is not
    descriptive. Prefer the title line that follows the ``VULNERABLE:`` marker,
    append any CVE, and fall back to a humanized script id.
    """
    lines = [ln.strip(" |\t") for ln in (output or "").splitlines()]
    lines = [ln for ln in lines if ln]

    title = ""
    for i, ln in enumerate(lines):
        if ln.upper().startswith("VULNERABLE"):
            # The next non-state line is typically the human-readable title.
            for nxt in lines[i + 1:]:
                if not re.match(r"^(state|ids|risk|disclosure|references|cvss)\b", nxt, re.IGNORECASE):
                    title = nxt
                    break
            break

    if not title:
        title = lines[0] if lines else ""
    if not title and script_id:
        title = script_id.replace("-", " ").replace("_", " ").strip().capitalize()

    cve = _CVE_RE.search(output or "")
    if cve:
        cve_id = f"CVE-{cve.group(1)}"
        if cve_id.lower() not in title.lower():
            title = f"{title} ({cve_id})" if title else cve_id

    return (title or "N/A")[:250]


def extract_vulnerabilities(
    db: Session,
    scan_id: int,
    result_json: str | None = None,
    *,
    replace: bool = False,
) -> str | None:
    """Parse stored Nmap JSON for a Scan and insert Vulnerabilities.

    Re-runnable: pass ``replace=True`` to refresh the Scan's existing
    Vulnerability rows, so a Severity-inference change can be re-applied to a
    stored Scan without re-scanning and without duplicating rows. Rows are
    matched on ``(port, script_id)`` and updated in place — never deleted and
    re-inserted — so Exploit rows that reference a vulnerability (FK
    ``exploit.vuln_id``) are preserved. Stale rows no longer present in the scan
    output are removed only when nothing references them. When ``result_json``
    is omitted the Scan's stored ``results_json`` is used. Returns an error
    string on failure, None on success.
    """
    if result_json is None:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan or not scan.results_json:
            return f"No stored results to extract for scan {scan_id}"
        result_json = scan.results_json

    try:
        data = json.loads(result_json)
        # Unwrap the completed_with_errors envelope if present.
        if "hosts" not in data and isinstance(data.get("scan_results"), dict):
            data = data["scan_results"]

        existing = {}
        if replace:
            for v in db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all():
                existing[(v.port, v.script_id)] = v

        count = 0
        seen = set()
        for host in data.get("hosts", []):
            for vuln in host.get("vulns", []):
                output = vuln.get("output", "")
                script_id = vuln.get("id")
                port = vuln.get("port")
                key = (port, script_id)
                seen.add(key)
                severity = _infer_severity(output)
                description = _summarize_vuln(output, script_id)

                row = existing.get(key)
                if row is not None:
                    # Update in place — keeps vuln_id stable for referencing Exploits.
                    row.severity = severity
                    row.description = description
                    row.raw_output = output
                else:
                    db.add(Vulnerability(
                        scan_id=scan_id,
                        port=port,
                        script_id=script_id,
                        severity=severity,
                        description=description,
                        raw_output=output,
                    ))
                count += 1

        # Drop rows no longer reported, but only if no Exploit references them.
        if replace:
            for key, row in existing.items():
                if key in seen:
                    continue
                if db.query(Exploit).filter(Exploit.vuln_id == row.vuln_id).first():
                    continue
                db.delete(row)

        db.commit()
        create_audit_log(
            db,
            f"Extracted {count} vulnerabilities from scan {scan_id}" + (" (re-extract)" if replace else ""),
            "system",
        )
        return None
    except Exception as e:
        error_msg = f"Vulnerability extraction failed for scan {scan_id}: {e}"
        print(f"[!] {error_msg}")
        return error_msg
