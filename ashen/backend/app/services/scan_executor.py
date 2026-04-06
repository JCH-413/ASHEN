"""
scan_executor.py
Asynchronous scan executor that integrates the local NmapScanner class.
P1.6: Vulnerability extraction failures are logged and surfaced in scan status.
"""

import json
import re
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy.orm import Session
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.utils.logging_utils import create_audit_log
from app.core.db import SessionLocal
from app.services.scanner.nmap_scanner import NmapScanner

MAX_CONCURRENT_SCANS = 10
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds between retries
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS)


def _is_scan_cancelled(db: Session, scan_id: int) -> bool:
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    return bool(scan and scan.status == "cancelled")


def _is_cancelled_error(error_message: str | None) -> bool:
    return bool(error_message and "cancel" in error_message.lower())


def run_scan_background(scan_id: int, ip: str, user_email: str):
    """Synchronous scan function — suitable for FastAPI BackgroundTasks."""
    _perform_scan_with_retries(scan_id, ip, user_email)


def _perform_scan_with_retries(scan_id: int, ip: str, user_email: str):
    """Perform scan with up to MAX_RETRIES attempts using the NmapScanner wrapper."""
    db: Session = SessionLocal()
    attempt = 0
    success = False
    cancelled = False
    result_output = None
    error_message = None

    while attempt < MAX_RETRIES and not success and not cancelled:
        if _is_scan_cancelled(db, scan_id):
            cancelled = True
            error_message = "Scan was cancelled"
            break

        attempt += 1
        create_audit_log(db, f"Scan {scan_id} attempt {attempt} started for {ip}", user_email)

        try:
            if not _update_scan_status(db, scan_id, "running", progress=10):
                cancelled = True
                error_message = "Scan was cancelled"
                break

            scanner = NmapScanner()
            if not _update_scan_status(db, scan_id, "running", progress=20):
                cancelled = True
                error_message = "Scan was cancelled"
                break

            parsed = scanner.quick_scan(ip, scan_id=scan_id)
            if not _update_scan_status(db, scan_id, "running", progress=70):
                cancelled = True
                error_message = "Scan was cancelled"
                break

            result_output = json.dumps(parsed, indent=2)
            success = True

        except Exception as e:
            error_message = str(e)
            if _is_cancelled_error(error_message) or _is_scan_cancelled(db, scan_id):
                cancelled = True
                create_audit_log(db, f"Scan {scan_id} was cancelled", user_email)
                break
            create_audit_log(db, f"Scan {scan_id} attempt {attempt} failed: {error_message}", user_email)
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)

    final_status = "cancelled" if cancelled else ("completed" if success else "failed")
    _finalize_scan(db, scan_id, final_status, result_output, error_message, user_email)
    db.close()


def _update_scan_status(db: Session, scan_id: int, status: str, progress: int | None = None) -> bool:
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        return False

    # Never allow worker transitions to override a user-cancelled scan.
    if scan.status == "cancelled" and status != "cancelled":
        return False

    scan.status = status
    if progress is not None:
        scan.progress = progress
    db.commit()
    return True


def _finalize_scan(db: Session, scan_id: int, status: str, result_output: str, error_message: str, user_email: str):
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        return

    # If user cancelled in parallel, preserve cancelled as terminal state.
    if scan.status == "cancelled" and status != "cancelled":
        status = "cancelled"

    scan.status = status
    if status == "completed":
        scan.progress = 90
    elif status in ("failed", "cancelled"):
        scan.progress = 0
    scan.end_time = datetime.utcnow()
    scan.results_json = result_output if result_output else json.dumps({"error": error_message or status})
    if error_message:
        # Store a safe, truncated error detail
        scan.error_detail = error_message[:500]
    db.commit()

    if status == "completed":
        msg = f"Scan {scan_id} completed successfully"
    elif status == "cancelled":
        msg = f"Scan {scan_id} cancelled"
    else:
        msg = f"Scan {scan_id} failed after retries"
    create_audit_log(db, msg, user_email)

    if status == "completed" and result_output:
        extraction_error = _extract_vulnerabilities(db, scan_id, result_output)
        if not extraction_error:
            scan.progress = 100
            db.commit()
        # P1.6: If extraction failed, record it in the scan record and audit log
        if extraction_error:
            scan.status = "completed_with_errors"
            # Preserve original results and append extraction error
            try:
                parsed_results = json.loads(result_output)
            except (json.JSONDecodeError, TypeError):
                parsed_results = {"raw": result_output}
            scan.results_json = json.dumps({
                "scan_results": parsed_results,
                "extraction_error": extraction_error
            })
            db.commit()
            create_audit_log(
                db,
                f"Scan {scan_id} completed but vulnerability extraction failed: {extraction_error}",
                user_email
            )


def _extract_vulnerabilities(db, scan_id: int, result_json: str) -> str | None:
    """
    Parse Nmap JSON results and insert vulnerabilities into DB.
    Returns error message string if extraction fails, None on success.
    """
    try:
        data = json.loads(result_json)
        hosts = data.get("hosts", [])
        count = 0
        for host in hosts:
            for vuln in host.get("vulns", []):
                port = vuln.get("port")
                script_id = vuln.get("id")
                output = vuln.get("output", "")

                # Severity inference
                sev = "unknown"
                if re.search(r"critical", output, re.IGNORECASE):
                    sev = "critical"
                elif re.search(r"high", output, re.IGNORECASE):
                    sev = "high"
                elif re.search(r"medium", output, re.IGNORECASE):
                    sev = "medium"
                elif re.search(r"low", output, re.IGNORECASE):
                    sev = "low"

                description = output.splitlines()[0][:250] if output else "N/A"

                v = Vulnerability(
                    scan_id=scan_id,
                    port=port,
                    script_id=script_id,
                    severity=sev,
                    description=description,
                    raw_output=output
                )
                db.add(v)
                count += 1
        db.commit()
        create_audit_log(
            db,
            f"Extracted {count} vulnerabilities from scan {scan_id}",
            "system"
        )
        return None
    except Exception as e:
        error_msg = f"Vulnerability extraction failed for scan {scan_id}: {e}"
        print(f"[!] {error_msg}")
        return error_msg
