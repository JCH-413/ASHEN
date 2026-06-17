"""
scan_executor.py
Asynchronous scan executor that integrates the local NmapScanner class.
P1.6: Vulnerability extraction failures are logged and surfaced in scan status.
"""

import json
import time
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy.orm import Session
from app.models.scan import Scan
from app.utils.logging_utils import create_audit_log
from app.core.db import SessionLocal
from app.services.scanner.nmap_scanner import NmapScanner
from app.services import scan_lifecycle

# Status transitions and Vulnerability extraction now live in scan_lifecycle.
# These aliases preserve the executor's internal call sites (and existing imports
# from this module) while the logic lives in one place.
_update_scan_status = scan_lifecycle.mark_status
_finalize_scan = scan_lifecycle.finalize
_extract_vulnerabilities = scan_lifecycle.extract_vulnerabilities

MAX_CONCURRENT_SCANS = 10
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds between retries
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS)


def _is_scan_cancelled(db: Session, scan_id: int) -> bool:
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    return bool(scan and scan.status == "cancelled")


def _is_cancelled_error(error_message: str | None) -> bool:
    return bool(error_message and "cancel" in error_message.lower())


def _is_non_retryable_scan_error(error_message: str | None) -> bool:
    if not error_message:
        return False
    msg = error_message.lower()
    return (
        "not found" in msg
        or "unreachable" in msg
        or "invalid ip" in msg
    )


def _count_open_ports(parsed: dict) -> int:
    total = 0
    for host in parsed.get("hosts", []):
        protocols = host.get("protocols", {}) or {}
        for ports in protocols.values():
            for p in ports:
                if str((p or {}).get("state", "")).lower() == "open":
                    total += 1
    return total


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
    completion_note = None

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
            open_ports = _count_open_ports(parsed)
            if open_ports == 0:
                completion_note = "Host reachable, but no open ports were discovered."
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

            if _is_non_retryable_scan_error(error_message):
                create_audit_log(db, f"Scan {scan_id} failed (non-retryable): {error_message}", user_email)
                break

            create_audit_log(db, f"Scan {scan_id} attempt {attempt} failed: {error_message}", user_email)
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)

    final_status = "cancelled" if cancelled else ("completed" if success else "failed")
    _finalize_scan(db, scan_id, final_status, result_output, error_message, user_email, completion_note)
    db.close()
