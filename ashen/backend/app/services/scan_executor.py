"""
scan_executor.py
Asynchronous scan executor that integrates the local NmapScanner class.
This framework does not execute scans here; enable the marked section
inside your own VM environment.
"""

import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy.orm import Session
from app.models.scan import Scan
from app.utils.logging_utils import create_audit_log
from app.core.db import SessionLocal

# You will import your real wrapper inside your VM
from app.services.scanner.nmap_scanner import NmapScanner

MAX_CONCURRENT_SCANS = 10
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds between retries
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS)


def run_scan_background(scan_id: int, ip: str, user_email: str):
    """Synchronous scan function — suitable for FastAPI BackgroundTasks."""
    _perform_scan_with_retries(scan_id, ip, user_email)


def _perform_scan_with_retries(scan_id: int, ip: str, user_email: str):
    """Perform scan with up to MAX_RETRIES attempts using the NmapScanner wrapper."""
    db: Session = SessionLocal()
    attempt = 0
    success = False
    result_output = None
    error_message = None

    while attempt < MAX_RETRIES and not success:
        attempt += 1
        create_audit_log(db, f"Scan {scan_id} attempt {attempt} started for {ip}", user_email)

        try:
            _update_scan_status(db, scan_id, "running")

            # ------------------------------------------------------------------
            # In your own environment, uncomment the following lines:
            #
            # 
            scanner = NmapScanner()
            # 
            parsed = scanner.quick_scan(ip)
            # 
            result_output = json.dumps(parsed, indent=2)
            # ------------------------------------------------------------------

            # Placeholder result (no real scan executed here)
            """
            result_output = json.dumps({
                "target": ip,
                "duration": 1.2,
                "hosts": [{
                    "ip": ip,
                    "state": "up",
                    "protocols": {"tcp": [{"port": 22, "state": "open", "name": "ssh"}]},
                    "vulns": [{"port": 22, "id": "simulated", "output": "Example vulnerability output"}]
                }]
            }, indent=2)
            """
            success = True

        except Exception as e:
            error_message = str(e)
            create_audit_log(db, f"Scan {scan_id} attempt {attempt} failed: {error_message}", user_email)
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)

    final_status = "completed" if success else "failed"
    _finalize_scan(db, scan_id, final_status, result_output, error_message, user_email)
    db.close()


def _update_scan_status(db: Session, scan_id: int, status: str):
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    scan.status = status
    db.commit()


def _finalize_scan(db: Session, scan_id: int, status: str, result_output: str, error_message: str, user_email: str):
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    scan.status = status
    scan.end_time = datetime.utcnow()
    scan.results_json = result_output if result_output else json.dumps({"error": error_message})
    db.commit()

    msg = f"Scan {scan_id} {'completed successfully' if status == 'completed' else 'failed after retries'}"
    create_audit_log(db, msg, user_email)
    if status == "completed" and result_output:
    	_extract_vulnerabilities(db, scan_id, result_output)

    
# this module is just for parsing vuln into DB
import re
from app.models.vulnerability import Vulnerability

def _extract_vulnerabilities(db, scan_id: int, result_json: str):
    """
    Parse Nmap JSON results and insert vulnerabilities into DB.
    """
    try:
        data = json.loads(result_json)
        hosts = data.get("hosts", [])
        for host in hosts:
            for vuln in host.get("vulns", []):
                port = vuln.get("port")
                script_id = vuln.get("id")
                output = vuln.get("output", "")

                # --- Severity inference ---
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
        db.commit()
    except Exception as e:
        print(f"[!] Vulnerability extraction failed for scan {scan_id}: {e}")

