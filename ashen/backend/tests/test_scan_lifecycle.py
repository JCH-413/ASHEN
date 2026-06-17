"""
Tests for the Scan lifecycle seam (app/services/scan_lifecycle.py).

The weight sits on the two things the module was created to own: the
cancel-race guard (in one place now, no route bypass) and re-runnable,
idempotent Vulnerability extraction. Plus a thin route test for /re-extract.
"""
import json
from datetime import datetime

from app.services import scan_lifecycle
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability


SCAN_JSON = json.dumps({
    "hosts": [
        {"vulns": [
            {"port": "80", "id": "http-vuln-x", "output": "This is a CRITICAL flaw"},
            {"port": "21", "id": "ftp-anon", "output": "Anonymous login (medium severity)"},
        ]},
    ]
})


def _seed_scan(db, *, status="completed", user_id=1, results_json=None):
    scan = Scan(
        target_system_id=1,
        user_id=user_id,
        session_id=1,
        status=status,
        start_time=datetime(2025, 1, 1, 12, 0, 0),
        results_json=results_json,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


# ── the cancel-race guard, in one place ─────────────────────────────────


class TestStatusGuard:
    def test_mark_status_normal_transition(self, db):
        scan = _seed_scan(db, status="queued")
        assert scan_lifecycle.mark_status(db, scan.scan_id, "running", progress=20) is True
        db.refresh(scan)
        assert scan.status == "running"
        assert scan.progress == 20

    def test_mark_status_preserves_start_time(self, db):
        scan = _seed_scan(db, status="queued")
        original = scan.start_time
        scan_lifecycle.mark_status(db, scan.scan_id, "running")
        db.refresh(scan)
        assert scan.start_time == original

    def test_mark_status_cannot_override_cancelled(self, db):
        scan = _seed_scan(db, status="cancelled")
        assert scan_lifecycle.mark_status(db, scan.scan_id, "running", progress=50) is False
        db.refresh(scan)
        assert scan.status == "cancelled"
        assert scan.progress != 50

    def test_mark_status_missing_scan(self, db):
        assert scan_lifecycle.mark_status(db, 999999, "running") is False

    def test_finalize_preserves_cancelled(self, db):
        scan = _seed_scan(db, status="cancelled")
        scan_lifecycle.finalize(db, scan.scan_id, "completed", SCAN_JSON, None, "a@b.c")
        db.refresh(scan)
        assert scan.status == "cancelled"


class TestCancel:
    def test_cancel_running_scan(self, db):
        scan = _seed_scan(db, status="running")
        assert scan_lifecycle.cancel(db, scan, "a@b.c") is True
        db.refresh(scan)
        assert scan.status == "cancelled"
        assert scan.end_time is not None

    def test_cancel_queued_scan(self, db):
        scan = _seed_scan(db, status="queued")
        assert scan_lifecycle.cancel(db, scan, "a@b.c") is True

    def test_cannot_cancel_completed_scan(self, db):
        scan = _seed_scan(db, status="completed")
        assert scan_lifecycle.cancel(db, scan, "a@b.c") is False
        db.refresh(scan)
        assert scan.status == "completed"


# ── re-runnable, idempotent extraction ──────────────────────────────────


class TestExtraction:
    def test_extract_inserts_with_inferred_severity(self, db):
        scan = _seed_scan(db)
        err = scan_lifecycle.extract_vulnerabilities(db, scan.scan_id, SCAN_JSON)
        assert err is None
        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.scan_id).all()
        assert len(vulns) == 2
        sev = {v.script_id: v.severity for v in vulns}
        assert sev["http-vuln-x"] == "critical"
        assert sev["ftp-anon"] == "medium"

    def test_re_extract_replace_does_not_duplicate(self, db):
        scan = _seed_scan(db)
        scan_lifecycle.extract_vulnerabilities(db, scan.scan_id, SCAN_JSON)
        scan_lifecycle.extract_vulnerabilities(db, scan.scan_id, SCAN_JSON, replace=True)
        count = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.scan_id).count()
        assert count == 2  # replaced, not appended

    def test_re_extract_recomputes_severity(self, db):
        scan = _seed_scan(db)
        # A stale row with the wrong severity, as an old Severity-rule run would leave.
        db.add(Vulnerability(
            scan_id=scan.scan_id, port="80", script_id="http-vuln-x",
            severity="unknown", description="stale", raw_output="old",
        ))
        db.commit()
        scan_lifecycle.extract_vulnerabilities(db, scan.scan_id, SCAN_JSON, replace=True)
        row = db.query(Vulnerability).filter(
            Vulnerability.scan_id == scan.scan_id,
            Vulnerability.script_id == "http-vuln-x",
        ).first()
        assert row.severity == "critical"  # recomputed

    def test_extract_reads_stored_results_when_json_omitted(self, db):
        scan = _seed_scan(db, results_json=SCAN_JSON)
        err = scan_lifecycle.extract_vulnerabilities(db, scan.scan_id, replace=True)
        assert err is None
        assert db.query(Vulnerability).filter(Vulnerability.scan_id == scan.scan_id).count() == 2

    def test_extract_unwraps_completed_with_errors_envelope(self, db):
        scan = _seed_scan(db)
        wrapped = json.dumps({"scan_results": json.loads(SCAN_JSON), "extraction_error": "boom"})
        err = scan_lifecycle.extract_vulnerabilities(db, scan.scan_id, wrapped, replace=True)
        assert err is None
        assert db.query(Vulnerability).filter(Vulnerability.scan_id == scan.scan_id).count() == 2


# ── thin route test: /re-extract goes through the seam ───────────────────


class TestReExtractRoute:
    def test_owner_can_re_extract(self, client, analyst_headers, seed_analyst, db):
        scan = _seed_scan(db, status="completed_with_errors", user_id=seed_analyst.user_id,
                          results_json=SCAN_JSON)
        resp = client.post(f"/scan/{scan.scan_id}/re-extract", headers=analyst_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["vulnerabilities"] == 2
        assert body["status"] == "completed"  # promoted from completed_with_errors
        db.refresh(scan)
        assert scan.status == "completed"

    def test_cannot_re_extract_non_completed(self, client, analyst_headers, seed_analyst, db):
        scan = _seed_scan(db, status="running", user_id=seed_analyst.user_id)
        resp = client.post(f"/scan/{scan.scan_id}/re-extract", headers=analyst_headers)
        assert resp.status_code == 409

    def test_non_owner_cannot_re_extract(self, client, analyst_headers, seed_analyst, db):
        scan = _seed_scan(db, status="completed", user_id=999, results_json=SCAN_JSON)
        resp = client.post(f"/scan/{scan.scan_id}/re-extract", headers=analyst_headers)
        assert resp.status_code == 403
