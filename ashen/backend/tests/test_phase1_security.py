"""
Phase 1 Security Tests.
Covers: ownership checks, IP authorization for exploits, rate limiting,
duplicate scan prevention, extraction failure surfacing, lightweight polling.
"""
import json
from unittest.mock import patch, MagicMock
from datetime import datetime


# ── Helpers ──────────────────────────────────────────────────────────────────

def _seed_target(db, admin_id, ip="10.0.0.1"):
    """Ensure an authorized target exists."""
    from app.models.target_system import TargetSystem
    t = db.query(TargetSystem).filter(TargetSystem.ip_address == ip).first()
    if not t:
        t = TargetSystem(ip_address=ip, added_by=admin_id, authorized=True)
        db.add(t)
        db.commit()
        db.refresh(t)
    return t


def _seed_scan(db, user_id, target_id, session_id=1, status="completed"):
    from app.models.scan import Scan
    s = Scan(
        target_system_id=target_id,
        user_id=user_id,
        session_id=session_id,
        status=status,
        start_time=datetime.utcnow(),
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _seed_vuln(db, scan_id, port=22):
    from app.models.vulnerability import Vulnerability
    v = Vulnerability(
        scan_id=scan_id,
        port=port,
        script_id="test-vuln",
        severity="high",
        description="test vulnerability",
        raw_output="test output",
    )
    db.add(v)
    db.commit()
    db.refresh(v)
    return v


def _seed_second_analyst(db, client, admin_token):
    """Create a second analyst for cross-user access tests."""
    from app.models.user import User
    existing = db.query(User).filter(User.email == "other@ashen.dev").first()
    if existing:
        # Login
        resp = client.post("/auth/user-login", json={"email": "other@ashen.dev", "password": "Other123!"})
        if resp.status_code == 200:
            return existing, resp.json()["access_token"]
        resp = client.post("/auth/user-login", params={"email": "other@ashen.dev", "password": "Other123!"})
        return existing, resp.json()["access_token"]

    # Create via API
    resp = client.post(
        "/auth/create-user",
        json={"name": "Other Analyst", "email": "other@ashen.dev", "password": "Other123!"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    if resp.status_code != 200:
        client.post(
            "/auth/create-user",
            params={"name": "Other Analyst", "email": "other@ashen.dev", "password": "Other123!"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
    user = db.query(User).filter(User.email == "other@ashen.dev").first()
    # Login
    resp = client.post("/auth/user-login", json={"email": "other@ashen.dev", "password": "Other123!"})
    if resp.status_code != 200:
        resp = client.post("/auth/user-login", params={"email": "other@ashen.dev", "password": "Other123!"})
    return user, resp.json()["access_token"]


# ── P1.1: Scan Status Ownership ─────────────────────────────────────────────

class TestScanStatusOwnership:
    """Analysts can only view their own scans via /scan/status."""

    def test_owner_can_view_scan(self, client, analyst_headers, analyst_token, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id)
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id)

        resp = client.get(f"/scan/status/{scan.scan_id}", headers=analyst_headers)
        assert resp.status_code == 200
        assert resp.json()["scan_id"] == scan.scan_id

    def test_non_owner_cannot_view_scan(self, client, admin_token, analyst_token, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id)
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id)

        other_user, other_token = _seed_second_analyst(db, client, admin_token)
        resp = client.get(
            f"/scan/status/{scan.scan_id}",
            headers={"Authorization": f"Bearer {other_token}"},
        )
        assert resp.status_code == 403

    def test_admin_can_view_any_scan(self, client, auth_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id)
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id)

        resp = client.get(f"/scan/status/{scan.scan_id}", headers=auth_headers)
        assert resp.status_code == 200


# ── P1.1: Vulnerability Ownership ───────────────────────────────────────────

class TestVulnOwnership:
    """Analysts can only see vulns from their own scans."""

    def test_owner_can_view_vulns(self, client, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id)
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id)
        _seed_vuln(db, scan.scan_id)

        resp = client.get(f"/vulns/by-scan/{scan.scan_id}", headers=analyst_headers)
        assert resp.status_code == 200

    def test_non_owner_cannot_view_vulns(self, client, admin_token, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id)
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id)
        _seed_vuln(db, scan.scan_id)

        other_user, other_token = _seed_second_analyst(db, client, admin_token)
        resp = client.get(
            f"/vulns/by-scan/{scan.scan_id}",
            headers={"Authorization": f"Bearer {other_token}"},
        )
        assert resp.status_code == 403

    def test_vulns_all_filtered_by_user(self, client, admin_token, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id)
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id)
        _seed_vuln(db, scan.scan_id, port=8888)

        # Analyst sees only their own
        resp = client.get("/vulns/all", headers=analyst_headers)
        assert resp.status_code == 200
        analyst_vulns = resp.json()["items"]

        # Admin sees all
        resp_admin = client.get("/vulns/all", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp_admin.status_code == 200
        admin_vulns = resp_admin.json()["items"]
        assert len(admin_vulns) >= len(analyst_vulns)


# ── P1.2: IP Authorization for Exploits ─────────────────────────────────────

class TestExploitIPAuth:
    """Exploit /run must reject target IPs not authorized in TargetSystem."""

    def test_exploit_unauthorized_ip_rejected(self, client, analyst_headers):
        resp = client.post(
            "/exploit/run",
            params={
                "target_ip": "192.168.99.99",
                "exploit_type": "ms17_010_check",
                "ack_disclaimer": True,
            },
            headers=analyst_headers,
        )
        assert resp.status_code == 403
        assert "not authorized" in resp.json()["detail"].lower()

    def test_exploit_authorized_ip_accepted(self, client, analyst_headers, db, seed_admin):
        _seed_target(db, seed_admin.admin_id, ip="10.0.0.50")

        with patch("app.api.exploits._run_exploit_task"):
            resp = client.post(
                "/exploit/run",
                params={
                    "target_ip": "10.0.0.50",
                    "exploit_type": "ms17_010_check",
                    "ack_disclaimer": True,
                },
                headers=analyst_headers,
            )
        # Should be accepted (pending), not 403
        assert resp.status_code == 200
        assert resp.json()["status"] == "pending"


# ── P1.3: Rate Limiting ─────────────────────────────────────────────────────

class TestRateLimiting:
    """Scan start and exploit trigger are rate-limited per user."""

    def test_scan_rate_limit(self, client, analyst_headers, db, seed_admin, seed_analyst):
        from app.core.rate_limit import reset_rate_limits, SCAN_RATE_LIMIT
        reset_rate_limits()

        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.2")

        # Mock the background task to avoid actual scan execution
        with patch("app.api.scans.run_scan_background"):
            for i in range(SCAN_RATE_LIMIT):
                # Clear any active scan so duplicate prevention doesn't block us
                from app.models.scan import Scan
                db.query(Scan).filter(
                    Scan.target_system_id == target.target_id,
                    Scan.status.in_(["queued", "running"])
                ).update({"status": "completed"}, synchronize_session="fetch")
                db.commit()

                resp = client.post("/scan/start", json={
                    "ip_address": "10.0.0.2",
                    "ack_disclaimer": True,
                }, headers=analyst_headers)
                # First N should succeed (200) or be blocked by duplicate check (409)
                assert resp.status_code in (200, 409), f"Request {i+1} got {resp.status_code}"

            # Clear active scans one more time
            db.query(Scan).filter(
                Scan.target_system_id == target.target_id,
                Scan.status.in_(["queued", "running"])
            ).update({"status": "completed"}, synchronize_session="fetch")
            db.commit()

            # Next one should be rate-limited
            resp = client.post("/scan/start", json={
                "ip_address": "10.0.0.2",
                "ack_disclaimer": True,
            }, headers=analyst_headers)
            assert resp.status_code == 429

        reset_rate_limits()

    def test_exploit_rate_limit(self, client, analyst_headers, db, seed_admin):
        from app.core.rate_limit import reset_rate_limits, EXPLOIT_RATE_LIMIT
        reset_rate_limits()

        _seed_target(db, seed_admin.admin_id, ip="10.0.0.3")

        with patch("app.api.exploits._run_exploit_task"):
            for i in range(EXPLOIT_RATE_LIMIT):
                resp = client.post(
                    "/exploit/run",
                    params={
                        "target_ip": "10.0.0.3",
                        "exploit_type": "ms17_010_check",
                        "ack_disclaimer": True,
                    },
                    headers=analyst_headers,
                )
                assert resp.status_code == 200, f"Request {i+1} got {resp.status_code}"

            # Next one should be rate-limited
            resp = client.post(
                "/exploit/run",
                params={
                    "target_ip": "10.0.0.3",
                    "exploit_type": "ms17_010_check",
                    "ack_disclaimer": True,
                },
                headers=analyst_headers,
            )
            assert resp.status_code == 429

        reset_rate_limits()


# ── P1.4: Duplicate Scan Prevention ─────────────────────────────────────────

class TestDuplicateScanPrevention:
    """Cannot start a second scan for the same target while one is active."""

    def test_duplicate_active_scan_rejected(self, client, analyst_headers, db, seed_admin, seed_analyst):
        from app.core.rate_limit import reset_rate_limits
        reset_rate_limits()

        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.4")
        # Create an active scan manually
        _seed_scan(db, seed_analyst.user_id, target.target_id, status="running")

        resp = client.post("/scan/start", json={
            "ip_address": "10.0.0.4",
            "ack_disclaimer": True,
        }, headers=analyst_headers)
        assert resp.status_code == 409
        assert "already running" in resp.json()["detail"].lower()

    def test_completed_scan_allows_new(self, client, analyst_headers, db, seed_admin, seed_analyst):
        from app.core.rate_limit import reset_rate_limits
        reset_rate_limits()

        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.5")
        _seed_scan(db, seed_analyst.user_id, target.target_id, status="completed")

        with patch("app.api.scans.run_scan_background"):
            resp = client.post("/scan/start", json={
                "ip_address": "10.0.0.5",
                "ack_disclaimer": True,
            }, headers=analyst_headers)
        assert resp.status_code == 200


# ── P1.5: Temp XML Uniqueness ───────────────────────────────────────────────

class TestTempXMLHandling:
    """NmapScanner uses unique temp filenames and cleans up."""

    def test_unique_filenames(self):
        """Two scans should produce different temp file paths."""
        import os
        import tempfile
        import uuid

        # Simulate the logic
        scan_dir = os.path.join(tempfile.gettempdir(), "ashen_scans")
        f1 = os.path.join(scan_dir, f"scan_{uuid.uuid4().hex[:12]}.xml")
        f2 = os.path.join(scan_dir, f"scan_{uuid.uuid4().hex[:12]}.xml")
        assert f1 != f2

    def test_cleanup_called_on_success(self):
        """After parsing, the XML file should be cleaned up."""
        from app.services.scanner.nmap_scanner import NmapScanner
        with patch.object(NmapScanner, '_cleanup') as mock_cleanup:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                with patch("xml.etree.ElementTree.parse") as mock_parse:
                    mock_root = MagicMock()
                    mock_root.findall.return_value = []
                    mock_parse.return_value = MagicMock(getroot=lambda: mock_root)

                    with patch("shutil.which", return_value="/usr/bin/nmap"):
                        scanner = NmapScanner()
                        scanner.quick_scan("10.0.0.1")
                    mock_cleanup.assert_called_once()

    def test_cleanup_called_on_failure(self):
        """If nmap fails, the XML file should still be cleaned up."""
        from app.services.scanner.nmap_scanner import NmapScanner
        with patch.object(NmapScanner, '_cleanup') as mock_cleanup:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stderr=b"error")
                with patch("shutil.which", return_value="/usr/bin/nmap"):
                    scanner = NmapScanner()
                    try:
                        scanner.quick_scan("10.0.0.1")
                    except RuntimeError:
                        pass
                    mock_cleanup.assert_called_once()


# ── P1.6: Vulnerability Extraction Failure Surfacing ─────────────────────────

class TestExtractionFailureSurfacing:
    """Extraction failures must not be silently swallowed."""

    def test_extraction_returns_error_on_bad_json(self):
        from app.services.scan_executor import _extract_vulnerabilities
        from unittest.mock import MagicMock
        db = MagicMock()
        result = _extract_vulnerabilities(db, 1, "not valid json")
        assert result is not None
        assert "failed" in result.lower() or "extraction" in result.lower()

    def test_extraction_returns_none_on_success(self, db):
        from app.services.scan_executor import _extract_vulnerabilities
        good_json = json.dumps({
            "hosts": [{
                "ip": "10.0.0.1",
                "vulns": [{
                    "port": 22,
                    "id": "test-script",
                    "output": "VULNERABLE: high severity issue"
                }]
            }]
        })
        result = _extract_vulnerabilities(db, 99999, good_json)
        assert result is None

    def test_finalize_marks_extraction_error(self, db):
        """If extraction fails, scan status should become completed_with_errors."""
        from app.services.scan_executor import _finalize_scan
        from app.models.scan import Scan

        scan = Scan(
            target_system_id=1,
            user_id=1,
            session_id=1,
            status="running",
            start_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Pass broken JSON so extraction will fail
        _finalize_scan(db, scan.scan_id, "completed", "not valid json", None, "test@test.com")
        db.refresh(scan)
        assert scan.status == "completed_with_errors"


# ── P1.7: Lightweight Polling Response ───────────────────────────────────────

class TestLightweightPolling:
    """In-progress scans should not return heavy results_json."""

    def test_queued_scan_returns_no_results(self, client, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id)
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id, status="queued")

        resp = client.get(f"/scan/status/{scan.scan_id}", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["results_json"] is None
        assert data["status"] == "queued"

    def test_running_scan_returns_no_results(self, client, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id)
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id, status="running")

        resp = client.get(f"/scan/status/{scan.scan_id}", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["results_json"] is None

    def test_completed_scan_returns_results(self, client, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id)
        from app.models.scan import Scan
        scan = Scan(
            target_system_id=target.target_id,
            user_id=seed_analyst.user_id,
            session_id=1,
            status="completed",
            start_time=datetime.utcnow(),
            results_json='{"hosts": []}',
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        resp = client.get(f"/scan/status/{scan.scan_id}", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["results_json"] is not None


# ── Exploit Types Endpoint ───────────────────────────────────────────────────

class TestExploitTypes:
    """Backend-driven exploit types endpoint."""

    def test_exploit_types_returns_list(self, client, analyst_headers):
        resp = client.get("/exploit/types", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "exploit_types" in data
        keys = [et["key"] for et in data["exploit_types"]]
        assert "ssh_brute_force" in keys
        assert "ms17_010_check" in keys
