"""
Phase 2 Backend Tests: IP validation, scan cancellation, exploit IP validation.
"""
from datetime import datetime
from unittest.mock import patch


def _seed_target(db, admin_id, ip="10.0.0.1"):
    from app.models.target_system import TargetSystem
    t = db.query(TargetSystem).filter(TargetSystem.ip_address == ip).first()
    if not t:
        t = TargetSystem(ip_address=ip, added_by=admin_id, authorized=True)
        db.add(t)
        db.commit()
        db.refresh(t)
    return t


def _seed_scan(db, user_id, target_id, session_id=1, status="running"):
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


# ── P2.1: IP Validation ─────────────────────────────────────────────

class TestIPValidation:
    def test_scan_rejects_invalid_ip(self, client, analyst_headers):
        resp = client.post("/scan/start", json={
            "ip_address": "not-an-ip",
            "ack_disclaimer": True,
        }, headers=analyst_headers)
        assert resp.status_code == 422

    def test_scan_rejects_empty_ip(self, client, analyst_headers):
        resp = client.post("/scan/start", json={
            "ip_address": "",
            "ack_disclaimer": True,
        }, headers=analyst_headers)
        assert resp.status_code == 422

    def test_scan_accepts_valid_ipv4(self, client, analyst_headers, db, seed_admin):
        _seed_target(db, seed_admin.admin_id, ip="10.0.0.10")
        from app.core.rate_limit import reset_rate_limits
        reset_rate_limits()

        with patch("app.api.scans.run_scan_background"):
            resp = client.post("/scan/start", json={
                "ip_address": "10.0.0.10",
                "ack_disclaimer": True,
            }, headers=analyst_headers)
        # Should succeed (200) or fail for other reasons, but not 422 (validation)
        assert resp.status_code != 422

    def test_scan_accepts_valid_ipv6(self, client, analyst_headers):
        resp = client.post("/scan/start", json={
            "ip_address": "::1",
            "ack_disclaimer": True,
        }, headers=analyst_headers)
        # Will likely be 403 (not authorized), but should NOT be 422
        assert resp.status_code != 422

    def test_exploit_rejects_invalid_ip(self, client, analyst_headers):
        resp = client.post(
            "/exploit/run",
            params={
                "target_ip": "bad-ip",
                "exploit_type": "ms17_010_check",
                "ack_disclaimer": True,
            },
            headers=analyst_headers,
        )
        assert resp.status_code == 422

    def test_exploit_rejects_empty_ip(self, client, analyst_headers):
        resp = client.post(
            "/exploit/run",
            params={
                "target_ip": "",
                "exploit_type": "ms17_010_check",
                "ack_disclaimer": True,
            },
            headers=analyst_headers,
        )
        assert resp.status_code == 422

    def test_admin_target_rejects_invalid_ip(self, client, auth_headers):
        resp = client.post("/admin/targets", json={
            "ip_address": "not-valid",
        }, headers=auth_headers)
        assert resp.status_code == 422

    def test_scan_request_rejects_invalid_ip(self, client, analyst_headers):
        resp = client.post("/scan/request-scan", json={
            "ip_address": "xyz",
            "reason": "testing",
        }, headers=analyst_headers)
        assert resp.status_code == 422


# ── P2.2: Scan Cancellation ─────────────────────────────────────────

class TestScanCancellation:
    def test_cancel_running_scan(self, client, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.20")
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id, status="running")

        resp = client.post(f"/scan/cancel/{scan.scan_id}", headers=analyst_headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"

    def test_cancel_queued_scan(self, client, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.21")
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id, status="queued")

        resp = client.post(f"/scan/cancel/{scan.scan_id}", headers=analyst_headers)
        assert resp.status_code == 200

    def test_cannot_cancel_completed_scan(self, client, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.22")
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id, status="completed")

        resp = client.post(f"/scan/cancel/{scan.scan_id}", headers=analyst_headers)
        assert resp.status_code == 409

    def test_non_owner_cannot_cancel(self, client, admin_token, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.23")
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id, status="running")

        # Create another analyst
        from app.models.user import User
        from app.core.security import hash_password
        other = db.query(User).filter(User.email == "cancel-test@ashen.dev").first()
        if not other:
            client.post(
                "/auth/create-user",
                json={"name": "Cancel Test", "email": "cancel-test@ashen.dev", "password": "Cancel1!"},
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        resp = client.post("/auth/user-login", json={"email": "cancel-test@ashen.dev", "password": "Cancel1!"})
        if resp.status_code != 200:
            resp = client.post("/auth/user-login", params={"email": "cancel-test@ashen.dev", "password": "Cancel1!"})
        other_token = resp.json()["access_token"]

        resp = client.post(
            f"/scan/cancel/{scan.scan_id}",
            headers={"Authorization": f"Bearer {other_token}"},
        )
        assert resp.status_code == 403

    def test_admin_can_cancel_any_scan(self, client, auth_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.24")
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id, status="running")

        resp = client.post(f"/scan/cancel/{scan.scan_id}", headers=auth_headers)
        assert resp.status_code == 200

    def test_cancel_nonexistent_scan(self, client, analyst_headers):
        resp = client.post("/scan/cancel/99999", headers=analyst_headers)
        assert resp.status_code == 404

    def test_cancel_requires_auth(self, client):
        resp = client.post("/scan/cancel/1")
        assert resp.status_code in (401, 403)
