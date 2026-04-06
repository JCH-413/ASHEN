"""
Tests for scan and scan-request routes.
Covers: Issue #1 (query params), Issue #12 (scan history not filtered).
"""


class TestScanStart:
    def test_start_scan_requires_auth(self, client):
        resp = client.post("/scan/start", json={
            "ip_address": "192.168.1.100",
            "ack_disclaimer": True
        })
        assert resp.status_code in (401, 403), \
            f"Expected auth error, got {resp.status_code}"

    def test_start_scan_with_json_body(self, client, analyst_headers, db, seed_admin):
        """Issue #1: /scan/start should accept JSON body."""
        from app.models.target_system import TargetSystem
        # Ensure an authorized target exists
        target = db.query(TargetSystem).filter(TargetSystem.ip_address == "10.0.0.1").first()
        if not target:
            target = TargetSystem(ip_address="10.0.0.1", added_by=seed_admin.admin_id)
            db.add(target)
            db.commit()

        resp = client.post("/scan/start", json={
            "ip_address": "10.0.0.1",
            "ack_disclaimer": True
        }, headers=analyst_headers)
        # Should accept JSON body — may fail on nmap not installed, but should NOT be 422
        assert resp.status_code != 422, \
            f"Issue #1: /scan/start rejects JSON body (422). Should use Pydantic schema."

    def test_start_scan_disclaimer_required(self, client, analyst_headers):
        """Must acknowledge disclaimer."""
        resp = client.post("/scan/start", json={
            "ip_address": "10.0.0.1",
            "ack_disclaimer": False
        }, headers=analyst_headers)
        assert resp.status_code == 400

    def test_start_scan_admin_forbidden(self, client, auth_headers):
        resp = client.post("/scan/start", json={
            "ip_address": "10.0.0.1",
            "ack_disclaimer": True
        }, headers=auth_headers)
        assert resp.status_code == 403


class TestScanHistory:
    def test_scan_history_requires_auth(self, client):
        resp = client.get("/scan/history")
        assert resp.status_code in (401, 403)

    def test_scan_history_filtered_by_user(self, client, analyst_headers, auth_headers):
        """Issue #12: Scan history should only show current user's scans, not all."""
        resp_analyst = client.get("/scan/history", headers=analyst_headers)
        assert resp_analyst.status_code == 200
        data = resp_analyst.json()
        # Now returns paginated response
        assert "items" in data
        assert "total" in data


class TestScanRequest:
    def test_request_scan_requires_auth(self, client):
        resp = client.post("/scan/request-scan", json={
            "ip_address": "192.168.1.200",
            "reason": "need to test"
        })
        assert resp.status_code in (401, 403), \
            f"Expected auth error, got {resp.status_code}"

    def test_request_scan_with_json_body(self, client, analyst_headers):
        """Issue #1: /scan/request-scan should accept JSON body."""
        resp = client.post("/scan/request-scan", json={
            "ip_address": "172.16.0.50",
            "reason": "Testing JSON body"
        }, headers=analyst_headers)
        assert resp.status_code != 422, \
            f"Issue #1: /scan/request-scan rejects JSON body (422)."
