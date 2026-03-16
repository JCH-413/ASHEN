"""
Tests for admin routes.
Covers: Issue #3 (double require_admin), Issue #6 (admin sessions).
"""


class TestTargets:
    def test_add_target_requires_auth(self, client):
        resp = client.post("/admin/targets", json={"ip_address": "10.10.10.10"})
        assert resp.status_code in (401, 403)

    def test_add_target_with_json_body(self, client, auth_headers):
        """Issue #1: /admin/targets should accept JSON body."""
        resp = client.post("/admin/targets", json={
            "ip_address": "10.10.10.10"
        }, headers=auth_headers)
        assert resp.status_code != 422, \
            f"Issue #1: /admin/targets rejects JSON body (422)."

    def test_add_duplicate_target(self, client, auth_headers):
        """Adding same IP twice should fail."""
        # First add
        client.post("/admin/targets", json={"ip_address": "10.10.10.11"}, headers=auth_headers)
        # Duplicate
        resp = client.post("/admin/targets", json={"ip_address": "10.10.10.11"}, headers=auth_headers)
        assert resp.status_code == 400

    def test_list_targets(self, client, auth_headers):
        resp = client.get("/admin/targets", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestSessions:
    def test_sessions_require_auth(self, client):
        resp = client.get("/admin/sessions")
        assert resp.status_code in (401, 403)

    def test_admin_sessions_visible(self, client, auth_headers, admin_token):
        """Issue #6: Admin sessions should be visible in /admin/sessions."""
        resp = client.get("/admin/sessions", headers=auth_headers)
        assert resp.status_code == 200
        sessions = resp.json()
        # After admin login, at least one session should exist
        # With the bug (inner join on user_id), admin sessions are hidden
        assert len(sessions) > 0, \
            "Issue #6: No sessions returned — admin sessions likely excluded by INNER JOIN"


class TestAuditLogs:
    def test_audit_logs_require_auth(self, client):
        resp = client.get("/admin/audit-logs")
        assert resp.status_code in (401, 403)

    def test_audit_logs_with_auth(self, client, auth_headers):
        resp = client.get("/admin/audit-logs", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestScanRequestReview:
    def test_review_requires_auth(self, client):
        resp = client.post("/admin/scan-requests/1/review", json={"approve": True})
        assert resp.status_code in (401, 403)

    def test_review_with_json_body(self, client, auth_headers):
        """Issue #1: review should accept JSON body."""
        resp = client.post("/admin/scan-requests/999/review", json={
            "approve": True
        }, headers=auth_headers)
        # 404 is fine (no such request), but should NOT be 422
        assert resp.status_code != 422, \
            f"Issue #1: review rejects JSON body (422)."
