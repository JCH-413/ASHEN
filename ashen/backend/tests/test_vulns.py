"""
Tests for vulnerability routes.
Covers: Issue #2 (no auth on /vulns routes).
"""


class TestVulnsAuth:
    def test_vulns_all_requires_auth(self, client):
        """Issue #2: /vulns/all must require authentication."""
        resp = client.get("/vulns/all")
        assert resp.status_code in (401, 403), \
            f"Issue #2: /vulns/all is PUBLIC (got {resp.status_code}). Should require JWT."

    def test_vulns_by_scan_requires_auth(self, client):
        """Issue #2: /vulns/by-scan/{id} must require authentication."""
        resp = client.get("/vulns/by-scan/1")
        assert resp.status_code in (401, 403), \
            f"Issue #2: /vulns/by-scan/1 is PUBLIC (got {resp.status_code}). Should require JWT."

    def test_vulns_all_with_auth(self, client, analyst_headers):
        """Authenticated request should succeed (empty list is fine)."""
        resp = client.get("/vulns/all", headers=analyst_headers)
        # Should return 200 with empty list, not 401/403
        assert resp.status_code == 200

    def test_vulns_by_scan_with_auth_not_found(self, client, analyst_headers):
        """Authenticated request for nonexistent scan should return 404."""
        resp = client.get("/vulns/by-scan/99999", headers=analyst_headers)
        assert resp.status_code == 404
