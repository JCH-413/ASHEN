"""
Tests for /users routes.
"""


class TestUsersMe:
    def test_users_me_requires_auth(self, client):
        resp = client.get("/users/me")
        assert resp.status_code in (401, 403)

    def test_users_me_as_analyst(self, client, analyst_headers):
        resp = client.get("/users/me", headers=analyst_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "email" in body

    def test_users_me_admin_forbidden(self, client, auth_headers):
        resp = client.get("/users/me", headers=auth_headers)
        assert resp.status_code == 403
