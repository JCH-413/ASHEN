"""
Tests for authentication routes.
Covers: Issue #1 (query params vs body), login/logout, create-user.
"""


class TestAdminLogin:
    def test_admin_login_with_json_body(self, client, seed_admin):
        """Issue #1: Login should accept JSON body, not query params."""
        resp = client.post("/auth/admin-login", json={
            "email": "testadmin@ashen.dev",
            "password": "Admin123!"
        })
        assert resp.status_code == 200, f"Expected JSON body login to work, got {resp.status_code}: {resp.text}"
        assert "access_token" in resp.json()

    def test_admin_login_wrong_password(self, client, seed_admin):
        resp = client.post("/auth/admin-login", json={
            "email": "testadmin@ashen.dev",
            "password": "WrongPass"
        })
        assert resp.status_code == 401

    def test_admin_login_nonexistent(self, client):
        resp = client.post("/auth/admin-login", json={
            "email": "nobody@ashen.dev",
            "password": "whatever"
        })
        assert resp.status_code == 401


class TestUserLogin:
    def test_user_login_with_json_body(self, client, seed_analyst):
        """Issue #1: Login should accept JSON body."""
        resp = client.post("/auth/user-login", json={
            "email": "analyst@ashen.dev",
            "password": "Analyst1!"
        })
        assert resp.status_code == 200, f"Expected JSON body login to work, got {resp.status_code}: {resp.text}"
        assert "access_token" in resp.json()


class TestCreateUser:
    def test_create_user_requires_auth(self, client):
        """Create-user must require admin JWT."""
        resp = client.post("/auth/create-user", json={
            "name": "Hacker",
            "email": "hack@test.com",
            "password": "pass123"
        })
        assert resp.status_code in (401, 403), f"Expected auth error, got {resp.status_code}"

    def test_create_user_with_json_body(self, client, auth_headers):
        """Issue #1: create-user should accept JSON body."""
        resp = client.post("/auth/create-user", json={
            "name": "New User",
            "email": "newuser@ashen.dev",
            "password": "NewUser1!"
        }, headers=auth_headers)
        assert resp.status_code == 200, f"Expected JSON body create-user to work, got {resp.status_code}: {resp.text}"

    def test_create_user_duplicate(self, client, auth_headers, seed_analyst):
        """Should reject duplicate email."""
        resp = client.post("/auth/create-user", json={
            "name": "Duplicate",
            "email": "analyst@ashen.dev",
            "password": "Dup12345"
        }, headers=auth_headers)
        assert resp.status_code == 400


class TestLogout:
    def test_admin_logout(self, client, admin_token):
        resp = client.post("/auth/admin-logout", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200

    def test_user_logout(self, client, analyst_token):
        resp = client.post("/auth/user-logout", headers={"Authorization": f"Bearer {analyst_token}"})
        assert resp.status_code == 200

    def test_admin_logout_no_token(self, client):
        resp = client.post("/auth/admin-logout")
        assert resp.status_code in (401, 403)

    def test_user_logout_no_token(self, client):
        resp = client.post("/auth/user-logout")
        assert resp.status_code in (401, 403)
