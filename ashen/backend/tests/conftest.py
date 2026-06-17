"""
Shared fixtures for ASHEN backend tests.
Uses an in-memory SQLite database so tests don't touch the real DB.
"""
import os
# Force SQLite for tests BEFORE any app imports
os.environ["DATABASE_URL"] = "sqlite:///./test_ashen.db"
# Disable CSRF for unit tests (tested separately in test_csrf.py)
os.environ["CSRF_ENABLED"] = "false"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.db import Base, get_db
from app.core.security import hash_password
from app.main import app

# In-memory SQLite for tests
TEST_DATABASE_URL = "sqlite:///./test_ashen.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Create all tables once before any test runs."""
    # Import all models so they register with Base.metadata
    from app.models import admin, user, user_session, audit_log, target_system, scan_request, scan, vulnerability, exploit, report
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    import os
    try:
        if os.path.exists("./test_ashen.db"):
            os.remove("./test_ashen.db")
    except PermissionError:
        pass  # Windows file lock — cleaned up next run


@pytest.fixture(autouse=True)
def override_db():
    """Override the DB dependency for every test."""
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Clear rate-limit buckets before each test so counts don't bleed across tests."""
    from app.core.rate_limit import reset_rate_limits as _reset
    _reset()
    yield


@pytest.fixture
def client():
    """Fresh TestClient instance."""
    return TestClient(app)


@pytest.fixture
def db():
    """Direct DB session for setting up test data."""
    db = TestingSessionLocal()
    yield db
    db.close()


@pytest.fixture
def seed_admin(db):
    """Create a test admin in the DB."""
    from app.models.admin import Admin
    existing = db.query(Admin).filter(Admin.email == "testadmin@ashen.dev").first()
    if not existing:
        admin = Admin(
            name="Test Admin",
            email="testadmin@ashen.dev",
            password=hash_password("Admin123!")
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)
        return admin
    return existing


@pytest.fixture
def admin_token(client, seed_admin):
    """Get a valid admin JWT token."""
    # This tests the current state — might use query params or body
    # We try JSON body first; if that fails the test itself documents the bug
    resp = client.post("/auth/admin-login", json={"email": "testadmin@ashen.dev", "password": "Admin123!"})
    if resp.status_code == 200:
        return resp.json()["access_token"]
    # Fallback: try query params (current buggy behavior)
    resp = client.post("/auth/admin-login", params={"email": "testadmin@ashen.dev", "password": "Admin123!"})
    assert resp.status_code == 200, f"Admin login failed: {resp.text}"
    return resp.json()["access_token"]


@pytest.fixture
def seed_analyst(client, admin_token, db):
    """Create a test analyst user via the API."""
    from app.models.user import User
    existing = db.query(User).filter(User.email == "analyst@ashen.dev").first()
    if existing:
        return existing
    # Try JSON body first
    resp = client.post(
        "/auth/create-user",
        json={"name": "Test Analyst", "email": "analyst@ashen.dev", "password": "Analyst1!"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    if resp.status_code != 200:
        # Fallback to query params
        resp = client.post(
            "/auth/create-user",
            params={"name": "Test Analyst", "email": "analyst@ashen.dev", "password": "Analyst1!"},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
    user = db.query(User).filter(User.email == "analyst@ashen.dev").first()
    return user


@pytest.fixture
def analyst_token(client, seed_analyst):
    """Get a valid analyst JWT token."""
    resp = client.post("/auth/user-login", json={"email": "analyst@ashen.dev", "password": "Analyst1!"})
    if resp.status_code == 200:
        return resp.json()["access_token"]
    resp = client.post("/auth/user-login", params={"email": "analyst@ashen.dev", "password": "Analyst1!"})
    assert resp.status_code == 200, f"Analyst login failed: {resp.text}"
    return resp.json()["access_token"]


@pytest.fixture
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def analyst_headers(analyst_token):
    return {"Authorization": f"Bearer {analyst_token}"}
