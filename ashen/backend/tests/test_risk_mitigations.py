"""
Tests for risk mitigations:
R1: Redis-backed rate limiter (tests in-memory path; Redis tested by integration)
R2: Subprocess kill on scan cancellation
R4: CSRF protection middleware
"""
import os
import subprocess
from unittest.mock import patch, MagicMock
from datetime import datetime


# ── R1: Rate Limiter Fallback ────────────────────────────────────────

class TestRateLimiterFallback:
    def test_in_memory_fallback_works(self):
        """Without REDIS_URL, rate limiter uses in-memory backend."""
        from app.core.rate_limit import _redis_client, _check_rate_memory, reset_rate_limits
        reset_rate_limits()
        # Should not raise for first call
        _check_rate_memory("test:key", 5, 60)

    def test_in_memory_enforces_limit(self):
        from app.core.rate_limit import _check_rate_memory, reset_rate_limits
        from fastapi import HTTPException
        import pytest
        reset_rate_limits()
        for _ in range(3):
            _check_rate_memory("test:enforce", 3, 60)
        with pytest.raises(HTTPException) as exc:
            _check_rate_memory("test:enforce", 3, 60)
        assert exc.value.status_code == 429
        reset_rate_limits()

    def test_redis_fallback_on_failure(self):
        """If Redis call raises, should fall back to in-memory."""
        from app.core import rate_limit
        from app.core.rate_limit import reset_rate_limits
        reset_rate_limits()

        # Temporarily pretend we have a Redis client that fails
        fake_redis = MagicMock()
        fake_redis.pipeline.side_effect = Exception("Connection refused")
        original = rate_limit._redis_client
        rate_limit._redis_client = fake_redis
        try:
            # Should not raise — falls back to in-memory
            rate_limit._check_rate("test:fallback", 5, 60)
        finally:
            rate_limit._redis_client = original
            reset_rate_limits()


# ── R2: Subprocess Kill on Cancel ────────────────────────────────────

class TestSubprocessKill:
    def test_register_and_kill(self):
        from app.services.scanner.nmap_scanner import (
            register_scan_process, kill_scan_process, unregister_scan_process
        )
        mock_proc = MagicMock(spec=subprocess.Popen)
        mock_proc.wait.return_value = 0

        register_scan_process(9999, mock_proc)
        result = kill_scan_process(9999)
        assert result is True
        mock_proc.terminate.assert_called_once()

    def test_kill_nonexistent_returns_false(self):
        from app.services.scanner.nmap_scanner import kill_scan_process
        assert kill_scan_process(88888) is False

    def test_unregister_cleans_up(self):
        from app.services.scanner.nmap_scanner import (
            register_scan_process, unregister_scan_process, kill_scan_process
        )
        mock_proc = MagicMock(spec=subprocess.Popen)
        register_scan_process(7777, mock_proc)
        unregister_scan_process(7777)
        # After unregister, kill should return False
        assert kill_scan_process(7777) is False

    def test_cancel_endpoint_calls_kill(self, client, analyst_headers, db, seed_admin, seed_analyst):
        """POST /scan/cancel should call kill_scan_process."""
        from app.models.scan import Scan
        from app.models.target_system import TargetSystem

        target = db.query(TargetSystem).filter(TargetSystem.ip_address == "10.0.0.40").first()
        if not target:
            target = TargetSystem(ip_address="10.0.0.40", added_by=seed_admin.admin_id)
            db.add(target)
            db.commit()
            db.refresh(target)

        scan = Scan(
            target_system_id=target.target_id,
            user_id=seed_analyst.user_id,
            session_id=1,
            status="running",
            start_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        with patch("app.api.scans.kill_scan_process", return_value=True) as mock_kill:
            resp = client.post(f"/scan/cancel/{scan.scan_id}", headers=analyst_headers)
            assert resp.status_code == 200
            mock_kill.assert_called_once_with(scan.scan_id)


# ── R4: CSRF Middleware ──────────────────────────────────────────────

class TestCSRFProtection:
    """Test CSRF middleware behavior directly (CSRF_ENABLED forced on)."""

    def test_csrf_blocks_post_without_header(self):
        """POST without X-CSRF-Token should be blocked when CSRF is enabled."""
        from app.core import csrf
        original = csrf.CSRF_ENABLED
        csrf.CSRF_ENABLED = True
        try:
            from fastapi.testclient import TestClient
            from app.main import app
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/scan/start", json={
                "ip_address": "10.0.0.1",
                "ack_disclaimer": True,
            })
            # Should get 403 CSRF, not 401/422
            assert resp.status_code == 403
            assert "csrf" in resp.json().get("detail", "").lower()
        finally:
            csrf.CSRF_ENABLED = original

    def test_csrf_allows_post_with_header(self):
        """POST with X-CSRF-Token should pass through to normal auth."""
        from app.core import csrf
        original = csrf.CSRF_ENABLED
        csrf.CSRF_ENABLED = True
        try:
            from fastapi.testclient import TestClient
            from app.main import app
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/scan/start", json={
                "ip_address": "10.0.0.1",
                "ack_disclaimer": True,
            }, headers={"X-CSRF-Token": "1"})
            # Should get past CSRF — will fail on auth (401/403), not CSRF
            assert resp.status_code != 403 or "csrf" not in resp.json().get("detail", "").lower()
        finally:
            csrf.CSRF_ENABLED = original

    def test_csrf_allows_get(self):
        """GET requests should not require CSRF header."""
        from app.core import csrf
        original = csrf.CSRF_ENABLED
        csrf.CSRF_ENABLED = True
        try:
            from fastapi.testclient import TestClient
            from app.main import app
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/")
            assert resp.status_code == 200
        finally:
            csrf.CSRF_ENABLED = original

    def test_csrf_exempts_login(self):
        """Login endpoints should be exempt from CSRF."""
        from app.core import csrf
        original = csrf.CSRF_ENABLED
        csrf.CSRF_ENABLED = True
        try:
            from fastapi.testclient import TestClient
            from app.main import app
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/auth/user-login", json={
                "email": "test@test.com",
                "password": "test",
            })
            # Should get 401 (bad creds), NOT 403 CSRF
            assert resp.status_code != 403 or "csrf" not in resp.json().get("detail", "").lower()
        finally:
            csrf.CSRF_ENABLED = original
