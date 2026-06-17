"""
Tests for the authorisation seam (app/core/authz.py).

The weight sits on the seam itself — the disclaimer coercion and the two target
gates, each in isolation — plus one thin assertion per wired route that the guard
is actually attached (including that the AI/reports drift is now closed).
"""
import pytest
from fastapi import HTTPException

from app.core.authz import _truthy, _gate_target_ip, _gate_scan_target


# ── helpers ─────────────────────────────────────────────────────────────


def _seed_target(db, ip, *, authorized=True):
    from app.models.target_system import TargetSystem
    from app.models.admin import Admin

    admin = db.query(Admin).first()
    t = TargetSystem(ip_address=ip, added_by=admin.admin_id, authorized=authorized)
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def _seed_scan(db, target_id, user_id):
    from app.models.scan import Scan

    s = Scan(target_system_id=target_id, user_id=user_id, status="completed")
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


# ── disclaimer coercion (bool body vs string query param) ───────────────


class TestTruthy:
    @pytest.mark.parametrize(
        "value,expected",
        [
            (True, True), (False, False),
            ("true", True), ("True", True), ("1", True), ("yes", True), ("on", True),
            ("false", False), ("0", False), ("", False), ("  ", False), (None, False),
        ],
    )
    def test_truthy(self, value, expected):
        assert _truthy(value) is expected


# ── the raw-IP gate (scans, exploits) ───────────────────────────────────


class TestTargetGate:
    def test_authorised_ip_passes(self, db, seed_admin):
        _seed_target(db, "10.20.0.1", authorized=True)
        _gate_target_ip(db, "10.20.0.1")  # must not raise

    def test_authorised_ip_tolerates_whitespace(self, db, seed_admin):
        _seed_target(db, "10.20.0.5", authorized=True)
        _gate_target_ip(db, "  10.20.0.5  ")

    def test_unauthorised_ip_is_403(self, db, seed_admin):
        _seed_target(db, "10.20.0.2", authorized=False)
        with pytest.raises(HTTPException) as e:
            _gate_target_ip(db, "10.20.0.2")
        assert e.value.status_code == 403

    def test_unknown_ip_is_403(self, db, seed_admin):
        with pytest.raises(HTTPException) as e:
            _gate_target_ip(db, "203.0.113.77")
        assert e.value.status_code == 403

    def test_malformed_ip_is_422(self, db):
        with pytest.raises(HTTPException) as e:
            _gate_target_ip(db, "not-an-ip")
        assert e.value.status_code == 422


# ── the Scan-derived gate (AI guidance) ─────────────────────────────────


class TestScanTargetGate:
    def test_authorised_scan_passes(self, db, seed_admin, seed_analyst):
        t = _seed_target(db, "10.21.0.1", authorized=True)
        s = _seed_scan(db, t.target_id, seed_analyst.user_id)
        _gate_scan_target(db, s.scan_id)  # must not raise

    def test_unauthorised_scan_target_is_403(self, db, seed_admin, seed_analyst):
        t = _seed_target(db, "10.21.0.2", authorized=False)
        s = _seed_scan(db, t.target_id, seed_analyst.user_id)
        with pytest.raises(HTTPException) as e:
            _gate_scan_target(db, s.scan_id)
        assert e.value.status_code == 403

    def test_missing_scan_is_404(self, db):
        with pytest.raises(HTTPException) as e:
            _gate_scan_target(db, 999999)
        assert e.value.status_code == 404


# ── thin per-route wiring: the guard is attached ────────────────────────


class TestScanRouteWiring:
    def test_admin_actor_rejected(self, client, auth_headers):
        resp = client.post(
            "/scan/start",
            json={"ip_address": "10.22.0.1", "ack_disclaimer": True},
            headers=auth_headers,
        )
        assert resp.status_code == 403

    def test_missing_disclaimer_rejected(self, client, analyst_headers, seed_analyst):
        resp = client.post(
            "/scan/start",
            json={"ip_address": "10.22.0.1", "ack_disclaimer": False},
            headers=analyst_headers,
        )
        assert resp.status_code == 400

    def test_unauthorised_target_rejected(self, client, analyst_headers, seed_analyst):
        resp = client.post(
            "/scan/start",
            json={"ip_address": "203.0.113.50", "ack_disclaimer": True},
            headers=analyst_headers,
        )
        assert resp.status_code == 403


class TestExploitRouteWiring:
    def test_admin_actor_rejected(self, client, auth_headers):
        resp = client.post(
            "/exploit/run",
            params={"target_ip": "10.22.1.1", "exploit_type": "ms17_010_check", "ack_disclaimer": True},
            headers=auth_headers,
        )
        assert resp.status_code == 403

    def test_missing_disclaimer_rejected(self, client, analyst_headers, seed_analyst):
        # ack_disclaimer arrives as the *string* "false" on the query string.
        resp = client.post(
            "/exploit/run",
            params={"target_ip": "203.0.113.51", "exploit_type": "ms17_010_check", "ack_disclaimer": False},
            headers=analyst_headers,
        )
        assert resp.status_code == 400

    def test_unauthorised_target_rejected(self, client, analyst_headers, seed_analyst):
        resp = client.post(
            "/exploit/run",
            params={"target_ip": "203.0.113.51", "exploit_type": "ms17_010_check", "ack_disclaimer": True},
            headers=analyst_headers,
        )
        assert resp.status_code == 403


class TestAiReportsDriftClosed:
    def test_ai_recommend_rejects_admin(self, client, auth_headers):
        resp = client.post("/ai/recommend-attacks", json={"scan_id": 1}, headers=auth_headers)
        assert resp.status_code == 403

    def test_ai_recommend_gates_unauthorised_scan(self, client, analyst_headers, seed_analyst):
        resp = client.post("/ai/recommend-attacks", json={"scan_id": 999999}, headers=analyst_headers)
        assert resp.status_code == 404

    def test_reports_rejects_admin(self, client, auth_headers):
        resp = client.post(
            "/reports/generate", json={"scan_id": 1, "format": "html"}, headers=auth_headers
        )
        assert resp.status_code == 403
