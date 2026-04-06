"""
Phase 3 Tests: pagination, filters, progress model, exploit types endpoint.
"""
from datetime import datetime


def _seed_target(db, admin_id, ip="10.0.0.1"):
    from app.models.target_system import TargetSystem
    t = db.query(TargetSystem).filter(TargetSystem.ip_address == ip).first()
    if not t:
        t = TargetSystem(ip_address=ip, added_by=admin_id, authorized=True)
        db.add(t)
        db.commit()
        db.refresh(t)
    return t


def _seed_scan(db, user_id, target_id, session_id=1, status="completed", progress=100):
    from app.models.scan import Scan
    s = Scan(
        target_system_id=target_id,
        user_id=user_id,
        session_id=session_id,
        status=status,
        progress=progress,
        start_time=datetime.utcnow(),
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _seed_vuln(db, scan_id, port=22, severity="high"):
    from app.models.vulnerability import Vulnerability
    v = Vulnerability(
        scan_id=scan_id,
        port=port,
        script_id=f"test-{port}",
        severity=severity,
        description=f"test vuln on port {port}",
        raw_output=f"VULNERABLE output for port {port}",
    )
    db.add(v)
    db.commit()
    db.refresh(v)
    return v


# ── Pagination Tests ─────────────────────────────────────────────────

class TestScanHistoryPagination:
    def test_returns_paginated_format(self, client, analyst_headers):
        resp = client.get("/scan/history", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert "skip" in data
        assert "limit" in data

    def test_pagination_skip_limit(self, client, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.30")
        for _ in range(5):
            _seed_scan(db, seed_analyst.user_id, target.target_id)

        resp = client.get("/scan/history?skip=0&limit=2", headers=analyst_headers)
        data = resp.json()
        assert len(data["items"]) <= 2
        assert data["total"] >= 5

    def test_pagination_skip_beyond(self, client, analyst_headers):
        resp = client.get("/scan/history?skip=10000&limit=10", headers=analyst_headers)
        data = resp.json()
        assert len(data["items"]) == 0


class TestVulnsPagination:
    def test_returns_paginated_format(self, client, analyst_headers):
        resp = client.get("/vulns/all", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data

    def test_pagination_limit(self, client, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.31")
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id)
        for port in range(100, 106):
            _seed_vuln(db, scan.scan_id, port=port)

        resp = client.get("/vulns/all?limit=3", headers=analyst_headers)
        data = resp.json()
        assert len(data["items"]) <= 3
        assert data["total"] >= 6


# ── Vulnerability Filter Tests ───────────────────────────────────────

class TestVulnFilters:
    def test_filter_by_severity(self, client, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.32")
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id)
        _seed_vuln(db, scan.scan_id, port=80, severity="critical")
        _seed_vuln(db, scan.scan_id, port=443, severity="low")

        resp = client.get("/vulns/all?severity=critical", headers=analyst_headers)
        data = resp.json()
        for item in data["items"]:
            assert item["severity"] == "critical"

    def test_filter_by_port(self, client, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.33")
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id)
        _seed_vuln(db, scan.scan_id, port=3306)
        _seed_vuln(db, scan.scan_id, port=5432)

        resp = client.get("/vulns/all?port=3306", headers=analyst_headers)
        data = resp.json()
        for item in data["items"]:
            assert item["port"] == 3306

    def test_filter_by_scan_id(self, client, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.34")
        scan1 = _seed_scan(db, seed_analyst.user_id, target.target_id)
        scan2 = _seed_scan(db, seed_analyst.user_id, target.target_id)
        _seed_vuln(db, scan1.scan_id, port=22)
        _seed_vuln(db, scan2.scan_id, port=80)

        resp = client.get(f"/vulns/all?scan_id={scan1.scan_id}", headers=analyst_headers)
        data = resp.json()
        for item in data["items"]:
            assert item["scan_id"] == scan1.scan_id

    def test_raw_output_included(self, client, analyst_headers, db, seed_admin, seed_analyst):
        """raw_output should be returned for vuln description expand."""
        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.35")
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id)
        _seed_vuln(db, scan.scan_id, port=9999)

        resp = client.get("/vulns/all", headers=analyst_headers)
        items = resp.json()["items"]
        port_9999 = [v for v in items if v["port"] == 9999]
        if port_9999:
            assert "raw_output" in port_9999[0]


# ── Progress Model Tests ─────────────────────────────────────────────

class TestScanProgress:
    def test_progress_in_status_response(self, client, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.36")
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id, status="running", progress=45)

        resp = client.get(f"/scan/status/{scan.scan_id}", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "progress" in data
        assert data["progress"] == 45

    def test_completed_scan_shows_100(self, client, analyst_headers, db, seed_admin, seed_analyst):
        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.37")
        scan = _seed_scan(db, seed_analyst.user_id, target.target_id, status="completed", progress=100)

        resp = client.get(f"/scan/status/{scan.scan_id}", headers=analyst_headers)
        data = resp.json()
        assert data["progress"] == 100

    def test_error_detail_in_status(self, client, analyst_headers, db, seed_admin, seed_analyst):
        """Failed scans should include error_detail."""
        target = _seed_target(db, seed_admin.admin_id, ip="10.0.0.38")
        from app.models.scan import Scan
        scan = Scan(
            target_system_id=target.target_id,
            user_id=seed_analyst.user_id,
            session_id=1,
            status="failed",
            progress=0,
            error_detail="nmap timed out after 600s",
            start_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        resp = client.get(f"/scan/status/{scan.scan_id}", headers=analyst_headers)
        data = resp.json()
        assert "error_detail" in data
        assert data["error_detail"] == "nmap timed out after 600s"


# ── Exploit Types Endpoint ───────────────────────────────────────────

class TestExploitTypesEndpoint:
    def test_returns_all_types(self, client, analyst_headers):
        resp = client.get("/exploit/types", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "exploit_types" in data
        types = data["exploit_types"]
        assert len(types) >= 4
        keys = [t["key"] for t in types]
        assert "ssh_brute_force" in keys
        assert "ftp_brute_force" in keys
        assert "ms17_010_check" in keys
        assert "shellshock_cgi" in keys

    def test_includes_tool_info(self, client, analyst_headers):
        resp = client.get("/exploit/types", headers=analyst_headers)
        types = resp.json()["exploit_types"]
        for t in types:
            assert "key" in t
            assert "tool" in t
            assert t["tool"] in ("metasploit", "hydra", "curl")

    def test_requires_auth(self, client):
        resp = client.get("/exploit/types")
        assert resp.status_code in (401, 403)
