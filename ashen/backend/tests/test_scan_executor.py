"""
Tests for scan_executor module.
Covers: Issue #7 (async issues), Issue #8 (start_time overwrite).
"""
from unittest.mock import patch, MagicMock
from datetime import datetime


class TestScanExecutor:
    def test_perform_scan_preserves_start_time(self, db):
        """Issue #8: _update_scan_status should NOT overwrite start_time on retries."""
        from app.services.scan_executor import _update_scan_status
        from app.models.scan import Scan

        # Create a scan with a known start_time
        original_time = datetime(2025, 1, 1, 12, 0, 0)
        scan = Scan(
            target_system_id=1,
            user_id=1,
            session_id=1,
            status="queued",
            start_time=original_time
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Call _update_scan_status (simulating a retry)
        _update_scan_status(db, scan.scan_id, "running")

        db.refresh(scan)
        # After fix, start_time should be preserved — not overwritten
        # Before fix, start_time gets reset to utcnow()
        assert scan.start_time == original_time, \
            f"Issue #8: start_time was overwritten from {original_time} to {scan.start_time}"

    def test_run_scan_background_is_sync(self):
        """Issue #7: run_scan_background should be a sync function (not async)."""
        from app.services import scan_executor
        import asyncio
        # After fix, it should NOT be a coroutine function
        assert not asyncio.iscoroutinefunction(scan_executor.run_scan_background), \
            "Issue #7: run_scan_background is still async — should be sync for BackgroundTasks"

    def test_update_scan_status_does_not_override_cancelled(self, db):
        """Cancellation should be terminal: worker updates must not flip it back to running."""
        from app.services.scan_executor import _update_scan_status
        from app.models.scan import Scan

        scan = Scan(
            target_system_id=1,
            user_id=1,
            session_id=1,
            status="cancelled",
            progress=0,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        updated = _update_scan_status(db, scan.scan_id, "running", progress=20)
        db.refresh(scan)

        assert updated is False
        assert scan.status == "cancelled"
        assert scan.progress == 0

    def test_finalize_scan_respects_existing_cancelled(self, db):
        """Finalization should preserve cancelled if a race occurs during background execution."""
        from app.services.scan_executor import _finalize_scan
        from app.models.scan import Scan

        scan = Scan(
            target_system_id=1,
            user_id=1,
            session_id=1,
            status="cancelled",
            progress=0,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        _finalize_scan(
            db,
            scan.scan_id,
            "failed",
            None,
            "Scan was cancelled",
            "analyst@ashen.dev",
        )
        db.refresh(scan)

        assert scan.status == "cancelled"
