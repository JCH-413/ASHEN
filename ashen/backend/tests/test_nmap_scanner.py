"""
Tests for NmapScanner class.
Covers: Issue #5 (quick_scan not inside class).
"""


class TestNmapScannerClass:
    def test_quick_scan_is_class_method(self):
        """Issue #5: quick_scan must be a method of NmapScanner, not a standalone function."""
        from app.services.scanner.nmap_scanner import NmapScanner
        assert hasattr(NmapScanner, 'quick_scan'), \
            "Issue #5: quick_scan is NOT a method of NmapScanner class (indentation bug)"

    def test_nmap_scanner_instantiation(self):
        """NmapScanner should instantiate without error if nmap is in PATH, or raise EnvironmentError."""
        from app.services.scanner.nmap_scanner import NmapScanner
        import shutil
        if shutil.which("nmap"):
            scanner = NmapScanner()
            assert scanner is not None
            # Verify we can call quick_scan on the instance
            assert callable(getattr(scanner, 'quick_scan', None)), \
                "Issue #5: NmapScanner instance has no callable quick_scan method"
        else:
            import pytest
            with pytest.raises(EnvironmentError):
                NmapScanner()
