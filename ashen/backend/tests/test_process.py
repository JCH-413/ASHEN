"""
Tests for the deep process module — the one place external-process lifecycle lives.
"""
from unittest.mock import MagicMock

from app.services import process


def test_run_captures_output_and_returncode():
    out = process.run(["printf", "hello"], timeout=10)
    assert out.stdout == "hello"
    assert out.returncode == 0
    assert out.timed_out is False
    assert out.cancelled is False


def test_run_timeout_sets_timed_out():
    out = process.run(["sleep", "5"], timeout=1)
    assert out.timed_out is True


def test_cancel_terminates_registered_process():
    proc = MagicMock()
    proc.wait.return_value = 0
    process.register("scan:4242", proc)
    assert process.cancel("scan:4242") is True
    proc.terminate.assert_called_once()


def test_cancel_unknown_token_returns_false():
    assert process.cancel("exploit:does-not-exist") is False


def test_unregister_then_cancel_is_false():
    process.register("scan:7", MagicMock())
    process.unregister("scan:7")
    assert process.cancel("scan:7") is False


def test_token_namespacing_avoids_id_collision():
    scan_proc, exploit_proc = MagicMock(), MagicMock()
    process.register("scan:5", scan_proc)
    process.register("exploit:5", exploit_proc)
    assert process.cancel("scan:5") is True
    scan_proc.terminate.assert_called_once()
    exploit_proc.terminate.assert_not_called()   # same id, different namespace
    process.cancel("exploit:5")
