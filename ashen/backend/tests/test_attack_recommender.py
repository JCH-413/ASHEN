"""
Tests for the attack recommendation pipeline:
- safety_filter.filter_attack_response
- attack_recommender.recommend_attacks / stream_attack_recommendation
- prompt_templates.build_attack_prompt
- context builder correctness
"""
import pytest
from unittest.mock import patch

from app.services.safety_filter import filter_attack_response, filter_response
from app.services.prompt_templates import build_attack_prompt


# ── filter_attack_response tests ────────────────────────────────────

class TestFilterAttackResponse:
    def test_empty_response(self):
        assert filter_attack_response("") == "No response"
        assert filter_attack_response(None) == "No response"

    def test_blocks_unsafe_content(self):
        result = filter_attack_response("Use ddos to take down the server")
        assert "Unsafe content" in result

    def test_preserves_structured_output(self):
        response = """Exploitation Order:

1. Port 21 — ftp_brute_force — high severity anonymous FTP, likely vulnerable
2. Port 22 — ssh_brute_force — medium severity, try default credentials
3. Port 445 — ms17_010_check — check for EternalBlue"""

        result = filter_attack_response(response)
        assert "Exploitation Order" in result
        assert "ftp_brute_force" in result
        assert "1." in result
        assert "2." in result

    def test_removes_urls(self):
        response = "Try the exploit.\nDetails at http://exploit-db.com/123.\nContinue testing."
        result = filter_attack_response(response)
        assert "http://" not in result
        assert "Try the exploit" in result
        assert "Continue testing" in result

    def test_preserves_multiline_content(self):
        response = """1. Port 21 — ftp_brute_force — anonymous FTP detected
2. Port 22 — ssh_brute_force — weak SSH config
3. Port 445 — ms17_010_check — SMB open
4. Port 80 — shellshock_cgi — CGI scripts found"""
        result = filter_attack_response(response)
        lines = [l for l in result.split("\n") if l.strip()]
        assert len(lines) >= 4

    def test_does_not_use_strict_keyword_filter(self):
        """Attack filter should NOT require specific keywords like the old filter_response did."""
        response = "1. Port 21 — ftp_brute_force\n2. Port 22 — ssh_brute_force"
        result = filter_attack_response(response)
        assert "ftp_brute_force" in result
        assert "ssh_brute_force" in result


# ── Legacy filter_response still works ───────────────────────────────

class TestLegacyFilterResponse:
    def test_still_exists_and_blocks_unsafe(self):
        result = filter_response("Use ddos attack")
        assert "Unsafe content" in result


# ── build_attack_prompt tests ────────────────────────────────────────

class TestBuildAttackPrompt:
    def test_includes_context_data(self):
        prompt = build_attack_prompt("Target: 192.168.1.1\nPort 21 - ftp-anon (high)")
        assert "192.168.1.1" in prompt
        assert "ftp-anon" in prompt

    def test_prompt_mentions_exploit_matching(self):
        prompt = build_attack_prompt("test data")
        assert "exploit" in prompt.lower()
        assert "priority" in prompt.lower()

    def test_prompt_is_compact(self):
        prompt = build_attack_prompt("test data")
        assert len(prompt) < 600

    def test_ends_with_primer(self):
        prompt = build_attack_prompt("test data")
        assert prompt.rstrip().endswith("1.")


# ── recommend_attacks service tests ──────────────────────────────────

class TestRecommendAttacks:
    @patch("app.services.attack_recommender.client")
    def test_returns_structured_output(self, mock_client):
        mock_client.generate.return_value = """ Port 21 — ftp_brute_force — anonymous FTP detected, high severity
2. Port 22 — ssh_brute_force — weak SSH config, try default credentials
3. Port 445 — ms17_010_check — SMB open, check for EternalBlue"""

        from app.services.attack_recommender import recommend_attacks
        result = recommend_attacks("Port 21 - ftp-anon")

        assert "Exploitation Order" in result
        assert "ftp_brute_force" in result
        assert "1." in result

    @patch("app.services.attack_recommender.client")
    def test_handles_empty_input(self, mock_client):
        from app.services.attack_recommender import recommend_attacks
        result = recommend_attacks("")
        assert result == "No input provided"

    @patch("app.services.attack_recommender.client")
    def test_handles_service_error(self, mock_client):
        mock_client.generate.side_effect = RuntimeError("model error")

        from app.services.attack_recommender import recommend_attacks
        result = recommend_attacks("test")
        assert "Error generating" in result

    @patch("app.services.attack_recommender.client")
    def test_propagates_ai_unavailable(self, mock_client):
        from app.services.ollama_client import AIServiceUnavailableError
        mock_client.generate.side_effect = AIServiceUnavailableError("offline")

        from app.services.attack_recommender import recommend_attacks
        with pytest.raises(AIServiceUnavailableError):
            recommend_attacks("test")

    @patch("app.services.attack_recommender.client")
    def test_stream_yields_tokens_with_header(self, mock_client):
        mock_client.generate_stream.return_value = iter([" Port 21 ", "— ftp_brute_force", " — high"])

        from app.services.attack_recommender import stream_attack_recommendation
        tokens = list(stream_attack_recommendation("test"))
        # First token should be the prepended header
        assert tokens[0] == "Exploitation Order:\n\n1."
        assert "ftp_brute_force" in "".join(tokens)


# ── Context builder tests ────────────────────────────────────────────

class TestBuildRichAttackContext:
    """Test _build_rich_attack_context via direct import."""

    def test_empty_scan_returns_empty(self):
        """The function should return empty string if scan not found."""
        from unittest.mock import MagicMock
        from app.api.ai import _build_rich_attack_context

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        db.query.return_value.filter.return_value.all.return_value = []

        result = _build_rich_attack_context(db, scan_id=999)
        assert result == ""

    def test_builds_context_with_vulns_and_exploits(self):
        from unittest.mock import MagicMock
        from app.api.ai import _build_rich_attack_context

        db = MagicMock()

        # Mock scan
        mock_scan = MagicMock()
        mock_scan.target.ip_address = "192.168.1.100"
        mock_scan.start_time.isoformat.return_value = "2026-04-05T00:00:00"

        # Mock vulnerability
        mock_vuln = MagicMock()
        mock_vuln.port = "21"
        mock_vuln.script_id = "ftp-anon"
        mock_vuln.severity = "high"
        mock_vuln.description = "Anonymous FTP allowed"
        mock_vuln.raw_output = "State: VULNERABLE\nCVE-2011-2523"

        # Mock exploit
        mock_exploit = MagicMock()
        mock_exploit.exploit_type = "ftp_brute_force"
        mock_exploit.tool_used = "hydra"
        mock_exploit.status = "success"
        mock_exploit.vulnerable = True
        mock_exploit.result_summary = "Credentials found"

        def query_side_effect(model):
            mock_query = MagicMock()
            model_name = model.__name__ if hasattr(model, '__name__') else str(model)
            if model_name == "Scan":
                mock_query.filter.return_value.first.return_value = mock_scan
            elif model_name == "Vulnerability":
                mock_query.filter.return_value.all.return_value = [mock_vuln]
            elif model_name == "Exploit":
                mock_query.filter.return_value.all.return_value = [mock_exploit]
            return mock_query

        db.query.side_effect = query_side_effect

        result = _build_rich_attack_context(db, scan_id=1)

        assert "192.168.1.100" in result
        assert "ftp-anon" in result
        assert "high" in result
        assert "ftp_brute_force" in result
        # Context should list available exploit types
        assert "ssh_brute_force" in result
        assert "ms17_010_check" in result
        assert "shellshock_cgi" in result
