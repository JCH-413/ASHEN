"""
Tests for the remediation pipeline:
- safety_filter.filter_remediation_response
- remediation_service.get_remediation
- prompt_templates.build_remediation_prompt
- AI API endpoints (/ai/remediate, /ai/chat)
"""
import pytest
from unittest.mock import patch, MagicMock

from app.services.safety_filter import filter_remediation_response, filter_response
from app.services.prompt_templates import build_remediation_prompt


# ── filter_remediation_response tests ────────────────────────────────

class TestFilterRemediationResponse:
    def test_empty_response(self):
        assert filter_remediation_response("") == "No response"
        assert filter_remediation_response(None) == "No response"

    def test_blocks_unsafe_content(self):
        result = filter_remediation_response("Run rm -rf / to clean up")
        assert "Unsafe content" in result

    def test_preserves_structured_output(self):
        response = """## Root Cause
The FTP service is running with anonymous login enabled.

## Immediate Containment
- Disable anonymous FTP access immediately
- Block port 21 at the firewall

## Permanent Fix
- Update vsftpd configuration to disable anonymous access
- Set anonymous_enable=NO in /etc/vsftpd.conf

## Validation
- Run nmap scan to verify port 21 is filtered
- Attempt anonymous FTP login to confirm rejection

## Hardening
- Migrate to SFTP for encrypted file transfer
- Implement IP-based access control lists"""

        result = filter_remediation_response(response)
        assert "## Root Cause" in result
        assert "## Immediate Containment" in result
        assert "## Permanent Fix" in result
        assert "## Validation" in result
        assert "## Hardening" in result
        assert "Disable anonymous FTP" in result

    def test_removes_urls(self):
        response = "Update the package.\nSee http://example.com for details.\nRestart the service."
        result = filter_remediation_response(response)
        assert "http://" not in result
        assert "Update the package" in result
        assert "Restart the service" in result

    def test_preserves_multiline_content(self):
        response = """Line one about the vulnerability.
Line two with more detail.
Line three with a fix step.
Line four about validation."""
        result = filter_remediation_response(response)
        lines = [l for l in result.split("\n") if l.strip()]
        assert len(lines) >= 4

    def test_does_not_apply_attack_keyword_filter(self):
        """Remediation filter should NOT strip lines just because they lack attack keywords."""
        response = "Install the security patch.\nConfigure the firewall rules.\nRestart the application server."
        result = filter_remediation_response(response)
        assert "Install the security patch" in result
        assert "Configure the firewall rules" in result
        assert "Restart the application server" in result


# ── filter_response (attack filter) still works ──────────────────────

class TestFilterResponseAttack:
    def test_blocks_unsafe_content(self):
        result = filter_response("Use ddos to test the server")
        assert "Unsafe content" in result

    def test_attack_filter_passes_attack_keywords(self):
        result = filter_response("Try brute force on the login page")
        assert "brute" in result.lower() or "login" in result.lower()


# ── build_remediation_prompt tests ───────────────────────────────────

class TestBuildRemediationPrompt:
    def test_includes_context_data(self):
        prompt = build_remediation_prompt("Port 21 - FTP Anonymous Login (high)")
        assert "Port 21" in prompt
        assert "FTP Anonymous Login" in prompt

    def test_requests_structured_sections(self):
        prompt = build_remediation_prompt("test data")
        assert "Root Cause" in prompt
        assert "Immediate Containment" in prompt
        assert "Permanent Fix" in prompt
        assert "Validation" in prompt
        assert "Hardening" in prompt


# ── echo detection tests ─────────────────────────────────────────────

class TestEchoDetection:
    def test_detects_echo(self):
        from app.services.remediation_service import _is_echo
        context = "Vulnerability: FTP-VSFTPD on port 21\nSeverity: high\nDescription: backdoor found"
        response = "Vulnerability: FTP-VSFTPD on port 21\nSeverity: high\nDescription: backdoor found\nSome extra line"
        assert _is_echo(context, response) is True

    def test_no_echo_for_real_output(self):
        from app.services.remediation_service import _is_echo
        context = "Vulnerability: FTP-VSFTPD on port 21\nSeverity: high"
        response = "## Root Cause\nThe vsFTPd 2.3.4 has a backdoor.\n\n## Permanent Fix\n- Upgrade vsFTPd"
        assert _is_echo(context, response) is False

    def test_empty_inputs(self):
        from app.services.remediation_service import _is_echo
        assert _is_echo("", "something") is False
        assert _is_echo("something", "") is False

    @patch("app.services.remediation_service.client")
    def test_retries_on_echo(self, mock_client):
        context = "Vulnerability: FTP-VSFTPD on port 21\nSeverity: high\nDescription: backdoor found in vsFTPd"
        echoed = context  # model echoes input
        real_output = "## Root Cause\nBackdoor in vsFTPd 2.3.4.\n\n## Permanent Fix\n- Upgrade to latest version"

        mock_client.generate.side_effect = [echoed, real_output]

        from app.services.remediation_service import get_remediation
        result = get_remediation(context)

        assert mock_client.generate.call_count == 2
        assert "Root Cause" in result
        assert "Permanent Fix" in result


# ── get_remediation service tests ────────────────────────────────────

class TestGetRemediation:
    @patch("app.services.remediation_service.client")
    def test_returns_full_structured_output(self, mock_client):
        mock_client.generate.return_value = """## Root Cause
Anonymous FTP is enabled.

## Immediate Containment
- Disable anonymous access

## Permanent Fix
- Update vsftpd.conf

## Validation
- Test FTP connection

## Hardening
- Switch to SFTP"""

        from app.services.remediation_service import get_remediation
        result = get_remediation("FTP vuln on port 21")

        assert "Root Cause" in result
        assert "Immediate Containment" in result
        assert "Permanent Fix" in result
        assert len(result.split("\n")) > 5

    @patch("app.services.remediation_service.client")
    def test_handles_service_error_gracefully(self, mock_client):
        mock_client.generate.side_effect = RuntimeError("model error")

        from app.services.remediation_service import get_remediation
        result = get_remediation("test")
        assert "Error generating" in result

    @patch("app.services.remediation_service.client")
    def test_propagates_ai_unavailable(self, mock_client):
        from app.services.ollama_client import AIServiceUnavailableError
        mock_client.generate.side_effect = AIServiceUnavailableError("offline")

        from app.services.remediation_service import get_remediation
        with pytest.raises(AIServiceUnavailableError):
            get_remediation("test")


# ── API endpoint tests ───────────────────────────────────────────────

class TestRemediateEndpoint:
    @patch("app.api.ai.get_remediation")
    def test_remediate_requires_input(self, mock_remed, client, analyst_token):
        resp = client.post(
            "/ai/remediate",
            json={},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp.status_code == 400

    @patch("app.api.ai.get_remediation")
    def test_remediate_returns_guidance(self, mock_remed, client, analyst_token, db):
        # Seed a vulnerability
        from app.models.vulnerability import Vulnerability
        v = Vulnerability(
            scan_id=None, port="21", script_id="ftp-anon",
            severity="high", description="Anonymous FTP login allowed",
        )
        db.add(v)
        db.commit()
        db.refresh(v)

        mock_remed.return_value = "## Root Cause\nAnonymous FTP.\n\n## Permanent Fix\n- Disable anonymous login"

        resp = client.post(
            "/ai/remediate",
            json={"vuln_id": v.vuln_id},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "guidance" in data
        assert "Root Cause" in data["guidance"]

    def test_remediate_requires_auth(self, client):
        resp = client.post("/ai/remediate", json={"description": "test"})
        assert resp.status_code in (401, 403)


class TestChatEndpoint:
    @patch("app.api.ai.OllamaClient")
    def test_chat_accepts_remediation_context(self, MockClient, client, analyst_token):
        instance = MockClient.return_value
        instance.generate.return_value = "Here is my answer about the fix."

        resp = client.post(
            "/ai/chat",
            json={
                "question": "How do I verify the fix?",
                "remediation_context": "## Permanent Fix\n- Disable anonymous FTP",
            },
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp.status_code == 200
        # Verify the remediation context was included in the prompt
        call_args = instance.generate.call_args[0][0]
        assert "Prior remediation guidance" in call_args
        assert "Disable anonymous FTP" in call_args

    @patch("app.api.ai.OllamaClient")
    def test_chat_works_without_remediation_context(self, MockClient, client, analyst_token):
        instance = MockClient.return_value
        instance.generate.return_value = "General answer."

        resp = client.post(
            "/ai/chat",
            json={"question": "What is FTP?"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["answer"] == "General answer."
