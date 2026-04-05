"""
ai.py
API routes for AI attack recommendations, remediation guidance, and chat.
All routes require JWT authentication.
"""
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from datetime import datetime
from app.core.db import get_db
from app.core.security import get_current_user
from app.models.vulnerability import Vulnerability
from app.models.scan import Scan
from app.models.exploit import Exploit
from app.utils.logging_utils import create_audit_log
from app.services.attack_recommender import recommend_attacks, stream_attack_recommendation
from app.services.remediation_service import get_remediation, stream_remediation
from app.services.feedback_service import handle_feedback
from app.services.governance_logger import log_event
from app.services.ollama_client import AIServiceUnavailableError, OllamaClient
from app.schemas.ai_schema import (
    AttackRecommendRequest,
    RemediationRequest,
    ReviewRequest,
    AIChatRequest,
)

router = APIRouter(prefix="/ai", tags=["AI Engine"])


def _build_vuln_context(db: Session, scan_id: int, vuln_id: int = None) -> str:
    """Build a text context from scan/vuln data for the AI prompt."""
    parts = []

    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if scan and scan.target:
        parts.append(f"Target: {scan.target.ip_address}")

    if vuln_id:
        vulns = [db.query(Vulnerability).filter(Vulnerability.vuln_id == vuln_id).first()]
    else:
        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()

    for v in vulns:
        if v:
            parts.append(f"Port {v.port} - {v.script_id} ({v.severity}): {v.description}")

    return "\n".join(parts) if parts else "No vulnerability data available"


def _build_rich_remediation_context(db: Session, vuln_id=None, exploit_id=None, description=None) -> str:
    """Build concise context for remediation — enough for the LLM to reason,
    short enough that tinyllama doesn't echo it back."""
    parts = []

    vuln = None
    if vuln_id:
        vuln = db.query(Vulnerability).filter(Vulnerability.vuln_id == vuln_id).first()
        if vuln:
            parts.append(f"Vulnerability: {vuln.script_id} on port {vuln.port}")
            parts.append(f"Severity: {vuln.severity}")
            if vuln.description:
                parts.append(f"Description: {vuln.description}")

            # Extract key facts from raw scan output (CVE, state) — skip verbose dump
            if vuln.raw_output:
                raw = str(vuln.raw_output)
                summary_lines = []
                for line in raw.split("\n"):
                    low = line.strip().lower()
                    if any(kw in low for kw in ["cve", "state:", "vulnerable", "version", "discovery"]):
                        summary_lines.append(line.strip())
                if summary_lines:
                    parts.append("Key findings: " + "; ".join(summary_lines[:5]))

            if vuln.scan_id:
                scan = db.query(Scan).filter(Scan.scan_id == vuln.scan_id).first()
                if scan and scan.target:
                    parts.append(f"Target: {scan.target.ip_address}")

    if exploit_id:
        exploit = db.query(Exploit).filter(Exploit.exploit_id == exploit_id).first()
        if exploit:
            parts.append(f"Exploit: {exploit.exploit_type} via {exploit.tool_used}")
            parts.append(f"Result: {exploit.status}" + (f" — {exploit.result_summary[:200]}" if exploit.result_summary else ""))

    if description:
        parts.append(f"Context: {description}")

    return "\n".join(parts) if parts else ""


# ── Attack Recommendations ───────────────────────────────────────────

def _build_rich_attack_context(db: Session, scan_id: int, vuln_id: int = None) -> str:
    """Build context for attack recommendations: open ports, vulns, prior
    exploits, and the list of exploit types available in ASHEN."""
    parts = []

    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        return ""

    # Target info
    if scan.target:
        parts.append(f"Target: {scan.target.ip_address}")

    # Vulnerabilities (open ports + findings)
    if vuln_id:
        vulns = [db.query(Vulnerability).filter(Vulnerability.vuln_id == vuln_id).first()]
    else:
        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()

    if vulns:
        parts.append("Open ports and vulnerabilities:")
        for v in vulns:
            if not v:
                continue
            line = f"- Port {v.port} | {v.script_id} | Severity: {v.severity}"
            if v.description:
                line += f" | {v.description[:100]}"
            parts.append(line)

    # Prior exploit attempts
    exploits = db.query(Exploit).filter(Exploit.scan_id == scan_id).all()
    if exploits:
        parts.append("Already tested:")
        for ex in exploits:
            parts.append(f"- {ex.exploit_type} → {ex.status}")

    # Available exploit types in ASHEN
    parts.append("Available exploits in this system:")
    parts.append("- ftp_brute_force (targets FTP on port 21, tool: hydra)")
    parts.append("- ssh_brute_force (targets SSH on port 22, tool: metasploit)")
    parts.append("- ms17_010_check (targets SMB on port 445, tool: metasploit)")
    parts.append("- shellshock_cgi (targets HTTP/CGI on port 80/443, tool: curl)")

    return "\n".join(parts)


@router.post("/recommend-attacks")
def ai_recommend_attacks(
    body: AttackRecommendRequest,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.scan_id == body.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    context = _build_rich_attack_context(db, body.scan_id, body.vuln_id)
    try:
        response = recommend_attacks(context)
    except AIServiceUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))

    email = current_payload.get("sub", "unknown")
    log_event(context, response, action="attack_recommendation")
    create_audit_log(db, f"AI attack recommendation generated for scan {body.scan_id}", email)

    return {
        "scan_id": body.scan_id,
        "vuln_id": body.vuln_id,
        "recommendation": response,
        "model": "tinyllama",
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.post("/recommend-attacks/stream")
def ai_recommend_attacks_stream(
    body: AttackRecommendRequest,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.scan_id == body.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    context = _build_rich_attack_context(db, body.scan_id, body.vuln_id)
    email = current_payload.get("sub", "unknown")

    def generate_sse():
        full_response = ""
        try:
            for token in stream_attack_recommendation(context):
                full_response += token
                yield _sse_event(token)
        except AIServiceUnavailableError as e:
            yield _sse_event(str(e), event="error")
            return
        except Exception:
            yield _sse_event("Error generating attack recommendations.", event="error")
            return

        log_event(context, full_response, action="attack_recommendation")
        create_audit_log(db, f"AI attack recommendation generated for scan {body.scan_id}", email)
        yield _sse_event("", event="done")

    return StreamingResponse(generate_sse(), media_type="text/event-stream")


# ── Remediation Guidance ─────────────────────────────────────────────

@router.post("/remediate")
def ai_remediate(
    body: RemediationRequest,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    context = _build_rich_remediation_context(
        db,
        vuln_id=body.vuln_id,
        exploit_id=body.exploit_id,
        description=body.description,
    )

    if not context:
        raise HTTPException(status_code=400, detail="Provide at least one of: vuln_id, exploit_id, or description")

    try:
        response = get_remediation(context)
    except AIServiceUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))

    email = current_payload.get("sub", "unknown")
    log_event(context, response, action="remediation_guidance")
    create_audit_log(db, f"AI remediation generated (vuln_id={body.vuln_id}, exploit_id={body.exploit_id})", email)

    return {
        "vuln_id": body.vuln_id,
        "exploit_id": body.exploit_id,
        "guidance": response,
        "model": "tinyllama",
        "generated_at": datetime.utcnow().isoformat(),
    }


# ── Streaming Remediation (SSE) ──────────────────────────────────────

def _sse_event(data: str, event: str = "token") -> str:
    """Format a single Server-Sent Event."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@router.post("/remediate/stream")
def ai_remediate_stream(
    body: RemediationRequest,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    context = _build_rich_remediation_context(
        db,
        vuln_id=body.vuln_id,
        exploit_id=body.exploit_id,
        description=body.description,
    )

    if not context:
        raise HTTPException(status_code=400, detail="Provide at least one of: vuln_id, exploit_id, or description")

    email = current_payload.get("sub", "unknown")

    def generate_sse():
        full_response = ""
        try:
            for token in stream_remediation(context):
                full_response += token
                yield _sse_event(token)
        except AIServiceUnavailableError as e:
            yield _sse_event(str(e), event="error")
            return
        except Exception:
            yield _sse_event("Error generating remediation guidance.", event="error")
            return

        # Log after completion
        log_event(context, full_response, action="remediation_guidance")
        create_audit_log(db, f"AI remediation generated (vuln_id={body.vuln_id}, exploit_id={body.exploit_id})", email)
        yield _sse_event("", event="done")

    return StreamingResponse(generate_sse(), media_type="text/event-stream")


@router.post("/chat/stream")
def ai_chat_stream(
    body: AIChatRequest,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    context_parts = []

    if body.vuln_id:
        vuln = db.query(Vulnerability).filter(Vulnerability.vuln_id == body.vuln_id).first()
        if vuln:
            context_parts.append(f"Context - Vulnerability: {vuln.script_id} on port {vuln.port} ({vuln.severity}): {vuln.description}")

    if body.exploit_id:
        exploit = db.query(Exploit).filter(Exploit.exploit_id == body.exploit_id).first()
        if exploit:
            context_parts.append(f"Context - Exploit: {exploit.exploit_type} via {exploit.tool_used} on {exploit.target_ip} — {exploit.result_summary}")

    if body.remediation_context:
        context_parts.append(f"Prior remediation guidance:\n{body.remediation_context}")

    context_parts.append(f"User question: {body.question}")

    prompt = "\n\n".join(context_parts)
    ollama = OllamaClient()

    def generate_sse():
        try:
            for token in ollama.generate_stream(prompt):
                yield _sse_event(token)
        except AIServiceUnavailableError as e:
            yield _sse_event(str(e), event="error")
            return
        except Exception:
            yield _sse_event("Error processing chat request.", event="error")
            return

        yield _sse_event("", event="done")

    return StreamingResponse(generate_sse(), media_type="text/event-stream")


# ── Review (Accept / Reject / Regenerate) ────────────────────────────

@router.post("/review")
def ai_review(
    body: ReviewRequest,
    scan_id: int = None,
    vuln_id: int = None,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    email = current_payload.get("sub", "unknown")
    valid_actions = ("accept", "reject", "regenerate")
    if body.action not in valid_actions:
        raise HTTPException(status_code=400, detail=f"Action must be one of: {valid_actions}")

    result = handle_feedback("", "", body.action)

    # If regenerate, re-run recommendation
    new_response = None
    if body.action == "regenerate" and scan_id:
        context = _build_vuln_context(db, scan_id, vuln_id)
        new_response = recommend_attacks(context)
        log_event(context, new_response, action="regenerated")

    create_audit_log(db, f"AI output {body.action}ed by {email}", email)

    response = {"action": body.action, "result": result}
    if new_response:
        response["new_recommendation"] = new_response
    return response


# ── Chat (follow-up Q&A) ─────────────────────────────────────────────

@router.post("/chat")
def ai_chat(
    body: AIChatRequest,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    context_parts = []

    # Add vulnerability context
    if body.vuln_id:
        vuln = db.query(Vulnerability).filter(Vulnerability.vuln_id == body.vuln_id).first()
        if vuln:
            context_parts.append(f"Context - Vulnerability: {vuln.script_id} on port {vuln.port} ({vuln.severity}): {vuln.description}")
            if vuln.raw_output:
                context_parts.append(f"Scan output: {vuln.raw_output}")

    # Add exploit context
    if body.exploit_id:
        exploit = db.query(Exploit).filter(Exploit.exploit_id == body.exploit_id).first()
        if exploit:
            context_parts.append(f"Context - Exploit: {exploit.exploit_type} via {exploit.tool_used} on {exploit.target_ip} — {exploit.result_summary}")

    # Add prior remediation context if provided
    if body.remediation_context:
        context_parts.append(f"Prior remediation guidance:\n{body.remediation_context}")

    # Add the user question
    context_parts.append(f"User question: {body.question}")

    client = OllamaClient()
    try:
        response = client.generate("\n\n".join(context_parts))
    except AIServiceUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))

    return {
        "question": body.question,
        "answer": response,
        "model": "tinyllama",
    }
