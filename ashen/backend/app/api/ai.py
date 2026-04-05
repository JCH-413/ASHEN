"""
ai.py
API routes for AI attack recommendations, remediation guidance, and chat.
All routes require JWT authentication.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from app.core.db import get_db
from app.core.security import get_current_user
from app.models.vulnerability import Vulnerability
from app.models.scan import Scan
from app.models.exploit import Exploit
from app.utils.logging_utils import create_audit_log
from app.services.attack_recommender import recommend_attacks
from app.services.remediation_service import get_remediation
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


# ── Attack Recommendations ───────────────────────────────────────────

@router.post("/recommend-attacks")
def ai_recommend_attacks(
    body: AttackRecommendRequest,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.scan_id == body.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    context = _build_vuln_context(db, body.scan_id, body.vuln_id)
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


# ── Remediation Guidance ─────────────────────────────────────────────

@router.post("/remediate")
def ai_remediate(
    body: RemediationRequest,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    # Build context from whichever ID was provided
    context_parts = []

    if body.exploit_id:
        exploit = db.query(Exploit).filter(Exploit.exploit_id == body.exploit_id).first()
        if exploit:
            context_parts.append(f"Exploit: {exploit.exploit_type} on {exploit.target_ip} - {exploit.result_summary}")

    if body.vuln_id:
        vuln = db.query(Vulnerability).filter(Vulnerability.vuln_id == body.vuln_id).first()
        if vuln:
            context_parts.append(f"Vulnerability: Port {vuln.port} - {vuln.script_id} ({vuln.severity}): {vuln.description}")

    if body.description:
        context_parts.append(body.description)

    if not context_parts:
        raise HTTPException(status_code=400, detail="Provide at least one of: vuln_id, exploit_id, or description")

    context = "\n".join(context_parts)
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
    context_parts = [f"User question: {body.question}"]

    if body.vuln_id:
        vuln = db.query(Vulnerability).filter(Vulnerability.vuln_id == body.vuln_id).first()
        if vuln:
            context_parts.insert(0, f"Context - Vulnerability: Port {vuln.port} - {vuln.script_id}: {vuln.description}")

    if body.exploit_id:
        exploit = db.query(Exploit).filter(Exploit.exploit_id == body.exploit_id).first()
        if exploit:
            context_parts.insert(0, f"Context - Exploit: {exploit.exploit_type} on {exploit.target_ip}: {exploit.result_summary}")

    client = OllamaClient()
    try:
        response = client.generate("\n".join(context_parts))
    except AIServiceUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))

    return {
        "question": body.question,
        "answer": response,
        "model": "tinyllama",
    }
