# scans.py
# JWT auth on all routes.
# Scan runs as a true background task — does not block the route.
# XML output file uses scan_id to prevent concurrent scan collisions.

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from datetime import datetime
from app.core.db import get_db
from app.models.scan import Scan
from app.models.target_system import TargetSystem
from app.models.user import User
from app.models.user_session import UserSession
from app.services.scan_executor import run_scan_background
from app.utils.logging_utils import create_audit_log
from app.core.security import get_current_user
from app.schemas.scan_schema import ScanStartRequest

router = APIRouter(prefix="/scan", tags=["Scanning"])


@router.post("/start")
def start_scan(
    body: ScanStartRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user)
):
    role = current_payload.get("role")
    if role != "Analyst":
        raise HTTPException(status_code=403, detail="Only users can start scans")

    if not body.ack_disclaimer:
        raise HTTPException(status_code=400, detail="Must acknowledge ethical disclaimer before scanning")

    email = current_payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    target = db.query(TargetSystem).filter(
        TargetSystem.ip_address == body.ip_address,
        TargetSystem.authorized == True
    ).first()
    if not target:
        raise HTTPException(status_code=403, detail="IP not authorized for scanning")

    session = db.query(UserSession).filter(
        UserSession.user_id == user.user_id
    ).order_by(UserSession.login_time.desc()).first()
    if not session:
        raise HTTPException(status_code=400, detail="No active session found")

    new_scan = Scan(
        target_system_id=target.target_id,
        user_id=user.user_id,
        session_id=session.session_id,
        status="queued",
        start_time=datetime.utcnow()
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    create_audit_log(
        db,
        f"User {user.email} queued scan on {body.ip_address}",
        user.email
    )

    # Fire and forget — does not block the response
    background_tasks.add_task(
        run_scan_background,
        new_scan.scan_id,
        body.ip_address,
        user.email
    )

    return {
        "scan_id": new_scan.scan_id,
        "status": "queued",
        "message": f"Scan queued for {body.ip_address}"
    }


@router.get("/status/{scan_id}")
def get_scan_status(
    scan_id: int,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user)
):
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "start_time": scan.start_time,
        "end_time": scan.end_time,
        "results_json": scan.results_json
    }


@router.get("/history")
def get_scan_history(
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user)
):
    email = current_payload.get("sub")
    role = current_payload.get("role")

    query = db.query(Scan)
    # Analysts only see their own scans; Admins see all
    if role != "Admin":
        user = db.query(User).filter(User.email == email).first()
        if user:
            query = query.filter(Scan.user_id == user.user_id)

    scans = query.order_by(Scan.start_time.desc()).all()
    return [
        {
            "scan_id": s.scan_id,
            "ip": s.target.ip_address if s.target else None,
            "user": s.user.email if s.user else None,
            "status": s.status,
            "start_time": s.start_time,
            "end_time": s.end_time
        }
        for s in scans
    ]