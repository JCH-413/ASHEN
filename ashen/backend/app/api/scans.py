# scans.py
# JWT auth on all routes.
# Scan runs as a true background task — does not block the route.
# XML output file uses scan_id to prevent concurrent scan collisions.

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from datetime import datetime
from app.core.db import get_db
from app.models.scan import Scan
from app.models.target_system import TargetSystem
from app.models.user import User
from app.models.user_session import UserSession
from app.services.scan_executor import run_scan_background
from app.services.scanner.nmap_scanner import kill_scan_process
from app.utils.logging_utils import create_audit_log
from app.core.security import get_current_user
from app.core.rate_limit import check_scan_rate
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

    # P1.3: Rate limiting per user
    check_scan_rate(email)

    # P1.4: Prevent duplicate active scans for same target
    active_scan = db.query(Scan).filter(
        Scan.target_system_id == target.target_id,
        Scan.status.in_(["queued", "running"])
    ).first()
    if active_scan:
        raise HTTPException(
            status_code=409,
            detail=f"An active scan (ID {active_scan.scan_id}) is already running for this target"
        )

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

    # Ownership check: analysts can only view their own scans
    role = current_payload.get("role")
    if role != "Admin":
        email = current_payload.get("sub")
        user = db.query(User).filter(User.email == email).first()
        if not user or scan.user_id != user.user_id:
            raise HTTPException(status_code=403, detail="Not authorized to view this scan")

    # Lightweight response when scan is still in progress
    if scan.status in ("queued", "running"):
        return {
            "scan_id": scan.scan_id,
            "status": scan.status,
            "progress": scan.progress or 0,
            "start_time": scan.start_time,
            "end_time": None,
            "results_json": None,
            "error_detail": None
        }

    return {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "progress": scan.progress or (100 if scan.status in ("completed", "completed_with_errors") else 0),
        "start_time": scan.start_time,
        "end_time": scan.end_time,
        "results_json": scan.results_json,
        "error_detail": scan.error_detail
    }


@router.post("/cancel/{scan_id}")
def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user)
):
    """Cancel a queued or running scan. Only the owner or an admin can cancel."""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Ownership check
    role = current_payload.get("role")
    email = current_payload.get("sub")
    if role != "Admin":
        user = db.query(User).filter(User.email == email).first()
        if not user or scan.user_id != user.user_id:
            raise HTTPException(status_code=403, detail="Not authorized to cancel this scan")

    # Valid state transitions: only queued/running can be cancelled
    if scan.status not in ("queued", "running"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot cancel scan in '{scan.status}' state. Only queued/running scans can be cancelled."
        )

    scan.status = "cancelled"
    scan.end_time = datetime.utcnow()
    db.commit()

    # R2: Kill the nmap subprocess if it's still running
    killed = kill_scan_process(scan_id)

    create_audit_log(
        db,
        f"Scan {scan_id} cancelled by {email}" + (" (subprocess terminated)" if killed else ""),
        email
    )

    return {"scan_id": scan_id, "status": "cancelled", "message": "Scan cancelled successfully"}


@router.get("/history")
def get_scan_history(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
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

    total = query.count()
    scans = query.order_by(Scan.start_time.desc()).offset(skip).limit(limit).all()
    return {
        "items": [
            {
                "scan_id": s.scan_id,
                "ip": s.target.ip_address if s.target else None,
                "user": s.user.email if s.user else None,
                "status": s.status,
                "start_time": s.start_time,
                "end_time": s.end_time
            }
            for s in scans
        ],
        "total": total,
        "skip": skip,
        "limit": limit
    }