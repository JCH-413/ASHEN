'''
This module allows authenticated Admins to query the AUDIT_LOG table, optionally filter by:

- user (performed_by)
- date range (start, end)
- action keyword (action)
- pagination

it is an admin api router
'''
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, List
from app.core.db import get_db
from app.models.audit_log import AuditLog
from app.models.admin import Admin
from app.core.security import require_admin

# for accessing user_sessions
from app.models.user_session import UserSession
from app.models.user import User

# for adding and listing of authorize targets
from app.models.target_system import TargetSystem
from app.models.scan import Scan
from app.utils.logging_utils import create_audit_log

# for scan request
from app.models.scan_request import ScanRequest, RequestStatus
from app.schemas.admin_schema import TargetCreate, ScanRequestReview

router = APIRouter()

@router.get("/audit-logs", dependencies=[Depends(require_admin)])
def get_audit_logs(
    db: Session = Depends(get_db),
    performed_by: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 20
):
    """
    Returns filtered audit logs (Admin-only).
    Filters:
      - performed_by (str): user/admin email
      - action (str): keyword search
      - start/end (ISO datetime strings)
      - skip/limit: pagination
    """
    query = db.query(AuditLog)

    if performed_by:
        query = query.filter(AuditLog.performed_by.ilike(f"%{performed_by}%"))
    if action:
        query = query.filter(AuditLog.action.ilike(f"%{action}%"))
    if start:
        start_dt = datetime.fromisoformat(start)
        query = query.filter(AuditLog.timestamp >= start_dt)
    if end:
        end_dt = datetime.fromisoformat(end)
        query = query.filter(AuditLog.timestamp <= end_dt)

    logs = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()

    return [
        {
            "log_id": log.log_id,
            "action": log.action,
            "performed_by": log.performed_by,
            "timestamp": log.timestamp.isoformat()
        }
        for log in logs
    ]

# updating code to let the admin access user_sessions

@router.get("/sessions", dependencies=[Depends(require_admin)])
def get_all_sessions(
    db: Session = Depends(get_db),
    active_only: bool = Query(False, description="Show only active sessions"),
    skip: int = 0,
    limit: int = 50
):
    """
    Admin-only endpoint.
    Returns all user and admin sessions with login/logout info.
    Set active_only=true to show only currently active sessions.
    """
    query = db.query(UserSession).outerjoin(User, User.user_id == UserSession.user_id).outerjoin(Admin, Admin.admin_id == UserSession.admin_id)

    if active_only:
        query = query.filter(UserSession.logout_time == None)

    sessions = query.order_by(UserSession.login_time.desc()).offset(skip).limit(limit).all()

    return [
        {
            "session_id": s.session_id,
            "user_id": s.user_id,
            "admin_id": s.admin_id,
            "user_name": s.user.name if s.user else (s.admin.name if s.admin else None),
            "user_email": s.user.email if s.user else (s.admin.email if s.admin else None),
            "login_time": s.login_time.isoformat() if s.login_time else None,
            "logout_time": s.logout_time.isoformat() if s.logout_time else None,
            "status": "Active" if not s.logout_time else "Closed"
        }
        for s in sessions
    ]

# to get user specific session
@router.get("/sessions/{user_id}", dependencies=[Depends(require_admin)])
def get_user_sessions(user_id: int, db: Session = Depends(get_db)):
    sessions = db.query(UserSession).filter(UserSession.user_id == user_id).all()
    if not sessions:
        raise HTTPException(status_code=404, detail="No sessions found for this user")

    return [
        {
            "session_id": s.session_id,
            "login_time": s.login_time.isoformat() if s.login_time else None,
            "logout_time": s.logout_time.isoformat() if s.logout_time else None,
            "status": "Active" if not s.logout_time else "Closed"
        }
        for s in sessions
    ]

# to add authorize targets
@router.post("/targets")
def add_authorized_ip(body: TargetCreate, db: Session = Depends(get_db), admin_payload: dict = Depends(require_admin)):
    admin_email = admin_payload.get("sub")
    admin = db.query(Admin).filter(Admin.email == admin_email).first()
    existing = db.query(TargetSystem).filter(TargetSystem.ip_address == body.ip_address).first()

    if existing and existing.authorized:
        raise HTTPException(status_code=400, detail="IP already authorized")

    if existing and not existing.authorized:
        existing.authorized = True
        existing.added_by = admin.admin_id
        db.commit()
        create_audit_log(db, f"Admin {admin.email} re-authorized target {body.ip_address}", admin.email)
        return {"message": f"IP {body.ip_address} re-authorized successfully"}

    target = TargetSystem(ip_address=body.ip_address, added_by=admin.admin_id)
    db.add(target)
    db.commit()
    create_audit_log(db, f"Admin {admin.email} authorized target {body.ip_address}", admin.email)
    return {"message": f"IP {body.ip_address} authorized successfully"}

# to list authorizes targers
@router.get("/targets", dependencies=[Depends(require_admin)])
def list_authorized_targets(db: Session = Depends(get_db)):
    targets = db.query(TargetSystem).filter(TargetSystem.authorized == True).all()
    return [
    	{
    		"target_id": t.target_id, 
    		"ip": t.ip_address, 
    		"added by": t.added_by,
    		"authorized": t.authorized, 
    		"created_at": t.created_at
    	} 
    	for t in targets
    ]


@router.delete("/targets/{target_id}")
def delete_authorized_target(
    target_id: int,
    db: Session = Depends(get_db),
    admin_payload: dict = Depends(require_admin),
):
    admin_email = admin_payload.get("sub")
    admin = db.query(Admin).filter(Admin.email == admin_email).first()

    target = db.query(TargetSystem).filter(TargetSystem.target_id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Keep scan history intact: if scans exist, deactivate authorization instead of hard delete.
    related_scans = db.query(Scan).filter(Scan.target_system_id == target.target_id).count()
    target_ip = target.ip_address

    if related_scans > 0:
        target.authorized = False
        db.commit()
        create_audit_log(
            db,
            f"Admin {admin.email} removed target {target_ip} from authorized list (kept for history)",
            admin.email,
        )
        return {
            "message": f"IP {target_ip} removed from authorized list",
            "target_id": target_id,
            "soft_removed": True,
        }

    db.delete(target)
    db.commit()
    create_audit_log(db, f"Admin {admin.email} deleted target {target_ip}", admin.email)
    return {
        "message": f"IP {target_ip} deleted successfully",
        "target_id": target_id,
        "soft_removed": False,
    }

# to review scan request
@router.get("/scan-requests", dependencies=[Depends(require_admin)])
def get_pending_requests(db: Session = Depends(get_db)):
    requests = db.query(ScanRequest).filter(ScanRequest.status == RequestStatus.PENDING).all()
    return [
        {
            "request_id": r.request_id,
            "target_ip": r.target_ip,
            "requested_by": r.requested_by,
            "status": r.status.value,
            "created_at": r.created_at
        }
        for r in requests
    ]

@router.post("/scan-requests/{request_id}/review")
def review_scan_request(request_id: int, body: ScanRequestReview, db: Session = Depends(get_db), admin_payload: dict = Depends(require_admin)):
    request = db.query(ScanRequest).filter(ScanRequest.request_id == request_id).first()
    if not request:
        raise HTTPException(status_code=404, detail="Request not found")

    admin_email = admin_payload.get("sub")
    admin = db.query(Admin).filter(Admin.email == admin_email).first()

    request.status = RequestStatus.APPROVED if body.approve else RequestStatus.DENIED
    request.reviewed_by = admin.admin_id
    request.reviewed_at = datetime.utcnow()

    if body.approve:
        # Auto add to authorized targets
        if not db.query(TargetSystem).filter(TargetSystem.ip_address == request.target_ip).first():
            target = TargetSystem(ip_address=request.target_ip, added_by=admin.admin_id)
            db.add(target)
        create_audit_log(db, f"Admin {admin.email} approved scan request for {request.target_ip}", admin.email)
    else:
        create_audit_log(db, f"Admin {admin.email} denied scan request for {request.target_ip}", admin.email)

    db.commit()
    return {"message": f"Request {'approved' if body.approve else 'denied'} successfully"}
