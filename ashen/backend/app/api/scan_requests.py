# scan_requests.py
# Analysts can request scan authorization for an IP.
# JWT authentication required.

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.db import get_db
from app.models.scan_request import ScanRequest, RequestStatus
from app.models.target_system import TargetSystem
from app.models.user import User
from app.utils.logging_utils import create_audit_log
from app.core.security import get_current_user
from app.schemas.scan_schema import ScanRequestCreate

router = APIRouter(prefix="/scan", tags=["Scan Requests"])


@router.post("/request-scan")
def request_scan(
    body: ScanRequestCreate,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user)
):
    email = current_payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if IP is already authorized
    if db.query(TargetSystem).filter(
        TargetSystem.ip_address == body.ip_address,
        TargetSystem.authorized == True
    ).first():
        raise HTTPException(status_code=400, detail="IP already authorized — no request needed")

    # Check if a pending request already exists
    if db.query(ScanRequest).filter(
        ScanRequest.target_ip == body.ip_address,
        ScanRequest.status == RequestStatus.PENDING
    ).first():
        raise HTTPException(status_code=400, detail="Request already pending for this IP")

    new_request = ScanRequest(
        requested_by=user.user_id,
        target_ip=body.ip_address,
        reason=body.reason
    )
    db.add(new_request)
    db.commit()
    db.refresh(new_request)

    create_audit_log(
        db,
        f"User {user.email} requested scan authorization for {body.ip_address}",
        user.email
    )
    return {
        "message": f"Scan authorization request for {body.ip_address} submitted",
        "status": new_request.status.value
    }


@router.get("/my-requests")
def my_requests(
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user)
):
    """An analyst's own target-authorization requests + their status.

    Read-only; used by the notifications bell to surface 'IP authorized'.
    """
    email = current_payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    rows = (
        db.query(ScanRequest)
        .filter(ScanRequest.requested_by == user.user_id)
        .order_by(ScanRequest.created_at.desc())
        .all()
    )
    return [
        {
            "request_id": r.request_id,
            "target_ip": r.target_ip,
            "status": r.status.value,
            "created_at": r.created_at,
            "reviewed_at": r.reviewed_at,
        }
        for r in rows
    ]