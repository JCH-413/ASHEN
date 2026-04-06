from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from app.core.db import get_db
from app.models.vulnerability import Vulnerability
from app.models.scan import Scan
from app.models.user import User
from app.core.security import get_current_user

router = APIRouter(prefix="/vulns", tags=["Vulnerabilities"])


@router.get("/by-scan/{scan_id}")
def get_vulns_by_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    # Verify scan exists and user owns it
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    role = current_payload.get("role")
    if role != "Admin":
        email = current_payload.get("sub")
        user = db.query(User).filter(User.email == email).first()
        if not user or scan.user_id != user.user_id:
            raise HTTPException(status_code=403, detail="Not authorized to view this scan's vulnerabilities")

    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    if not vulns:
        raise HTTPException(status_code=404, detail="No vulnerabilities found for this scan")
    return [
        {
            "vuln_id": v.vuln_id,
            "port": v.port,
            "script_id": v.script_id,
            "severity": v.severity,
            "description": v.description,
            "raw_output": v.raw_output,
            "timestamp": v.timestamp,
        }
        for v in vulns
    ]


@router.get("/all")
def get_all_vulns(
    scan_id: Optional[int] = Query(None, description="Filter by scan ID"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    port: Optional[int] = Query(None, description="Filter by port"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    role = current_payload.get("role")

    if role == "Admin":
        query = db.query(Vulnerability)
    else:
        # Analysts only see vulns from their own scans
        email = current_payload.get("sub")
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        query = (
            db.query(Vulnerability)
            .join(Scan, Vulnerability.scan_id == Scan.scan_id)
            .filter(Scan.user_id == user.user_id)
        )

    # Apply filters
    if scan_id is not None:
        query = query.filter(Vulnerability.scan_id == scan_id)
    if severity is not None:
        query = query.filter(Vulnerability.severity == severity.lower())
    if port is not None:
        query = query.filter(Vulnerability.port == port)

    total = query.count()
    vulns = query.order_by(Vulnerability.timestamp.desc()).offset(skip).limit(limit).all()

    return {
        "items": [
            {
                "vuln_id": v.vuln_id,
                "scan_id": v.scan_id,
                "port": v.port,
                "script_id": v.script_id,
                "severity": v.severity,
                "description": v.description,
                "raw_output": v.raw_output,
                "timestamp": v.timestamp,
            }
            for v in vulns
        ],
        "total": total,
        "skip": skip,
        "limit": limit
    }
