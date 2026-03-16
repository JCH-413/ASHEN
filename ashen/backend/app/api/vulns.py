from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.db import get_db
from app.models.vulnerability import Vulnerability
from app.core.security import get_current_user

router = APIRouter(prefix="/vulns", tags=["Vulnerabilities"])

@router.get("/by-scan/{scan_id}")
def get_vulns_by_scan(scan_id: int, db: Session = Depends(get_db), _: dict = Depends(get_current_user)):
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
            "timestamp": v.timestamp
        }
        for v in vulns
    ]

@router.get("/all")
def get_all_vulns(db: Session = Depends(get_db), _: dict = Depends(get_current_user)):
    vulns = db.query(Vulnerability).order_by(Vulnerability.timestamp.desc()).all()
    return [
        {
            "vuln_id": v.vuln_id,
            "scan_id": v.scan_id,
            "port": v.port,
            "script_id": v.script_id,
            "severity": v.severity,
            "description": v.description,
            "timestamp": v.timestamp
        }
        for v in vulns
    ]
