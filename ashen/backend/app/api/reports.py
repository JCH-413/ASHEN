"""
reports.py
API routes for report generation and retrieval.
All routes require JWT authentication.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.orm import Session
from app.core.db import get_db
from app.core.security import get_current_user
from app.models.report import Report
from app.models.scan import Scan
from app.utils.logging_utils import create_audit_log
from app.services.report_builder import (
    build_report_data,
    generate_html_report,
    generate_csv_report,
)
from app.schemas.report_schema import ReportGenerateRequest

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post("/generate")
def generate_report(
    body: ReportGenerateRequest,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.scan_id == body.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if body.format not in ("html", "csv"):
        raise HTTPException(status_code=400, detail="Format must be 'html' or 'csv'")

    data = build_report_data(db, body.scan_id)

    if body.format == "html":
        content = generate_html_report(data)
    else:
        content = generate_csv_report(data)

    email = current_payload.get("sub", "unknown")

    report = Report(
        scan_id=body.scan_id,
        generated_by=email,
        format=body.format,
        content=content,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    create_audit_log(db, f"Report generated for scan {body.scan_id} ({body.format})", email)

    return {
        "report_id": report.report_id,
        "scan_id": body.scan_id,
        "format": body.format,
        "generated_by": email,
        "created_at": report.created_at.isoformat() if report.created_at else None,
        "message": "Report generated successfully",
    }


@router.get("/")
def list_reports(
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    reports = db.query(Report).order_by(Report.created_at.desc()).all()
    return [
        {
            "report_id": r.report_id,
            "scan_id": r.scan_id,
            "format": r.format,
            "generated_by": r.generated_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in reports
    ]


@router.get("/{report_id}")
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    report = db.query(Report).filter(Report.report_id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "report_id": report.report_id,
        "scan_id": report.scan_id,
        "format": report.format,
        "generated_by": report.generated_by,
        "created_at": report.created_at.isoformat() if report.created_at else None,
        "content": report.content,
    }


@router.get("/{report_id}/download")
def download_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_payload: dict = Depends(get_current_user),
):
    report = db.query(Report).filter(Report.report_id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.format == "html":
        return HTMLResponse(
            content=report.content,
            headers={"Content-Disposition": f"attachment; filename=ashen_report_{report.scan_id}.html"},
        )
    else:
        return PlainTextResponse(
            content=report.content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=ashen_report_{report.scan_id}.csv"},
        )
