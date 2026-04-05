from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.db import Base


class Report(Base):
    __tablename__ = "report"

    report_id    = Column(Integer, primary_key=True, index=True)
    scan_id      = Column(Integer, ForeignKey("scan.scan_id"), nullable=False)
    generated_by = Column(String, nullable=False)   # email
    format       = Column(String, default="html")   # html, csv
    content      = Column(Text, nullable=True)       # rendered HTML or CSV text
    created_at   = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", backref="reports")
