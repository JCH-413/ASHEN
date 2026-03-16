# tracks actions

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from datetime import datetime
from app.core.db import Base

class AuditLog(Base):
    __tablename__ = "audit_log"

    log_id = Column(Integer, primary_key=True, index=True)
    action = Column(String, nullable=False)
    performed_by = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
