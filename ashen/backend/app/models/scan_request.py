# scan request from user to admin to authorize an ip to be scanned

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
from enum import Enum as PyEnum
from app.core.db import Base

class RequestStatus(PyEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"

class ScanRequest(Base):
    __tablename__ = "scan_request"

    request_id = Column(Integer, primary_key=True, index=True)
    requested_by = Column(Integer, ForeignKey("user.user_id"), nullable=False)
    target_ip = Column(String, nullable=False)
    reason = Column(String, nullable=True)
    status = Column(Enum(RequestStatus), default=RequestStatus.PENDING)
    created_at = Column(DateTime, default=datetime.utcnow)
    reviewed_by = Column(Integer, ForeignKey("admin.admin_id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
