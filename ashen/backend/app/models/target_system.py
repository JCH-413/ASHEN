from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.db import Base

class TargetSystem(Base):
    __tablename__ = "target_system"

    target_id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, nullable=False)
    added_by = Column(Integer, ForeignKey("admin.admin_id"), nullable=False)
    authorized = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
