from sqlalchemy import Column, Integer, ForeignKey, String, DateTime, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.db import Base

class Scan(Base):
    __tablename__ = "scan"

    scan_id = Column(Integer, primary_key=True, index=True)
    target_system_id = Column(Integer, ForeignKey("target_system.target_id"))
    user_id = Column(Integer, ForeignKey("user.user_id"))
    session_id = Column(Integer, ForeignKey("user_session.session_id"))
    status = Column(String, default="queued")
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    results_json = Column(Text, nullable=True)

    target = relationship("TargetSystem")
    user = relationship("User")
    session = relationship("UserSession")
