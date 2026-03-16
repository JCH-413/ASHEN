from sqlalchemy import Column, Integer, ForeignKey, DateTime, CheckConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.db import Base

class UserSession(Base):
    __tablename__ = "user_session"

    session_id   = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, ForeignKey("user.user_id"),   nullable=True)
    admin_id     = Column(Integer, ForeignKey("admin.admin_id"), nullable=True)
    login_time   = Column(DateTime, default=datetime.utcnow)
    logout_time  = Column(DateTime, nullable=True)

    user  = relationship("User",  backref="sessions", foreign_keys=[user_id])
    admin = relationship("Admin", backref="sessions", foreign_keys=[admin_id])

    __table_args__ = (
        CheckConstraint(
            "(user_id IS NOT NULL AND admin_id IS NULL) OR "
            "(user_id IS NULL AND admin_id IS NOT NULL)",
            name="ck_session_user_or_admin"
        ),
    )