# updated user.py according to the ERD, linking the FK with Admin

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.db import Base

class User(Base):
    __tablename__ = "user"

    user_id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, default="Analyst")
    created_at = Column(DateTime, default=datetime.utcnow)

    created_by = Column(Integer, ForeignKey("admin.admin_id"), nullable=True)
    admin = relationship("Admin", backref="created_users")
