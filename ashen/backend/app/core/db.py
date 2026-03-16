from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.core.config import DATABASE_URL

# connect_args={"check_same_thread": False} is SQLite-only
# For PostgreSQL this arg must be absent
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def seed_admin():
    from app.models.admin import Admin
    from app.core.security import hash_password
    db = SessionLocal()
    if not db.query(Admin).first():
        admin = Admin(
            name="Root Admin",
            email="admin@ashen.dev",
            password=hash_password("Admin123!")
        )
        db.add(admin)
        db.commit()
    db.close()


def init_db():
    # All models must be imported here so SQLAlchemy knows about them
    # before calling create_all()
    from app.models import admin, user, user_session, audit_log, target_system, scan_request
    from app.models import scan, vulnerability  # these were missing
    Base.metadata.create_all(bind=engine)
    seed_admin()