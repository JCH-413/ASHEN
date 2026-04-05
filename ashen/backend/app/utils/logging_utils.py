from datetime import datetime
from sqlalchemy.orm import Session
from app.models.audit_log import AuditLog
from app.models.user_session import UserSession


def create_audit_log(db: Session, action: str, performed_by: str):
    """Insert a real audit log entry into the database."""
    try:
        log = AuditLog(
            action=action,
            performed_by=performed_by,
            timestamp=datetime.utcnow()
        )
        db.add(log)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[!] Audit log failed: {e}")


def create_user_session(db: Session, user_id: int = None, admin_id: int = None):
    """Create a new session row when a user or admin logs in."""
    try:
        session = UserSession(
            user_id=user_id,
            admin_id=admin_id,
            login_time=datetime.utcnow()
        )
        db.add(session)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[!] Session creation failed: {e}")


def close_user_session(db: Session, user_id: int = None, admin_id: int = None):
    """Close the most recent open session for a user or admin."""
    try:
        query = db.query(UserSession).filter(UserSession.logout_time == None)
        if user_id:
            query = query.filter(UserSession.user_id == user_id)
        elif admin_id:
            query = query.filter(UserSession.admin_id == admin_id)
        else:
            return

        session = query.order_by(UserSession.login_time.desc()).first()
        if session:
            session.logout_time = datetime.utcnow()
            db.commit()
    except Exception as e:
        db.rollback()
        print(f"[!] Session close failed: {e}")
