from app.models.audit_log import AuditLog
from app.models.user_session import UserSession
from sqlalchemy.orm import Session
from datetime import datetime


def create_audit_log(db: Session, action: str, performed_by: str):
    log = AuditLog(action=action, performed_by=performed_by)
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def create_user_session(db: Session, user_id: int = None, admin_id: int = None):
    if not user_id and not admin_id:
        raise ValueError("Either user_id or admin_id must be provided")
    if user_id and admin_id:
        raise ValueError("Only one of user_id or admin_id can be provided")

    session = UserSession(user_id=user_id, admin_id=admin_id)
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def close_user_session(db: Session, user_id: int = None, admin_id: int = None):
    query = db.query(UserSession).filter(UserSession.logout_time == None)

    if user_id:
        query = query.filter(UserSession.user_id == user_id)
    elif admin_id:
        query = query.filter(UserSession.admin_id == admin_id)
    else:
        raise ValueError("Either user_id or admin_id must be provided")

    active_session = query.first()
    if active_session:
        active_session.logout_time = datetime.utcnow()
        db.commit()
        db.refresh(active_session)
        return active_session
    return None