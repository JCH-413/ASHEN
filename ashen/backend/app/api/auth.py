from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.db import get_db
from app.models.admin import Admin
from app.models.user import User
from app.core.security import hash_password, verify_password, require_admin
from app.utils.jwt_handler import create_access_token, decode_access_token
from app.utils.logging_utils import create_audit_log, create_user_session, close_user_session
from app.schemas.user_schema import UserLogin, UserCreate
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

router = APIRouter()
bearer_scheme = HTTPBearer()


# --- Admin Login (public) ---
@router.post("/admin-login")
def admin_login(body: UserLogin, db: Session = Depends(get_db)):
    admin = db.query(Admin).filter(Admin.email == body.email).first()
    if not admin or not verify_password(body.password, admin.password):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    token = create_access_token({"sub": admin.email, "role": "Admin"})
    create_audit_log(db, f"Admin {admin.email} logged in", admin.email)
    create_user_session(db, admin_id=admin.admin_id)
    return {"access_token": token, "role": "Admin"}


# --- Analyst Login (public) ---
@router.post("/user-login")
def user_login(body: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid user credentials")
    token = create_access_token({"sub": user.email, "role": "Analyst"})
    create_audit_log(db, f"User {user.email} logged in", user.email)
    create_user_session(db, user_id=user.user_id)
    return {"access_token": token, "role": "Analyst"}


# --- Admin creates Analyst (JWT protected) ---
@router.post("/create-user")
def create_user(
    body: UserCreate,
    db: Session = Depends(get_db),
    admin_payload: dict = Depends(require_admin)
):
    admin_email = admin_payload.get("sub", "")
    admin = db.query(Admin).filter(Admin.email == admin_email).first()
    if not admin:
        raise HTTPException(status_code=403, detail="Admin not found")
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=400, detail="User already exists")

    new_user = User(
        name=body.name,
        email=body.email,
        password=hash_password(body.password),
        created_by=admin.admin_id
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    create_audit_log(db, f"Admin {admin_email} created user {body.email}", admin_email)
    return {"message": f"User {body.name} created successfully by {admin.name}"}


# --- Admin Logout (JWT verified) ---
@router.post("/admin-logout")
def admin_logout(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db)
):
    payload = decode_access_token(credentials.credentials)
    if not payload or payload.get("role") != "Admin":
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    email = payload.get("sub")
    admin = db.query(Admin).filter(Admin.email == email).first()
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    close_user_session(db, admin_id=admin.admin_id)    # admin_id
    create_audit_log(db, f"Admin {email} logged out", email)
    return {"message": "Admin logged out successfully"}


# --- User Logout (JWT verified) ---
@router.post("/user-logout")
def user_logout(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db)
):
    payload = decode_access_token(credentials.credentials)
    if not payload or payload.get("role") != "Analyst":
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    email = payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    close_user_session(db, user_id=user.user_id)       # user_id
    create_audit_log(db, f"User {email} logged out", email)
    return {"message": "User logged out successfully"}