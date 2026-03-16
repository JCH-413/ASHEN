# This file handles password hashing and auth dependencies

from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from app.utils.jwt_handler import decode_access_token
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

bearer_scheme = HTTPBearer()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def require_admin(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    payload = decode_access_token(token)

    if not payload or payload.get("role") != "Admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required or token invalid"
        )

    return payload


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    """Decode JWT and return the payload. Works for both Admin and Analyst tokens."""
    from sqlalchemy.orm import Session
    from app.core.db import get_db
    from app.models.user import User
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return payload


def get_current_analyst(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    """Decode JWT and fetch the Analyst user from the DB."""
    from sqlalchemy.orm import Session
    from app.core.db import SessionLocal
    from app.models.user import User
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    email = payload.get("sub")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        return user
    finally:
        db.close()
