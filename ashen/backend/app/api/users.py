# This file is to route (fetch logged-in user)

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.db import get_db
from app.models.user import User
from app.core.security import get_current_user

router = APIRouter()


@router.get("/me")
def read_users_me(db: Session = Depends(get_db), current_payload: dict = Depends(get_current_user)):
    role = current_payload.get("role")
    if role != "Analyst":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only users can access this endpoint"
        )

    email = current_payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return {
        "id": user.user_id,
        "username": user.name,
        "email": user.email
    }
