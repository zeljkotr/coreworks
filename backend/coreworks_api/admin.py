from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from coreworks_api.auth import get_current_user, get_db
from coreworks_api.models import User

router = APIRouter(prefix="/admin", tags=["administration"])


class AdminUser(BaseModel):
    id: int
    username: str
    role: str
    created_at: datetime


@router.get("/users", response_model=list[AdminUser])
def list_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[AdminUser]:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return list(db.scalars(select(User).order_by(User.id)).all())
