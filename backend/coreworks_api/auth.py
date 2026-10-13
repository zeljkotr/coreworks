from collections.abc import Generator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from coreworks_api.db import engine
from coreworks_api.models import User
from coreworks_api.security import hash_password, verify_password
from coreworks_api.tokens import create_access_token, read_access_token

router = APIRouter(prefix="/auth", tags=["authentication"])
bearer = HTTPBearer(auto_error=False)


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=1024)


class PublicUser(BaseModel):
    id: int
    username: str
    role: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: PublicUser


def get_db() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer token required")
    user_id = read_access_token(credentials.credentials)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def _response(user: User) -> AuthResponse:
    return AuthResponse(
        access_token=create_access_token(user.id),
        user=PublicUser(id=user.id, username=user.username, role=user.role),
    )


@router.post("/register", response_model=AuthResponse, status_code=201)
def register(data: Credentials, db: Session = Depends(get_db)) -> AuthResponse:
    username = data.username.strip()
    if len(username) < 3:
        raise HTTPException(status_code=422, detail="Invalid username")
    user = User(
        username=username,
        password_hash=hash_password(data.password),
        role="user",
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username already exists") from None
    return _response(user)


@router.post("/login", response_model=AuthResponse)
def login(data: Credentials, db: Session = Depends(get_db)) -> AuthResponse:
    username = data.username.strip()
    user = db.scalar(select(User).where(User.username.ilike(username)))
    if user is None or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return _response(user)


@router.get("/me", response_model=PublicUser)
def me(user: User = Depends(get_current_user)) -> PublicUser:
    return PublicUser(id=user.id, username=user.username, role=user.role)
