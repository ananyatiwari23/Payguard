import os
import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator
from pwdlib import PasswordHash


# Load the project's root .env file.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

SECRET_KEY = os.getenv("PAYGUARD_JWT_SECRET", "")
if len(SECRET_KEY) < 32:
    raise RuntimeError(
        "PAYGUARD_JWT_SECRET is missing or too short. Configure it in the project .env file."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 60
DATABASE_PATH = Path(__file__).resolve().parent / "payguard_auth.db"

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
security = HTTPBearer(auto_error=False)
password_hash = PasswordHash.recommended()


# -------------------- DATABASE --------------------

def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'owner',
                org_id TEXT,
                org_name TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)
        connection.commit()


initialize_database()


# -------------------- REQUEST MODELS --------------------

class SignupRequest(BaseModel):
    fullName: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=8, max_length=128)
    orgName: str | None = Field(default=None, max_length=120)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        value = value.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            raise ValueError("Enter a valid email address")
        return value

    @field_validator("fullName")
    @classmethod
    def validate_name(cls, value):
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Full name must contain at least 2 characters")
        return value

    @field_validator("orgName")
    @classmethod
    def clean_org_name(cls, value):
        return value.strip() if value and value.strip() else None


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value):
        return value.strip().lower()


# -------------------- USER AND TOKEN HELPERS --------------------

def user_profile(row):
    return {
        "id": row["id"],
        "email": row["email"],
        "fullName": row["full_name"],
        "role": row["role"],
        "orgId": row["org_id"],
        "orgName": row["org_name"],
        "isActive": bool(row["is_active"]),
    }


def create_access_token(user_id):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def auth_response(row):
    return {
        "accessToken": create_access_token(row["id"]),
        "tokenType": "bearer",
        "expiresIn": ACCESS_TOKEN_MINUTES * 60,
        "user": user_profile(row),
    }


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
):
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )
        user_id = payload.get("sub")
        if not user_id:
            raise ValueError("Missing token subject")
    except (jwt.InvalidTokenError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
        )

    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE id = ? AND is_active = 1",
            (user_id,),
        ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return row


# -------------------- AUTH ENDPOINTS --------------------

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(data: SignupRequest):
    user_id = str(uuid.uuid4())
    org_id = str(uuid.uuid4()) if data.orgName else None
    hashed_password = password_hash.hash(data.password)

    try:
        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO users
                (id, email, full_name, password_hash, role,
                 org_id, org_name, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    data.email,
                    data.fullName,
                    hashed_password,
                    "owner",
                    org_id,
                    data.orgName,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            row = connection.execute(
                "SELECT * FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    return auth_response(row)


@router.post("/login")
def login(data: LoginRequest):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE email = ? AND is_active = 1",
            (data.email,),
        ).fetchone()

    if row is None or not password_hash.verify(
        data.password, row["password_hash"]
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    return auth_response(row)


@router.get("/me")
def get_me(current_user=Depends(get_current_user)):
    return user_profile(current_user)


@router.post("/logout")
def logout(current_user=Depends(get_current_user)):
    # The frontend clears its stored access token.
    return {"message": "Logged out successfully"}
