"""Security utilities: password hashing, API keys, JWT tokens."""

import os
import secrets
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt

_SECRET_KEY = os.environ.get("AUTH_SECRET_KEY", "change-me-in-production")
_ALGORITHM = "HS256"
_TOKEN_EXPIRE_MINUTES = int(os.environ.get("AUTH_TOKEN_EXPIRE_MINUTES", "60"))


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(password.encode(), hashed.encode())


def generate_api_key() -> str:
    """Generate a cryptographically secure API key."""
    return secrets.token_hex(32)


def create_access_token(user_id: str, email: str) -> str:
    """Create a JWT access token."""
    expire = datetime.now(UTC) + timedelta(minutes=_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "email": email,
        "exp": expire,
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, _SECRET_KEY, algorithm=_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token.

    Raises:
        jwt.ExpiredSignatureError: If token is expired.
        jwt.InvalidTokenError: If token is invalid.
    """
    return jwt.decode(token, _SECRET_KEY, algorithms=[_ALGORITHM])  # type: ignore[no-any-return]
