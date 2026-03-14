"""FastAPI authentication dependencies."""

import uuid

import jwt
from fastapi import HTTPException, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from accessaudit.db.models import UserDB

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    api_key: str | None = Security(api_key_header),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> UserDB:
    """Authenticate user via API key or JWT Bearer token.

    Raises 401 if neither is valid.
    """
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        raise HTTPException(status_code=503, detail="Database not configured")

    from accessaudit.db.repository import UserRepository

    async with session_factory() as session:
        repo = UserRepository(session)

        # Try API key first
        if api_key:
            user = await repo.get_by_api_key(api_key)
            if user and user.is_active:
                return user

        # Try Bearer token
        if bearer:
            try:
                from accessaudit.auth.security import decode_access_token

                payload = decode_access_token(bearer.credentials)
                user_id = uuid.UUID(payload["sub"])
                user = await repo.get_by_id(user_id)
                if user and user.is_active:
                    return user
            except (jwt.InvalidTokenError, KeyError, ValueError):
                pass

    raise HTTPException(status_code=401, detail="Invalid or missing credentials")


async def get_optional_user(
    request: Request,
    api_key: str | None = Security(api_key_header),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> UserDB | None:
    """Authenticate user if credentials provided, return None otherwise.

    Used for dashboard routes where auth is optional.
    """
    if not api_key and not bearer:
        return None

    try:
        return await get_current_user(request, api_key, bearer)
    except HTTPException:
        return None
