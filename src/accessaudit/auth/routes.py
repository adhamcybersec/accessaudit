"""Authentication API routes."""

from fastapi import APIRouter, HTTPException, Request

from accessaudit.auth.models import TokenResponse, UserCreate, UserLogin, UserResponse
from accessaudit.auth.security import (
    create_access_token,
    generate_api_key,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(request: Request, body: UserCreate) -> TokenResponse:
    """Register a new user. Returns JWT token and API key."""
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        raise HTTPException(status_code=503, detail="Database not configured")

    from accessaudit.db.repository import UserRepository

    async with session_factory() as session:
        repo = UserRepository(session)

        existing = await repo.get_by_email(body.email)
        if existing:
            raise HTTPException(status_code=409, detail="Email already registered")

        api_key = generate_api_key()
        password_hash = hash_password(body.password)
        user = await repo.create(body.email, password_hash, api_key)
        await session.commit()

        token = create_access_token(str(user.id), user.email)

    return TokenResponse(access_token=token, api_key=api_key)


@router.post("/login", response_model=TokenResponse)
async def login(request: Request, body: UserLogin) -> TokenResponse:
    """Login with email and password. Returns JWT token and API key."""
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        raise HTTPException(status_code=503, detail="Database not configured")

    from accessaudit.db.repository import UserRepository

    async with session_factory() as session:
        repo = UserRepository(session)
        user = await repo.get_by_email(body.email)

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    token = create_access_token(str(user.id), user.email)
    return TokenResponse(access_token=token, api_key=user.api_key)


@router.get("/me", response_model=UserResponse)
async def get_me(request: Request) -> UserResponse:
    """Get current user info. Requires authentication."""
    from accessaudit.auth.dependencies import get_current_user

    user = await get_current_user(request)
    return UserResponse(
        id=str(user.id),
        email=user.email,
        api_key=user.api_key,
        is_active=user.is_active,
    )


@router.post("/rotate-key", response_model=UserResponse)
async def rotate_key(request: Request) -> UserResponse:
    """Rotate the current user's API key. Requires authentication."""
    from accessaudit.auth.dependencies import get_current_user

    user = await get_current_user(request)

    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        raise HTTPException(status_code=503, detail="Database not configured")

    from accessaudit.db.repository import UserRepository

    new_api_key = generate_api_key()
    async with session_factory() as session:
        repo = UserRepository(session)
        await repo.update_api_key(user.id, new_api_key)
        await session.commit()

    return UserResponse(
        id=str(user.id),
        email=user.email,
        api_key=new_api_key,
        is_active=user.is_active,
    )
