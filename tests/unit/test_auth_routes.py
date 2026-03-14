"""Tests for authentication API routes."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from accessaudit.api.app import create_app


@pytest.fixture
def app():
    """Create test app with mocked session factory."""
    app = create_app()
    # Mock session factory for auth routes
    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.commit = AsyncMock()
    mock_session.flush = AsyncMock()

    mock_factory = MagicMock(return_value=mock_session)
    app.state.session_factory = mock_factory
    app.state.db_available = True
    return app


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def test_register_success(client, app):
    """POST /api/v1/auth/register creates user and returns token."""
    mock_user = MagicMock()
    mock_user.id = uuid.uuid4()
    mock_user.email = "test@test.com"
    mock_user.api_key = "test-api-key"
    mock_user.is_active = True

    with patch("accessaudit.db.repository.UserRepository") as mock_repo_cls:
        mock_repo = mock_repo_cls.return_value
        mock_repo.get_by_email = AsyncMock(return_value=None)
        mock_repo.create = AsyncMock(return_value=mock_user)

        response = await client.post(
            "/api/v1/auth/register",
            json={"email": "test@test.com", "password": "secure123"},
        )

    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert "api_key" in data
    assert data["token_type"] == "bearer"


async def test_register_duplicate_email(client, app):
    """POST /api/v1/auth/register with existing email returns 409."""
    mock_existing = MagicMock()
    mock_existing.email = "test@test.com"

    with patch("accessaudit.db.repository.UserRepository") as mock_repo_cls:
        mock_repo = mock_repo_cls.return_value
        mock_repo.get_by_email = AsyncMock(return_value=mock_existing)

        response = await client.post(
            "/api/v1/auth/register",
            json={"email": "test@test.com", "password": "secure123"},
        )

    assert response.status_code == 409


async def test_login_success(client, app):
    """POST /api/v1/auth/login with valid credentials returns token."""
    from accessaudit.auth.security import hash_password

    mock_user = MagicMock()
    mock_user.id = uuid.uuid4()
    mock_user.email = "test@test.com"
    mock_user.password_hash = hash_password("secure123")
    mock_user.api_key = "test-api-key"
    mock_user.is_active = True

    with patch("accessaudit.db.repository.UserRepository") as mock_repo_cls:
        mock_repo = mock_repo_cls.return_value
        mock_repo.get_by_email = AsyncMock(return_value=mock_user)

        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "test@test.com", "password": "secure123"},
        )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["api_key"] == "test-api-key"


async def test_login_wrong_password(client, app):
    """POST /api/v1/auth/login with wrong password returns 401."""
    from accessaudit.auth.security import hash_password

    mock_user = MagicMock()
    mock_user.email = "test@test.com"
    mock_user.password_hash = hash_password("correct_password")
    mock_user.is_active = True

    with patch("accessaudit.db.repository.UserRepository") as mock_repo_cls:
        mock_repo = mock_repo_cls.return_value
        mock_repo.get_by_email = AsyncMock(return_value=mock_user)

        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "test@test.com", "password": "wrong_password"},
        )

    assert response.status_code == 401


async def test_login_nonexistent_user(client, app):
    """POST /api/v1/auth/login with unknown email returns 401."""
    with patch("accessaudit.db.repository.UserRepository") as mock_repo_cls:
        mock_repo = mock_repo_cls.return_value
        mock_repo.get_by_email = AsyncMock(return_value=None)

        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@test.com", "password": "any"},
        )

    assert response.status_code == 401
