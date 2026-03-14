"""Tests for authentication security utilities."""

import pytest

from accessaudit.auth.security import (
    create_access_token,
    decode_access_token,
    generate_api_key,
    hash_password,
    verify_password,
)


def test_hash_password():
    hashed = hash_password("my_secret")
    assert hashed != "my_secret"
    assert hashed.startswith("$2")


def test_verify_password_correct():
    hashed = hash_password("my_secret")
    assert verify_password("my_secret", hashed) is True


def test_verify_password_wrong():
    hashed = hash_password("my_secret")
    assert verify_password("wrong_password", hashed) is False


def test_generate_api_key():
    key = generate_api_key()
    assert len(key) == 64  # 32 bytes hex
    # Each key should be unique
    assert generate_api_key() != generate_api_key()


def test_create_and_decode_access_token():
    token = create_access_token("user-123", "test@test.com")
    payload = decode_access_token(token)
    assert payload["sub"] == "user-123"
    assert payload["email"] == "test@test.com"
    assert "exp" in payload
    assert "iat" in payload


def test_decode_invalid_token():
    import jwt

    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token("invalid.token.here")
