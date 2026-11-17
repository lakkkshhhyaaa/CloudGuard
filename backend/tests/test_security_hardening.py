from types import SimpleNamespace
from unittest.mock import Mock

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError
from starlette.requests import Request

from app import security


@pytest.fixture
def mock_request():
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/api/me",
        "raw_path": b"/api/me",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    return Request(scope)


@pytest.fixture
def credentials():
    return HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="dummy.jwt.token",
    )


@pytest.fixture
def valid_payload():
    return {
        "sub": "keycloak-user-123",
        "preferred_username": "alex.morgan",
        "azp": security.KEYCLOAK_CLIENT_ID,
        "realm_access": {"roles": ["IT_ADMIN"]},
    }


@pytest.fixture
def mocked_auth(monkeypatch, valid_payload):
    signing_key = SimpleNamespace(key="test-public-key")
    get_key = Mock(return_value=signing_key)
    decode = Mock(return_value=valid_payload)
    audit = Mock(return_value=True)

    monkeypatch.setattr(
        security.jwks_client,
        "get_signing_key_from_jwt",
        get_key,
    )
    monkeypatch.setattr(security.jwt, "decode", decode)
    monkeypatch.setattr(security, "record_audit_event", audit)

    return SimpleNamespace(
        get_key=get_key,
        decode=decode,
        audit=audit,
        signing_key=signing_key,
    )


def test_valid_token_returns_payload(mock_request, credentials, valid_payload, mocked_auth):
    result = security.verify_token(mock_request, credentials)

    assert result == valid_payload
    mocked_auth.get_key.assert_called_once_with("dummy.jwt.token")
    mocked_auth.decode.assert_called_once_with(
        "dummy.jwt.token",
        mocked_auth.signing_key.key,
        algorithms=["RS256"],
        issuer=security.ISSUER,
        audience=security.KEYCLOAK_API_AUDIENCE,
        options={"require": ["exp", "iat", "sub"]},
    )
    mocked_auth.audit.assert_not_called()


def test_missing_credentials_returns_401_and_audits(mock_request, monkeypatch):
    audit = Mock(return_value=True)
    monkeypatch.setattr(security, "record_audit_event", audit)

    with pytest.raises(HTTPException) as exc:
        security.verify_token(mock_request, None)

    assert exc.value.status_code == 401
    assert exc.value.headers["WWW-Authenticate"] == "Bearer"
    audit.assert_called_once()
    assert audit.call_args.kwargs["details"] == {
        "reason": "Missing bearer token"
    }


def test_wrong_authorized_party_returns_401(mock_request, credentials, valid_payload, mocked_auth):
    valid_payload["azp"] = "unexpected-client"

    with pytest.raises(HTTPException) as exc:
        security.verify_token(mock_request, credentials)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid token client"
    mocked_auth.audit.assert_called_once()
    assert mocked_auth.audit.call_args.kwargs["details"] == {
        "reason": "Invalid token client"
    }


def test_invalid_jwt_returns_401_and_audits(mock_request, credentials, mocked_auth):
    mocked_auth.decode.side_effect = jwt.InvalidTokenError("invalid token")

    with pytest.raises(HTTPException) as exc:
        security.verify_token(mock_request, credentials)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid or expired access token"
    mocked_auth.audit.assert_called_once()


def test_missing_required_claim_is_rejected_by_decode_options(
    mock_request, credentials, mocked_auth
):
    # PyJWT enforces required claims using the options passed to decode().
    security.verify_token(mock_request, credentials)

    options = mocked_auth.decode.call_args.kwargs["options"]
    assert set(options["require"]) == {"exp", "iat", "sub"}


def test_jwks_connection_failure_returns_503_without_invalid_token_audit(
    mock_request, credentials, mocked_auth
):
    mocked_auth.get_key.side_effect = PyJWKClientConnectionError(
        "Keycloak is unreachable"
    )

    with pytest.raises(HTTPException) as exc:
        security.verify_token(mock_request, credentials)

    assert exc.value.status_code == 503
    assert exc.value.detail == "Unable to verify authentication token"
    mocked_auth.audit.assert_not_called()


def test_jwks_signing_key_error_returns_401_and_audits(
    mock_request, credentials, mocked_auth
):
    mocked_auth.get_key.side_effect = PyJWKClientError(
        "No matching signing key"
    )

    with pytest.raises(HTTPException) as exc:
        security.verify_token(mock_request, credentials)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid or expired access token"
    mocked_auth.audit.assert_called_once()


def test_unexpected_error_returns_503(mock_request, credentials, mocked_auth):
    mocked_auth.get_key.side_effect = RuntimeError("unexpected failure")

    with pytest.raises(HTTPException) as exc:
        security.verify_token(mock_request, credentials)

    assert exc.value.status_code == 503
    assert exc.value.detail == "Unable to verify authentication token"
    mocked_auth.audit.assert_not_called()


def test_authentication_audit_does_not_include_token(
    mock_request, credentials, mocked_auth
):
    mocked_auth.decode.side_effect = jwt.InvalidTokenError("invalid token")

    with pytest.raises(HTTPException):
        security.verify_token(mock_request, credentials)

    audit_details = mocked_auth.audit.call_args.kwargs
    assert "dummy.jwt.token" not in repr(audit_details)
    assert "authorization" not in repr(audit_details).lower()
