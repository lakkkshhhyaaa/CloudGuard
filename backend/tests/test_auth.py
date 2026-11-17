import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.authorization import require_roles
from app.main import app as main_app
from app.security import verify_token


# Tests for the real application's authentication endpoints.
main_client = TestClient(main_app)


def test_me_rejects_missing_token():
    response = main_client.get("/api/me")
    assert response.status_code == 401


def test_me_rejects_invalid_token():
    response = main_client.get(
        "/api/me",
        headers={"Authorization": "Bearer invalid.test.token"},
    )
    assert response.status_code == 401


# Test the real authorization dependency without requiring a real Keycloak token.
admin_required = require_roles("IT_ADMIN")
authorization_app = FastAPI()


@authorization_app.get("/admin")
def admin_endpoint(current_user: dict = Depends(admin_required)):
    return {"message": "Welcome, admin"}


authorization_client = TestClient(authorization_app)


@pytest.fixture(autouse=True)
def clear_dependency_overrides():
    authorization_app.dependency_overrides.clear()
    yield
    authorization_app.dependency_overrides.clear()


def test_authorized_admin_can_access_endpoint():
    authorization_app.dependency_overrides[verify_token] = lambda: {
        "sub": "test-admin-id",
        "preferred_username": "alex.morgan",
        "realm_access": {"roles": ["IT_ADMIN"]},
    }

    response = authorization_client.get("/admin")

    assert response.status_code == 200
    assert response.json() == {"message": "Welcome, admin"}


def test_security_analyst_cannot_access_admin_endpoint(monkeypatch):
    audit_events = []

    def fake_record_audit_event(**event):
        audit_events.append(event)
        return True

    # Avoid writing test audit records into the development database.
    monkeypatch.setattr(
        "app.authorization.record_audit_event",
        fake_record_audit_event,
    )

    authorization_app.dependency_overrides[verify_token] = lambda: {
        "sub": "test-security-analyst-id",
        "preferred_username": "rahul.verma",
        "realm_access": {"roles": ["SECURITY_ANALYST"]},
    }

    response = authorization_client.get("/admin")

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "You do not have permission to access this resource"
    )

    assert len(audit_events) == 1
    assert audit_events[0]["action"] == "AUTHORIZATION_DENIED"
    assert audit_events[0]["outcome"] == "DENIED"
    assert audit_events[0]["username"] == "rahul.verma"
