import pytest
from fastapi.testclient import TestClient

from app.authorization import record_audit_event
from app.database import get_db
from app.main import app
from app.security import verify_token


client = TestClient(app)


class EmptyQuery:
    """Minimal query stub for endpoints that should find no user."""

    def options(self, *args, **kwargs):
        return self

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return None


class EmptyDatabaseSession:
    def query(self, *args, **kwargs):
        return EmptyQuery()


@pytest.fixture(autouse=True)
def reset_overrides(monkeypatch):
    app.dependency_overrides.clear()

    # Authorization denials should be asserted without writing test
    # events into the development database.
    monkeypatch.setattr(
        "app.authorization.record_audit_event",
        lambda **kwargs: True,
    )

    yield
    app.dependency_overrides.clear()


def use_it_admin():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "test-it-admin-id",
        "preferred_username": "test.admin",
        "realm_access": {"roles": ["IT_ADMIN"]},
    }


def test_non_admin_cannot_create_user():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "test-security-analyst-id",
        "preferred_username": "test.analyst",
        "realm_access": {"roles": ["SECURITY_ANALYST"]},
    }

    response = client.post(
        "/api/admin/users",
        json={
            "username": "new.employee",
            "email": "new.employee@example.com",
            "first_name": "New",
            "last_name": "Employee",
            "department_id": 1,
            "temporary_password": "TemporaryPass123!",
        },
    )

    assert response.status_code == 403


def test_create_user_rejects_missing_required_fields():
    use_it_admin()

    response = client.post(
        "/api/admin/users",
        json={
            "username": "new.employee",
            "email": "new.employee@example.com",
            "first_name": "New",
            "last_name": "Employee",
            "department_id": 1,
            # temporary_password intentionally omitted
        },
    )

    assert response.status_code == 422


def test_get_user_returns_404_when_user_does_not_exist():
    use_it_admin()
    app.dependency_overrides[get_db] = lambda: EmptyDatabaseSession()

    response = client.get("/api/admin/users/999999")

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"


def test_update_user_returns_404_when_user_does_not_exist():
    use_it_admin()
    app.dependency_overrides[get_db] = lambda: EmptyDatabaseSession()

    response = client.put(
        "/api/admin/users/999999",
        json={"first_name": "Updated"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"
