from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.database import get_db
from app.main import app
from app.models import Department, User
from app.security import verify_token


client = TestClient(app)


class FakeQuery:
    def __init__(self, result):
        self.result = result

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self.result


class FakeDatabaseSession:
    """In-memory session stub; no real database is contacted."""

    def __init__(self, *, flush_error=None):
        self.flush_error = flush_error
        self.query_counts = {}
        self.added = []
        self.rollback_called = False
        self.commit_called = False

    def query(self, model):
        count = self.query_counts.get(model, 0)
        self.query_counts[model] = count + 1

        if model is Department:
            result = SimpleNamespace(id=1, name="IT")
        elif model is User:
            # First query checks for an existing username/email.
            # Second query looks up the acting administrator for the audit row.
            result = None
        else:
            result = None

        return FakeQuery(result)

    def add(self, record):
        self.added.append(record)

    def flush(self):
        if self.flush_error:
            raise self.flush_error

    def commit(self):
        self.commit_called = True

    def refresh(self, record):
        # Simulate a generated database ID for the response schema.
        record.id = 101

    def rollback(self):
        self.rollback_called = True


@pytest.fixture(autouse=True)
def reset_overrides():
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def configure_admin_and_db(session):
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "test-it-admin-id",
        "preferred_username": "test.admin",
        "realm_access": {"roles": ["IT_ADMIN"]},
    }
    app.dependency_overrides[get_db] = lambda: session


def create_payload():
    return {
        "username": "rollback.test",
        "email": "rollback.test@example.com",
        "first_name": "Rollback",
        "last_name": "Test",
        "department_id": 1,
        "temporary_password": "TemporaryPass123!",
    }


def test_keycloak_creation_failure_returns_500_and_does_not_attempt_delete(
    monkeypatch,
):
    session = FakeDatabaseSession()
    configure_admin_and_db(session)
    deleted_users = []

    def fail_create_user(**kwargs):
        raise RuntimeError("Keycloak unavailable")

    monkeypatch.setattr("app.main.create_keycloak_user", fail_create_user)
    monkeypatch.setattr(
        "app.main.delete_keycloak_user",
        lambda user_id: deleted_users.append(user_id),
    )

    response = client.post("/api/admin/users", json=create_payload())

    assert response.status_code == 500
    assert response.json()["detail"] == "Unable to create user"
    assert session.rollback_called
    assert deleted_users == []


def test_department_assignment_failure_rolls_back_keycloak_user(monkeypatch):
    session = FakeDatabaseSession()
    configure_admin_and_db(session)
    deleted_users = []

    monkeypatch.setattr(
        "app.main.create_keycloak_user",
        lambda **kwargs: "created-keycloak-id",
    )

    def fail_assignment(**kwargs):
        raise RuntimeError("Keycloak group assignment failed")

    monkeypatch.setattr(
        "app.main.assign_user_to_department",
        fail_assignment,
    )
    monkeypatch.setattr(
        "app.main.delete_keycloak_user",
        lambda user_id: deleted_users.append(user_id),
    )

    response = client.post("/api/admin/users", json=create_payload())

    assert response.status_code == 500
    assert response.json()["detail"] == "Unable to create user"
    assert session.rollback_called
    assert deleted_users == ["created-keycloak-id"]


def test_database_flush_failure_rolls_back_keycloak_user(monkeypatch):
    session = FakeDatabaseSession(flush_error=RuntimeError("database flush failed"))
    configure_admin_and_db(session)
    deleted_users = []

    monkeypatch.setattr(
        "app.main.create_keycloak_user",
        lambda **kwargs: "created-keycloak-id",
    )
    monkeypatch.setattr(
        "app.main.assign_user_to_department",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "app.main.delete_keycloak_user",
        lambda user_id: deleted_users.append(user_id),
    )

    response = client.post("/api/admin/users", json=create_payload())

    assert response.status_code == 500
    assert response.json()["detail"] == "Unable to create user"
    assert session.rollback_called
    assert deleted_users == ["created-keycloak-id"]
    assert not session.commit_called


def test_keycloak_rollback_failure_returns_admin_investigation_error(
    monkeypatch,
):
    session = FakeDatabaseSession(flush_error=RuntimeError("database flush failed"))
    configure_admin_and_db(session)

    monkeypatch.setattr(
        "app.main.create_keycloak_user",
        lambda **kwargs: "created-keycloak-id",
    )
    monkeypatch.setattr(
        "app.main.assign_user_to_department",
        lambda **kwargs: None,
    )

    def fail_delete(user_id):
        raise RuntimeError("Keycloak deletion failed")

    monkeypatch.setattr("app.main.delete_keycloak_user", fail_delete)

    response = client.post("/api/admin/users", json=create_payload())

    assert response.status_code == 500
    assert response.json()["detail"] == (
        "Account creation failed and automatic Keycloak rollback could not "
        "be confirmed. Administrator investigation is required."
    )
    assert session.rollback_called


def test_value_error_after_keycloak_creation_rolls_back_identity(monkeypatch):
    session = FakeDatabaseSession()
    configure_admin_and_db(session)

    deleted_users = []

    monkeypatch.setattr(
        "app.main.create_keycloak_user",
        lambda **kwargs: "created-keycloak-id",
    )

    def raise_value_error(**kwargs):
        raise ValueError(
            "A user with this username or email already exists"
        )

    monkeypatch.setattr(
        "app.main.assign_user_to_department",
        raise_value_error,
    )

    monkeypatch.setattr(
        "app.main.delete_keycloak_user",
        lambda user_id: deleted_users.append(user_id),
    )

    response = client.post(
        "/api/admin/users",
        json=create_payload(),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "A user with this username or email already exists"
    )
    assert session.rollback_called
    assert deleted_users == ["created-keycloak-id"]
