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

    def options(self, *args, **kwargs):
        return self

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self.result


class FakeUpdateSession:
    """In-memory session stub for employee-update tests."""

    def __init__(self, employee, *, new_department=None, flush_error=None):
        self.employee = employee
        self.new_department = new_department
        self.flush_error = flush_error
        self.rollback_called = False
        self.commit_called = False
        self.flush_called = False

    def query(self, model):
        if model is User:
            return FakeQuery(self.employee)
        if model is Department:
            return FakeQuery(self.new_department)
        return FakeQuery(None)

    def flush(self):
        self.flush_called = True
        if self.flush_error:
            raise self.flush_error

    def commit(self):
        self.commit_called = True

    def rollback(self):
        self.rollback_called = True


@pytest.fixture(autouse=True)
def reset_app_overrides():
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def make_employee():
    old_department = SimpleNamespace(id=1, name="IT")
    return SimpleNamespace(
        id=25,
        keycloak_id="employee-keycloak-id",
        username="existing.employee",
        email="existing.employee@example.com",
        full_name="Existing Employee",
        department_id=1,
        department=old_department,
        is_active=True,
    )


def configure_admin_and_session(session):
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "test-it-admin-id",
        "preferred_username": "test.admin",
        "realm_access": {"roles": ["IT_ADMIN"]},
    }
    app.dependency_overrides[get_db] = lambda: session


def update_payload(**overrides):
    payload = {"first_name": "Updated"}
    payload.update(overrides)
    return payload


def test_keycloak_profile_update_failure_returns_500(monkeypatch):
    employee = make_employee()
    session = FakeUpdateSession(employee)
    configure_admin_and_session(session)

    def fail_profile_update(**kwargs):
        raise RuntimeError("Keycloak unavailable")

    monkeypatch.setattr(
        "app.main.update_keycloak_user",
        fail_profile_update,
    )

    response = client.put(
        f"/api/admin/users/{employee.id}",
        json=update_payload(),
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Unable to update employee"
    assert session.rollback_called
    assert not session.commit_called
    assert employee.full_name == "Existing Employee"


def test_department_transfer_failure_restores_keycloak_profile(monkeypatch):
    employee = make_employee()
    new_department = SimpleNamespace(id=2, name="SECURITY")
    session = FakeUpdateSession(employee, new_department=new_department)
    configure_admin_and_session(session)

    profile_updates = []
    department_moves = []

    monkeypatch.setattr(
        "app.main.update_keycloak_user",
        lambda **kwargs: profile_updates.append(kwargs),
    )

    def fail_department_move(**kwargs):
        department_moves.append(kwargs)
        raise RuntimeError("Department transfer failed")

    monkeypatch.setattr(
        "app.main.move_user_to_department",
        fail_department_move,
    )

    response = client.put(
        f"/api/admin/users/{employee.id}",
        json=update_payload(department_id=2),
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Unable to update employee"
    assert len(profile_updates) == 2
    assert profile_updates[0]["first_name"] == "Updated"
    assert profile_updates[1]["first_name"] == "Existing"
    assert profile_updates[1]["last_name"] == "Employee"
    assert department_moves == [{
        "user_id": "employee-keycloak-id",
        "old_department": "IT",
        "new_department": "SECURITY",
    }]
    assert session.rollback_called
    assert not session.commit_called


def test_database_flush_failure_restores_keycloak_profile(monkeypatch):
    employee = make_employee()
    session = FakeUpdateSession(
        employee,
        flush_error=RuntimeError("Database flush failed"),
    )
    configure_admin_and_session(session)

    profile_updates = []

    monkeypatch.setattr(
        "app.main.update_keycloak_user",
        lambda **kwargs: profile_updates.append(kwargs),
    )

    response = client.put(
        f"/api/admin/users/{employee.id}",
        json=update_payload(),
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Unable to update employee"
    assert len(profile_updates) == 2
    assert profile_updates[1]["email"] == "existing.employee@example.com"
    assert profile_updates[1]["first_name"] == "Existing"
    assert profile_updates[1]["last_name"] == "Employee"
    assert session.rollback_called
    assert not session.commit_called


def test_database_failure_reverses_department_and_profile_changes(
    monkeypatch,
):
    employee = make_employee()
    new_department = SimpleNamespace(id=2, name="SECURITY")
    session = FakeUpdateSession(
        employee,
        new_department=new_department,
        flush_error=RuntimeError("Database flush failed"),
    )
    configure_admin_and_session(session)

    profile_updates = []
    department_moves = []

    monkeypatch.setattr(
        "app.main.update_keycloak_user",
        lambda **kwargs: profile_updates.append(kwargs),
    )
    monkeypatch.setattr(
        "app.main.move_user_to_department",
        lambda **kwargs: department_moves.append(kwargs),
    )

    response = client.put(
        f"/api/admin/users/{employee.id}",
        json=update_payload(department_id=2),
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Unable to update employee"
    assert len(profile_updates) == 2
    assert len(department_moves) == 2
    assert department_moves[0]["old_department"] == "IT"
    assert department_moves[0]["new_department"] == "SECURITY"
    assert department_moves[1]["old_department"] == "SECURITY"
    assert department_moves[1]["new_department"] == "IT"
    assert session.rollback_called
    assert not session.commit_called


def test_profile_compensation_failure_requires_admin_investigation(
    monkeypatch,
):
    employee = make_employee()
    session = FakeUpdateSession(
        employee,
        flush_error=RuntimeError("Database flush failed"),
    )
    configure_admin_and_session(session)

    update_attempts = []

    def fail_on_compensation(**kwargs):
        update_attempts.append(kwargs)
        if len(update_attempts) == 2:
            raise RuntimeError("Keycloak profile restoration failed")

    monkeypatch.setattr(
        "app.main.update_keycloak_user",
        fail_on_compensation,
    )

    response = client.put(
        f"/api/admin/users/{employee.id}",
        json=update_payload(),
    )

    assert response.status_code == 500
    assert response.json()["detail"] == (
        "Update failed. Keycloak compensation could not be confirmed for: "
        "profile. Administrator investigation required."
    )
    assert len(update_attempts) == 2
    assert session.rollback_called
    assert not session.commit_called
