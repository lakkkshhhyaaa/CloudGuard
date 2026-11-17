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

    def options(self, *args, **kwargs):
        return self

    def first(self):
        return self.result


class FakeDatabaseSession:
    """Small query stub for validation paths; it never touches PostgreSQL."""

    def __init__(self, results_by_model):
        self.results_by_model = results_by_model
        self.query_counts = {}

    def query(self, model):
        count = self.query_counts.get(model, 0)
        self.query_counts[model] = count + 1
        results = self.results_by_model.get(model, [])
        result = results[count] if count < len(results) else None
        return FakeQuery(result)

    def rollback(self):
        pass


@pytest.fixture(autouse=True)
def reset_app_overrides():
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def use_it_admin():
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "test-it-admin-id",
        "preferred_username": "test.admin",
        "realm_access": {"roles": ["IT_ADMIN"]},
    }


def use_fake_db(session):
    app.dependency_overrides[get_db] = lambda: session


def valid_create_payload(**overrides):
    payload = {
        "username": "new.employee",
        "email": "new.employee@example.com",
        "first_name": "New",
        "last_name": "Employee",
        "department_id": 1,
        "temporary_password": "TemporaryPass123!",
    }
    payload.update(overrides)
    return payload


def make_existing_employee():
    department = SimpleNamespace(id=1, name="IT")
    return SimpleNamespace(
        id=25,
        keycloak_id="test-keycloak-user-id",
        username="existing.employee",
        email="existing.employee@example.com",
        full_name="Existing Employee",
        department_id=1,
        department=department,
        is_active=True,
    )


def test_create_user_rejects_duplicate_username_or_email():
    use_it_admin()
    existing_user = SimpleNamespace(
        id=10,
        username="new.employee",
        email="new.employee@example.com",
    )
    session = FakeDatabaseSession({
        Department: [SimpleNamespace(id=1, name="IT")],
        User: [existing_user],
    })
    use_fake_db(session)

    response = client.post(
        "/api/admin/users",
        json=valid_create_payload(),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Username or email already exists"


def test_create_user_rejects_unknown_department():
    use_it_admin()
    session = FakeDatabaseSession({Department: [None]})
    use_fake_db(session)

    response = client.post(
        "/api/admin/users",
        json=valid_create_payload(department_id=999999),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Department not found"


def test_update_user_rejects_empty_update():
    use_it_admin()
    employee = make_existing_employee()
    session = FakeDatabaseSession({User: [employee]})
    use_fake_db(session)

    response = client.put(
        f"/api/admin/users/{employee.id}",
        json={},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "No update fields provided"


def test_update_user_rejects_explicit_null_field():
    use_it_admin()
    employee = make_existing_employee()
    session = FakeDatabaseSession({User: [employee]})
    use_fake_db(session)

    response = client.put(
        f"/api/admin/users/{employee.id}",
        json={"email": None},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "email cannot be null"


def test_update_user_rejects_duplicate_email():
    use_it_admin()
    employee = make_existing_employee()
    another_user = SimpleNamespace(
        id=26,
        username="another.employee",
        email="taken@example.com",
    )
    session = FakeDatabaseSession({
        User: [employee, another_user],
    })
    use_fake_db(session)

    response = client.put(
        f"/api/admin/users/{employee.id}",
        json={"email": "taken@example.com"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Email already belongs to another user"
