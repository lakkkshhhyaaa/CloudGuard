import pytest
from fastapi.testclient import TestClient

from app.database import get_db
from app.main import app
from app.security import verify_token


client = TestClient(app)


class FakeQuery:
    """Query stub for RBAC tests; no database connection is used."""

    def options(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def offset(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def all(self):
        return []

    def first(self):
        return None


class FakeDatabaseSession:
    def query(self, *args, **kwargs):
        return FakeQuery()


@pytest.fixture(autouse=True)
def reset_app_overrides(monkeypatch):
    app.dependency_overrides.clear()

    # Keep authorization-denial tests isolated from the development database.
    audit_events = []
    monkeypatch.setattr(
        "app.authorization.record_audit_event",
        lambda **kwargs: audit_events.append(kwargs) or True,
    )

    yield audit_events
    app.dependency_overrides.clear()


def authenticate_as(role_names):
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "rbac-test-user-id",
        "preferred_username": "rbac.test",
        "realm_access": {"roles": list(role_names)},
    }
    app.dependency_overrides[get_db] = lambda: FakeDatabaseSession()


# Each entry represents a real role-protected GET route in app/main.py.
ROUTE_ACCESS_CASES = [
    ("/api/admin/users", ("IT_ADMIN",)),
    ("/api/security/policies", ("IT_ADMIN", "SECURITY_ANALYST")),
    ("/api/security/events", ("IT_ADMIN", "SECURITY_ANALYST")),
    ("/api/security/risks", ("IT_ADMIN", "SECURITY_ANALYST")),
    ("/api/hr/dashboard", ("HR_MANAGER",)),
    ("/api/finance/dashboard", ("FINANCE_ANALYST",)),
]


@pytest.mark.parametrize(
    ("endpoint", "allowed_roles"),
    ROUTE_ACCESS_CASES,
)
def test_each_authorized_role_can_access_protected_endpoint(
    endpoint,
    allowed_roles,
):
    for role in allowed_roles:
        authenticate_as([role])
        response = client.get(endpoint)
        assert response.status_code == 200


@pytest.mark.parametrize(
    ("endpoint", "allowed_roles"),
    ROUTE_ACCESS_CASES,
)
@pytest.mark.parametrize(
    "unauthorized_role",
    ["IT_ADMIN", "SECURITY_ANALYST", "HR_MANAGER", "FINANCE_ANALYST"],
)
def test_other_application_roles_are_denied(
    endpoint,
    allowed_roles,
    unauthorized_role,
    reset_app_overrides,
):
    # Skip combinations where the role is actually authorized for this route.
    if unauthorized_role in allowed_roles:
        pytest.skip("This role is authorized for this endpoint")

    authenticate_as([unauthorized_role])

    response = client.get(endpoint)

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "You do not have permission to access this resource"
    )

    assert reset_app_overrides
    denial = reset_app_overrides[-1]
    assert denial["action"] == "AUTHORIZATION_DENIED"
    assert denial["outcome"] == "DENIED"
    assert denial["resource_id"] == endpoint
    assert denial["details"]["required_roles"] == list(allowed_roles)


@pytest.mark.parametrize(
    "roles",
    [
        [],
        ["offline_access", "uma_authorization"],
        ["NOT_A_CLOUDGUARD_ROLE"],
    ],
)
def test_user_without_cloudguard_application_role_is_denied(
    roles,
    reset_app_overrides,
):
    authenticate_as(roles)

    response = client.get("/api/hr/dashboard")

    assert response.status_code == 403
    assert reset_app_overrides
    assert reset_app_overrides[-1]["action"] == "AUTHORIZATION_DENIED"
    assert reset_app_overrides[-1]["details"]["user_roles"] == []


def test_user_with_multiple_roles_is_allowed_when_one_role_matches():
    authenticate_as(["HR_MANAGER", "SECURITY_ANALYST"])

    response = client.get("/api/security/policies")

    assert response.status_code == 200


def test_unprotected_health_endpoint_does_not_require_a_token():
    app.dependency_overrides.pop(verify_token, None)

    response = client.get("/health")

    assert response.status_code == 200
