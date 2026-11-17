import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import authorization


@pytest.fixture
def mock_request():
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/api/hr/dashboard",
        "raw_path": b"/api/hr/dashboard",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    return Request(scope)


@pytest.fixture
def audit_events(monkeypatch):
    events = []

    def fake_audit(**kwargs):
        events.append(kwargs)
        return True

    monkeypatch.setattr(authorization, "record_audit_event", fake_audit)
    return events


def make_user(roles):
    return {
        "sub": "authorization-test-user",
        "preferred_username": "authorization.test",
        "realm_access": {"roles": roles},
    }


def test_authorized_cloudguard_role_is_allowed(mock_request, audit_events):
    user = make_user(["HR_MANAGER"])
    checker = authorization.require_roles("HR_MANAGER")

    result = checker(mock_request, user)

    assert result is user
    assert audit_events == []


def test_user_with_one_matching_role_is_allowed(mock_request, audit_events):
    user = make_user(["FINANCE_ANALYST", "SECURITY_ANALYST"])
    checker = authorization.require_roles("SECURITY_ANALYST", "IT_ADMIN")

    assert checker(mock_request, user) is user
    assert audit_events == []


@pytest.mark.parametrize(
    "realm_access",
    [
        None,
        [],
        "not-a-dictionary",
        123,
        {},
        {"roles": None},
        {"roles": "IT_ADMIN"},
        {"roles": {"IT_ADMIN": True}},
    ],
)
def test_malformed_realm_access_is_denied(
    mock_request,
    audit_events,
    realm_access,
):
    user = {
        "sub": "authorization-test-user",
        "preferred_username": "authorization.test",
        "realm_access": realm_access,
    }
    checker = authorization.require_roles("IT_ADMIN")

    with pytest.raises(HTTPException) as exc:
        checker(mock_request, user)

    assert exc.value.status_code == 403
    assert audit_events[-1]["action"] == "AUTHORIZATION_DENIED"
    assert audit_events[-1]["details"]["user_roles"] == []


def test_non_string_role_entries_are_ignored(
    mock_request,
    audit_events,
):
    user = make_user(["HR_MANAGER", {}, ["IT_ADMIN"], 123, None])
    checker = authorization.require_roles("IT_ADMIN")

    with pytest.raises(HTTPException) as exc:
        checker(mock_request, user)

    assert exc.value.status_code == 403
    assert audit_events[-1]["details"]["user_roles"] == ["HR_MANAGER"]


def test_valid_role_is_not_blocked_by_unrelated_malformed_entries(
    mock_request,
    audit_events,
):
    user = make_user(["SECURITY_ANALYST", {}, 123, None])
    checker = authorization.require_roles("SECURITY_ANALYST")

    assert checker(mock_request, user) is user
    assert audit_events == []


def test_non_cloudguard_roles_do_not_grant_access(
    mock_request,
    audit_events,
):
    user = make_user(["offline_access", "uma_authorization"])
    checker = authorization.require_roles("HR_MANAGER")

    with pytest.raises(HTTPException) as exc:
        checker(mock_request, user)

    assert exc.value.status_code == 403
    assert audit_events[-1]["details"]["user_roles"] == []


def test_denial_is_audited_with_route_and_required_roles(
    mock_request,
    audit_events,
):
    user = make_user(["FINANCE_ANALYST"])
    checker = authorization.require_roles("HR_MANAGER", "IT_ADMIN")

    with pytest.raises(HTTPException):
        checker(mock_request, user)

    event = audit_events[-1]
    assert event["username"] == "authorization.test"
    assert event["action"] == "AUTHORIZATION_DENIED"
    assert event["outcome"] == "DENIED"
    assert event["resource_type"] == "API"
    assert event["resource_id"] == "/api/hr/dashboard"
    assert event["details"]["user_roles"] == ["FINANCE_ANALYST"]
    assert event["details"]["required_roles"] == ["HR_MANAGER", "IT_ADMIN"]
    assert event["details"]["method"] == "GET"
    assert event["keycloak_user_id"] == "authorization-test-user"


def test_audit_failure_does_not_bypass_authorization_denial(
    mock_request,
    monkeypatch,
):
    def failing_audit(**kwargs):
        raise RuntimeError("audit storage unavailable")

    monkeypatch.setattr(
        authorization,
        "record_audit_event",
        failing_audit,
    )
    checker = authorization.require_roles("IT_ADMIN")

    with pytest.raises(HTTPException) as exc:
        checker(mock_request, make_user(["HR_MANAGER"]))

    assert exc.value.status_code == 403


def test_missing_current_user_is_denied(mock_request, audit_events):
    checker = authorization.require_roles("IT_ADMIN")

    with pytest.raises(HTTPException) as exc:
        checker(mock_request, None)

    assert exc.value.status_code == 403
    assert audit_events[-1]["details"]["user_roles"] == []


def test_empty_allowed_roles_configuration_is_rejected():
    with pytest.raises(ValueError, match="At least one allowed"):
        authorization.require_roles()


@pytest.mark.parametrize(
    "invalid_roles",
    [
        ("SUPER_ADMIN",),
        ("it_admin",),
        (123,),
        (None,),
        (["IT_ADMIN"],),
    ],
)
def test_invalid_allowed_role_configuration_is_rejected(invalid_roles):
    with pytest.raises(ValueError, match="valid CloudGuard"):
        authorization.require_roles(*invalid_roles)


def test_duplicate_allowed_roles_are_normalized(
    mock_request,
    audit_events,
):
    user = make_user(["HR_MANAGER"])
    checker = authorization.require_roles("HR_MANAGER", "HR_MANAGER")

    assert checker(mock_request, user) is user
    assert audit_events == []
