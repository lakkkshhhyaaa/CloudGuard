from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.database import get_db
from app.main import app
from app.models.risk_assessment import RiskAssessment
from app.security import verify_token


client = TestClient(app)


def make_risk(**overrides):
    values = {
        "id": 7,
        "title": "Unpatched Server Vulnerability",
        "description": "An unpatched production server may allow unauthorized access.",
        "asset": "Production Linux Server",
        "category": "CLOUD_INFRASTRUCTURE",
        "likelihood": 4,
        "impact": 4,
        "risk_score": 16,
        "severity": "HIGH",
        "status": "OPEN",
        "mitigation_plan": "Apply patches and scan for vulnerabilities.",
        "owner": "Infrastructure Team",
        "created_by": "risk.test",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class FakeQuery:
    def __init__(self, records):
        self.records = records

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def all(self):
        return list(self.records)

    def first(self):
        return self.records[0] if self.records else None


class FakeDatabaseSession:
    """In-memory database stub; these tests never contact PostgreSQL."""

    def __init__(self, records=None):
        self.records = list(records or [])
        self.added = []
        self.deleted = []
        self.commit_called = False
        self.rollback_called = False

    def query(self, model):
        assert model is RiskAssessment
        return FakeQuery(self.records)

    def add(self, record):
        self.added.append(record)
        record.id = 8
        now = datetime.now(timezone.utc)
        record.created_at = now
        record.updated_at = now
        self.records.append(record)

    def commit(self):
        self.commit_called = True

    def refresh(self, record):
        return None

    def delete(self, record):
        self.deleted.append(record)
        if record in self.records:
            self.records.remove(record)

    def rollback(self):
        self.rollback_called = True


@pytest.fixture(autouse=True)
def reset_overrides(monkeypatch):
    app.dependency_overrides.clear()
    audit_events = []

    # Keep test audit events in memory; never write to the development DB.
    monkeypatch.setattr(
        "app.main.record_audit_event",
        lambda **kwargs: audit_events.append(kwargs) or True,
    )
    monkeypatch.setattr(
        "app.authorization.record_audit_event",
        lambda **kwargs: audit_events.append(kwargs) or True,
    )

    yield audit_events
    app.dependency_overrides.clear()


def authenticate_as(role="SECURITY_ANALYST"):
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "risk-test-user-id",
        "preferred_username": "risk.test",
        "realm_access": {"roles": [role]},
    }


def use_fake_db(session):
    app.dependency_overrides[get_db] = lambda: session


def valid_create_payload(**overrides):
    payload = {
        "title": "Unpatched Server Vulnerability",
        "description": (
            "An unpatched production server may allow unauthorized access."
        ),
        "asset": "Production Linux Server",
        "category": "CLOUD_INFRASTRUCTURE",
        "likelihood": 4,
        "impact": 4,
        "status": "OPEN",
        "mitigation_plan": "Apply patches and scan for vulnerabilities.",
        "owner": "Infrastructure Team",
    }
    payload.update(overrides)
    return payload


def test_list_risks_returns_database_records():
    authenticate_as()
    risk = make_risk()
    session = FakeDatabaseSession([risk])
    use_fake_db(session)

    response = client.get("/api/security/risks")

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["id"] == risk.id
    assert response.json()[0]["risk_score"] == 16
    assert response.json()[0]["severity"] == "HIGH"


def test_create_risk_calculates_score_severity_and_audits(reset_overrides):
    authenticate_as()
    session = FakeDatabaseSession()
    use_fake_db(session)

    response = client.post(
        "/api/security/risks",
        json=valid_create_payload(),
    )

    assert response.status_code == 201
    data = response.json()
    assert data["id"] == 8
    assert data["risk_score"] == 16
    assert data["severity"] == "HIGH"
    assert data["created_by"] == "risk.test"
    assert session.commit_called
    assert not session.rollback_called

    event = reset_overrides[-1]
    assert event["action"] == "CREATE_RISK_ASSESSMENT"
    assert event["outcome"] == "SUCCESS"
    assert event["resource_type"] == "RISK_ASSESSMENT"
    assert event["resource_id"] == "8"


@pytest.mark.parametrize(
    ("likelihood", "impact", "expected_score", "expected_severity"),
    [
        (1, 1, 1, "LOW"),
        (2, 2, 4, "LOW"),
        (2, 5, 10, "HIGH"),
        (3, 3, 9, "MEDIUM"),
        (4, 4, 16, "HIGH"),
        (5, 5, 25, "CRITICAL"),
    ],
)
def test_create_risk_uses_correct_severity_band(
    likelihood,
    impact,
    expected_score,
    expected_severity,
):
    authenticate_as()
    session = FakeDatabaseSession()
    use_fake_db(session)

    response = client.post(
        "/api/security/risks",
        json=valid_create_payload(
            likelihood=likelihood,
            impact=impact,
        ),
    )

    assert response.status_code == 201
    assert response.json()["risk_score"] == expected_score
    assert response.json()["severity"] == expected_severity


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("likelihood", 0),
        ("likelihood", 6),
        ("impact", 0),
        ("impact", 6),
        ("category", "UNKNOWN_CATEGORY"),
        ("status", "UNKNOWN_STATUS"),
    ],
)
def test_create_risk_rejects_invalid_input(field, value):
    authenticate_as()
    session = FakeDatabaseSession()
    use_fake_db(session)

    response = client.post(
        "/api/security/risks",
        json=valid_create_payload(**{field: value}),
    )

    assert response.status_code == 422
    assert not session.added
    assert not session.commit_called


def test_update_risk_recalculates_score_and_severity(reset_overrides):
    authenticate_as()
    risk = make_risk()
    session = FakeDatabaseSession([risk])
    use_fake_db(session)

    response = client.put(
        f"/api/security/risks/{risk.id}",
        json={"likelihood": 3, "impact": 4, "status": "IN_PROGRESS"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["likelihood"] == 3
    assert data["impact"] == 4
    assert data["risk_score"] == 12
    assert data["severity"] == "HIGH"
    assert data["status"] == "IN_PROGRESS"
    assert session.commit_called

    event = reset_overrides[-1]
    assert event["action"] == "UPDATE_RISK_ASSESSMENT"
    assert event["outcome"] == "SUCCESS"
    assert event["resource_id"] == str(risk.id)
    assert event["details"]["changed_fields"] == [
        "impact",
        "likelihood",
        "status",
    ]


def test_update_risk_rejects_empty_update():
    authenticate_as()
    risk = make_risk()
    session = FakeDatabaseSession([risk])
    use_fake_db(session)

    response = client.put(f"/api/security/risks/{risk.id}", json={})

    assert response.status_code == 400
    assert response.json()["detail"] == "No update fields provided"
    assert not session.commit_called


def test_update_risk_rejects_null_non_nullable_field():
    authenticate_as()
    risk = make_risk()
    session = FakeDatabaseSession([risk])
    use_fake_db(session)

    response = client.put(
        f"/api/security/risks/{risk.id}",
        json={"title": None},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "title cannot be null"
    assert not session.commit_called


@pytest.mark.parametrize("method", ["put", "delete"])
def test_risk_mutations_return_404_for_missing_record(method):
    authenticate_as()
    session = FakeDatabaseSession()
    use_fake_db(session)

    if method == "put":
        response = client.put(
            "/api/security/risks/999999",
            json={"title": "Updated risk"},
        )
    else:
        response = client.delete("/api/security/risks/999999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Risk assessment not found"


def test_delete_risk_removes_record_and_audits(reset_overrides):
    authenticate_as()
    risk = make_risk()
    session = FakeDatabaseSession([risk])
    use_fake_db(session)

    response = client.delete(f"/api/security/risks/{risk.id}")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Risk assessment deleted successfully",
        "risk_id": risk.id,
    }
    assert risk in session.deleted
    assert risk not in session.records
    assert session.commit_called

    event = reset_overrides[-1]
    assert event["action"] == "DELETE_RISK_ASSESSMENT"
    assert event["outcome"] == "SUCCESS"
    assert event["resource_id"] == str(risk.id)


def test_finance_role_cannot_access_risk_register(reset_overrides):
    authenticate_as("FINANCE_ANALYST")
    session = FakeDatabaseSession()
    use_fake_db(session)

    response = client.get("/api/security/risks")

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "You do not have permission to access this resource"
    )
    assert reset_overrides
    denial = reset_overrides[-1]
    assert denial["action"] == "AUTHORIZATION_DENIED"
    assert denial["outcome"] == "DENIED"
    assert denial["resource_id"] == "/api/security/risks"
    assert denial["details"]["required_roles"] == [
        "IT_ADMIN",
        "SECURITY_ANALYST",
    ]
