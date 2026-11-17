from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DepartmentResponse(BaseModel):
    id: int
    name: str
    description: str | None = None

    model_config = ConfigDict(from_attributes=True)


class UserResponse(BaseModel):
    id: int
    keycloak_id: str
    username: str
    email: str | None = None
    full_name: str | None = None
    department: DepartmentResponse | None = None
    is_active: bool

    model_config = ConfigDict(from_attributes=True)




class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: str = Field(max_length=255)
    first_name: str = Field(min_length=1, max_length=75)
    last_name: str = Field(min_length=1, max_length=75)

    department_id: int = Field(gt=0)

    temporary_password: str = Field(
        min_length=12,
        max_length=128,
    )


class UserUpdate(BaseModel):
    email: str | None = Field(
        default=None,
        max_length=255,
    )

    first_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=75,
    )

    last_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=75,
    )

    department_id: int | None = Field(
        default=None,
        gt=0,
    )

    is_active: bool | None = None


class AuditLogResponse(BaseModel):
    id: int
    user_id: int | None = None
    username: str
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    outcome: str
    details: dict[str, Any] | None = None
    source_ip: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


from typing import Literal


PolicyCategory = Literal[
    "IAM",
    "PASSWORD",
    "ACCESS_CONTROL",
    "NETWORK",
    "DATA_PROTECTION",
]

PolicySeverity = Literal[
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]


class SecurityPolicyCreate(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(min_length=10, max_length=2000)
    category: PolicyCategory
    severity: PolicySeverity = "MEDIUM"
    is_enabled: bool = True


class SecurityPolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=120)
    description: str | None = Field(default=None, min_length=10, max_length=2000)
    category: PolicyCategory | None = None
    severity: PolicySeverity | None = None
    is_enabled: bool | None = None


class SecurityPolicyResponse(BaseModel):
    id: int
    name: str
    description: str
    category: str
    severity: str
    is_enabled: bool
    created_by: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Risk Assessment
RiskCategory = Literal[
    "IAM",
    "NETWORK",
    "ENDPOINT",
    "APPLICATION",
    "DATA_PROTECTION",
    "CLOUD_INFRASTRUCTURE",
]

RiskStatus = Literal[
    "OPEN",
    "IN_PROGRESS",
    "MITIGATED",
    "ACCEPTED",
]


class RiskAssessmentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=150)
    description: str = Field(min_length=10, max_length=4000)
    asset: str = Field(min_length=2, max_length=150)
    category: RiskCategory
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    status: RiskStatus = "OPEN"
    mitigation_plan: str | None = Field(default=None, max_length=4000)
    owner: str | None = Field(default=None, max_length=100)


class RiskAssessmentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=150)
    description: str | None = Field(default=None, min_length=10, max_length=4000)
    asset: str | None = Field(default=None, min_length=2, max_length=150)
    category: RiskCategory | None = None
    likelihood: int | None = Field(default=None, ge=1, le=5)
    impact: int | None = Field(default=None, ge=1, le=5)
    status: RiskStatus | None = None
    mitigation_plan: str | None = Field(default=None, max_length=4000)
    owner: str | None = Field(default=None, max_length=100)


class RiskAssessmentResponse(BaseModel):
    id: int
    title: str
    description: str
    asset: str
    category: str
    likelihood: int
    impact: int
    risk_score: int
    severity: str
    status: str
    mitigation_plan: str | None = None
    owner: str | None = None
    created_by: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
