
from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from app.security import verify_token
from app.audit import record_audit_event

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

import logging
import os

logger = logging.getLogger(__name__)

from app.authorization import require_roles
from app.models import User, Department, AuditLog, SecurityPolicy
from app.models.risk_assessment import RiskAssessment
from app.schemas import (
    UserResponse,
    UserCreate,
    UserUpdate,
    AuditLogResponse,
    SecurityPolicyCreate,
    SecurityPolicyUpdate,
    SecurityPolicyResponse,
    RiskAssessmentCreate,
    RiskAssessmentUpdate,
    RiskAssessmentResponse,
)
from app.keycloak_admin import (
    create_keycloak_user,
    assign_user_to_department,
    delete_keycloak_user,
    update_keycloak_user,
    move_user_to_department,
)
from app.database import get_db
from app.security import verify_token


# Initialize FastAPI application
app = FastAPI(
    title="CloudGuard API",
    description="Backend API for the CloudGuard Security and IAM Platform",
    version="1.0.0"
)


# Configure CORS from an explicit allowlist.
# Example:
# CLOUDGUARD_ALLOWED_ORIGINS=http://localhost:5173,https://your-frontend.example
_allowed_origins_raw = os.getenv(
    "CLOUDGUARD_ALLOWED_ORIGINS",
    "http://localhost:5173",
)
ALLOWED_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in _allowed_origins_raw.split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


# Limit incoming request bodies. The default is suitable for the current JSON
# API; raise it deliberately if future features need larger payloads.
MAX_REQUEST_BODY_BYTES = int(
    os.getenv("CLOUDGUARD_MAX_REQUEST_BODY_BYTES", str(1 * 1024 * 1024))
)


class RequestBodyTooLarge(Exception):
    """Raised when an incoming HTTP request exceeds the configured limit."""


class RequestSizeLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        if max_bytes < 1:
            raise ValueError("Request body limit must be at least 1 byte")
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                await self._reject(send)
                return
            if declared_length < 0 or declared_length > self.max_bytes:
                await self._reject(send)
                return

        received_bytes = 0

        async def limited_receive():
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > self.max_bytes:
                    raise RequestBodyTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await self._reject(send)

    @staticmethod
    async def _reject(send):
        body = b'{"detail":"Request body too large"}'
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        })


class SecurityHeadersMiddleware:
    def __init__(self, app, enable_hsts: bool = False):
        self.app = app
        self.enable_hsts = enable_hsts

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def add_security_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {key.lower() for key, _ in headers}
                security_headers = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                ]
                if self.enable_hsts:
                    security_headers.append((
                        b"strict-transport-security",
                        b"max-age=31536000; includeSubDomains",
                    ))
                for key, value in security_headers:
                    if key not in existing:
                        headers.append((key, value))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, add_security_headers)


# Add application-level HTTP protections.
app.add_middleware(
    RequestSizeLimitMiddleware,
    max_bytes=MAX_REQUEST_BODY_BYTES,
)
app.add_middleware(
    SecurityHeadersMiddleware,
    enable_hsts=os.getenv("CLOUDGUARD_ENABLE_HSTS", "false").lower() == "true",
)


# Root endpoint
@app.get("/")
def root():
    return {
        "message": "Welcome to CloudGuard API",
        "status": "online"
    }


# Health check endpoint
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "CloudGuard Backend"
    }


# Protected user identity endpoint
@app.get("/api/me")
def get_current_user(
    current_user: dict = Depends(verify_token)
):
    return {
        "message": "Authentication successful",
        "user_id": current_user.get("sub"),
        "username": current_user.get("preferred_username"),
        "email": current_user.get("email"),
        "roles": current_user.get("realm_access", {}).get("roles", [])
    }

# Record successful authentication sessions
@app.post("/api/auth/session")
def record_authentication_success(
    request: Request,
    current_user: dict = Depends(verify_token),
):
    recorded = record_audit_event(
        username=current_user.get(
            "preferred_username", "unknown"
        ),
        action="AUTHENTICATION_SUCCESS",
        outcome="SUCCESS",
        resource_type="AUTHENTICATION",
        resource_id="KEYCLOAK_SESSION",
        details={
            "authentication_method": "OIDC",
        },
        source_ip=(
            request.client.host if request.client else None
        ),
        keycloak_user_id=current_user.get("sub"),
    )

    return {
        "message": "Authentication session processed",
        "audit_recorded": recorded,
    }


# Record successful logout sessions
@app.post("/api/auth/logout")
def record_authentication_logout(
    request: Request,
    current_user: dict = Depends(verify_token),
):
    recorded = record_audit_event(
        username=current_user.get(
            "preferred_username", "unknown"
        ),
        action="AUTHENTICATION_LOGOUT",
        outcome="SUCCESS",
        resource_type="AUTHENTICATION",
        resource_id="KEYCLOAK_SESSION",
        details={
            "authentication_method": "OIDC",
        },
        source_ip=(
            request.client.host if request.client else None
        ),
        keycloak_user_id=current_user.get("sub"),
    )

    return {
        "message": "Logout event processed",
        "audit_recorded": recorded,
    }


# IT Administration
@app.get("/api/admin/users", response_model=list[UserResponse])
def admin_users(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles("IT_ADMIN")),
):
    users = (
        db.query(User)
        .options(joinedload(User.department))
        .order_by(User.id)
        .all()
    )

    return users


# Update an employee
@app.put("/api/admin/users/{user_id}", response_model=UserResponse)
def update_admin_user(
    user_id: int,
    user_data: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles("IT_ADMIN")),
):
    # 1. Find the employee.
    employee = (
        db.query(User)
        .options(joinedload(User.department))
        .filter(User.id == user_id)
        .first()
    )

    if employee is None:
        raise HTTPException(status_code=404, detail="User not found")

    # 2. Extract supplied fields.
    changes = user_data.model_dump(exclude_unset=True)

    if not changes:
        raise HTTPException(
            status_code=400,
            detail="No update fields provided",
        )

    # 3. Reject explicit null values.
    for field in (
        "email", "first_name", "last_name",
        "department_id", "is_active",
    ):
        if field in changes and changes[field] is None:
            raise HTTPException(
                status_code=422,
                detail=f"{field} cannot be null",
            )

    # 4. Validate the target department.
    new_department = employee.department

    if "department_id" in changes:
        new_department = (
            db.query(Department)
            .filter(Department.id == changes["department_id"])
            .first()
        )

        if new_department is None:
            raise HTTPException(
                status_code=404,
                detail="Department not found",
            )

    # 5. Check email uniqueness.
    new_email = changes.get("email", employee.email)

    if new_email != employee.email:
        duplicate = (
            db.query(User)
            .filter(
                User.email == new_email,
                User.id != employee.id,
            )
            .first()
        )

        if duplicate:
            raise HTTPException(
                status_code=409,
                detail="Email already belongs to another user",
            )

    # 6. Capture original values before external changes.
    employee_id = employee.id
    keycloak_id = employee.keycloak_id
    username = employee.username

    old_email = employee.email
    old_full_name = employee.full_name or ""
    old_department_id = employee.department_id
    old_department_name = employee.department.name
    old_is_active = employee.is_active

    old_name_parts = old_full_name.split(" ", 1)
    old_first_name = old_name_parts[0] if old_name_parts else ""
    old_last_name = (
        old_name_parts[1] if len(old_name_parts) > 1 else ""
    )

    first_name = changes.get("first_name", old_first_name)
    last_name = changes.get("last_name", old_last_name)

    new_full_name = f"{first_name} {last_name}".strip()
    new_department_name = new_department.name
    new_is_active = changes.get("is_active", old_is_active)

    department_changed = (
        new_department.id != old_department_id
    )

    # 7. Track external changes for compensation.
    keycloak_profile_updated = False
    department_moved = False

    try:
        # Update Keycloak profile.
        update_keycloak_user(
            user_id=keycloak_id,
            email=new_email,
            first_name=first_name,
            last_name=last_name,
            enabled=new_is_active,
        )
        keycloak_profile_updated = True

        # Move Keycloak department membership if required.
        if department_changed:
            move_user_to_department(
                user_id=keycloak_id,
                old_department=old_department_name,
                new_department=new_department_name,
            )
            department_moved = True

        # Update PostgreSQL.
        employee.email = new_email
        employee.full_name = new_full_name
        employee.department_id = new_department.id
        employee.is_active = new_is_active

        # Flush catches database constraint errors before commit.
        db.flush()

        # Commit is the final operation inside this try block.
        db.commit()

    except Exception as error:
        db.rollback()

        compensation_errors = []

        # Restore department membership if the transfer completed.
        if department_moved:
            try:
                move_user_to_department(
                    user_id=keycloak_id,
                    old_department=new_department_name,
                    new_department=old_department_name,
                )
            except Exception as rollback_error:
                logger.exception(
                    "Department rollback failed for employee ID %s",
                    employee_id,
                )
                compensation_errors.append("department")

        # Restore the original Keycloak profile.
        if keycloak_profile_updated:
            try:
                update_keycloak_user(
                    user_id=keycloak_id,
                    email=old_email,
                    first_name=old_first_name,
                    last_name=old_last_name,
                    enabled=old_is_active,
                )
            except Exception as rollback_error:
                logger.exception(
                    "Profile rollback failed for employee ID %s",
                    employee_id,
                )
                compensation_errors.append("profile")

        if compensation_errors:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Update failed. Keycloak compensation could not "
                    "be confirmed for: "
                    + ", ".join(compensation_errors)
                    + ". Administrator investigation required."
                ),
            ) from None

        if isinstance(error, IntegrityError):
            raise HTTPException(
                status_code=409,
                detail="Database constraint conflict during update",
            ) from None

        logger.exception(
            "Employee update failed for employee ID %s",
            employee_id,
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to update employee",
        ) from None

    # 8. Record successful update after the database commit.
    record_audit_event(
        username=current_user.get("preferred_username", "unknown"),
        action="UPDATE_USER",
        outcome="SUCCESS",
        resource_type="USER",
        resource_id=keycloak_id,
        details={
            "updated_username": username,
            "changed_fields": sorted(changes.keys()),
            "previous_department": old_department_name,
            "new_department": new_department_name,
        },
        source_ip=request.client.host if request.client else None,
        keycloak_user_id=current_user.get("sub"),
    )

    # 9. Return the committed values without refreshing the ORM object.
    return {
        "id": employee_id,
        "keycloak_id": keycloak_id,
        "username": username,
        "email": new_email,
        "full_name": new_full_name,
        "department": new_department,
        "is_active": new_is_active,
    }


@app.get("/api/admin/users/{user_id}", response_model=UserResponse)
def get_admin_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles("IT_ADMIN")),
):
    user_record = (
        db.query(User)
        .options(joinedload(User.department))
        .filter(User.id == user_id)
        .first()
    )

    if user_record is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return user_record


from fastapi import Request
from sqlalchemy.exc import IntegrityError


@app.post("/api/admin/users", response_model=UserResponse, status_code=201)
def create_admin_user(
    user_data: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles("IT_ADMIN")),
):
    # 1. Validate department.
    department = (
        db.query(Department)
        .filter(Department.id == user_data.department_id)
        .first()
    )

    if department is None:
        raise HTTPException(
            status_code=404,
            detail="Department not found",
        )

    # 2. Check for existing username or email in PostgreSQL.
    existing_user = db.query(User).filter(
        (User.username == user_data.username)
        | (User.email == user_data.email)
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Username or email already exists",
        )

    keycloak_user_id = None

    try:
        # 3. Create identity in Keycloak.
        keycloak_user_id = create_keycloak_user(
            username=user_data.username,
            email=user_data.email,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            temporary_password=user_data.temporary_password,
        )

        # 4. Assign department group and inherited role.
        assign_user_to_department(
            user_id=keycloak_user_id,
            department=department.name,
        )

        # 5. Prepare PostgreSQL user record.
        new_user = User(
            keycloak_id=keycloak_user_id,
            username=user_data.username,
            email=user_data.email,
            full_name=f"{user_data.first_name} {user_data.last_name}",
            department_id=department.id,
            is_active=True,
        )

        db.add(new_user)
        db.flush()

        # 6. Record successful account creation.
        actor = db.query(User).filter(
            User.keycloak_id == current_user.get("sub")
        ).first()

        audit_entry = AuditLog(
            user_id=actor.id if actor else None,
            username=current_user.get("preferred_username", "unknown"),
            action="CREATE_USER",
            resource_type="USER",
            resource_id=keycloak_user_id,
            outcome="SUCCESS",
            details={
                "created_username": user_data.username,
                "department": department.name,
            },
            source_ip=request.client.host if request.client else None,
        )

        db.add(audit_entry)

        # 7. Commit user and audit record together.
        db.commit()
        db.refresh(new_user)

        return new_user


    except ValueError as error:
        db.rollback()

        # Compensate if Keycloak identity was already created.
        if keycloak_user_id:
            try:
                delete_keycloak_user(keycloak_user_id)
            except Exception:
                logger.exception(
                    "Keycloak rollback failed after account creation error"
                )
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Account creation failed and automatic "
                        "Keycloak rollback could not be confirmed. "
                        "Administrator investigation is required."
                    ),
                ) from None

        raise HTTPException(
            status_code=409,
            detail=str(error),
        ) from None

    except Exception as error:
        db.rollback()

        # Compensate if Keycloak identity was already created.
        if keycloak_user_id:
            try:
                delete_keycloak_user(keycloak_user_id)
            except Exception:
                logger.exception(
                    "Keycloak rollback failed after account creation error"
                )
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Account creation failed and automatic "
                        "Keycloak rollback could not be confirmed. "
                        "Administrator investigation is required."
                    ),
                ) from None

        if isinstance(error, IntegrityError):
            raise HTTPException(
                status_code=409,
                detail="Username or email already exists",
            ) from None

        logger.exception("Account creation failed")

        raise HTTPException(
            status_code=500,
            detail="Unable to create user",
        ) from None


    except Exception as error:
        db.rollback()

        # 8. Compensate if Keycloak identity was already created.
        if keycloak_user_id:
            try:
                delete_keycloak_user(keycloak_user_id)
            except Exception:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Account creation failed and automatic "
                        "Keycloak rollback could not be confirmed. "
                        "Administrator investigation is required."
                    ),
                ) from None

        if isinstance(error, IntegrityError):
            raise HTTPException(
                status_code=409,
                detail="Username or email already exists",
            ) from None

        raise HTTPException(
            status_code=500,
            detail="Unable to create user",
        ) from None




# Security Policies — database-backed policy management
@app.get(
    "/api/security/policies",
    response_model=list[SecurityPolicyResponse],
)
def list_security_policies(
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("IT_ADMIN", "SECURITY_ANALYST")
    ),
):
    policies = (
        db.query(SecurityPolicy)
        .order_by(SecurityPolicy.created_at.desc(), SecurityPolicy.id.desc())
        .all()
    )
    return policies


@app.post(
    "/api/security/policies",
    response_model=SecurityPolicyResponse,
    status_code=201,
)
def create_security_policy(
    policy_data: SecurityPolicyCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("IT_ADMIN", "SECURITY_ANALYST")
    ),
):
    existing_policy = (
        db.query(SecurityPolicy)
        .filter(SecurityPolicy.name == policy_data.name)
        .first()
    )
    if existing_policy:
        raise HTTPException(
            status_code=409,
            detail="A security policy with this name already exists",
        )

    policy = SecurityPolicy(
        name=policy_data.name,
        description=policy_data.description,
        category=policy_data.category,
        severity=policy_data.severity,
        is_enabled=policy_data.is_enabled,
        created_by=current_user.get("preferred_username", "unknown"),
    )

    try:
        db.add(policy)
        db.commit()
        db.refresh(policy)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="A security policy with this name already exists",
        ) from None

    record_audit_event(
        username=current_user.get("preferred_username", "unknown"),
        action="CREATE_POLICY",
        outcome="SUCCESS",
        resource_type="SECURITY_POLICY",
        resource_id=str(policy.id),
        details={
            "policy_name": policy.name,
            "category": policy.category,
            "severity": policy.severity,
            "is_enabled": policy.is_enabled,
        },
        source_ip=request.client.host if request.client else None,
        keycloak_user_id=current_user.get("sub"),
    )

    return policy


@app.put(
    "/api/security/policies/{policy_id}",
    response_model=SecurityPolicyResponse,
)
def update_security_policy(
    policy_id: int,
    policy_data: SecurityPolicyUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("IT_ADMIN", "SECURITY_ANALYST")
    ),
):
    policy = (
        db.query(SecurityPolicy)
        .filter(SecurityPolicy.id == policy_id)
        .first()
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="Security policy not found")

    changes = policy_data.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(
            status_code=400,
            detail="No update fields provided",
        )

    for field, value in changes.items():
        if value is None:
            raise HTTPException(
                status_code=422,
                detail=f"{field} cannot be null",
            )

    if "name" in changes:
        duplicate = (
            db.query(SecurityPolicy)
            .filter(
                SecurityPolicy.name == changes["name"],
                SecurityPolicy.id != policy_id,
            )
            .first()
        )
        if duplicate:
            raise HTTPException(
                status_code=409,
                detail="A security policy with this name already exists",
            )

    changed_fields = sorted(changes.keys())
    for field, value in changes.items():
        setattr(policy, field, value)

    try:
        db.commit()
        db.refresh(policy)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="A security policy with this name already exists",
        ) from None

    record_audit_event(
        username=current_user.get("preferred_username", "unknown"),
        action="UPDATE_POLICY",
        outcome="SUCCESS",
        resource_type="SECURITY_POLICY",
        resource_id=str(policy.id),
        details={
            "policy_name": policy.name,
            "changed_fields": changed_fields,
        },
        source_ip=request.client.host if request.client else None,
        keycloak_user_id=current_user.get("sub"),
    )

    return policy


@app.delete("/api/security/policies/{policy_id}")
def delete_security_policy(
    policy_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("IT_ADMIN", "SECURITY_ANALYST")
    ),
):
    policy = (
        db.query(SecurityPolicy)
        .filter(SecurityPolicy.id == policy_id)
        .first()
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="Security policy not found")

    deleted_policy_name = policy.name
    db.delete(policy)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Unable to delete security policy",
        ) from None

    record_audit_event(
        username=current_user.get("preferred_username", "unknown"),
        action="DELETE_POLICY",
        outcome="SUCCESS",
        resource_type="SECURITY_POLICY",
        resource_id=str(policy_id),
        details={"policy_name": deleted_policy_name},
        source_ip=request.client.host if request.client else None,
        keycloak_user_id=current_user.get("sub"),
    )

    return {
        "message": "Security policy deleted successfully",
        "policy_id": policy_id,
    }


# Security Operations — database-backed audit event retrieval
@app.get(
    "/api/security/events",
    response_model=list[AuditLogResponse],
)
def security_events(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("IT_ADMIN", "SECURITY_ANALYST")
    ),
):
    events = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return events


# Human Resources
@app.get("/api/hr/dashboard")
def hr_dashboard(
    current_user: dict = Depends(require_roles("HR_MANAGER"))
):
    return {
        "message": "HR dashboard access granted",
        "username": current_user.get("preferred_username"),
        "required_role": "HR_MANAGER"
    }


# Finance
@app.get("/api/finance/dashboard")
def finance_dashboard(
    current_user: dict = Depends(require_roles("FINANCE_ANALYST"))
):
    return {
        "message": "Finance dashboard access granted",
        "username": current_user.get("preferred_username"),
        "required_role": "FINANCE_ANALYST"
    }


# Risk Assessment — database-backed risk register
def calculate_risk_level(score: int) -> str:
    """Convert a 1–25 likelihood × impact score into a severity band."""
    if score <= 4:
        return "LOW"
    if score <= 9:
        return "MEDIUM"
    if score <= 16:
        return "HIGH"
    return "CRITICAL"


@app.get(
    "/api/security/risks",
    response_model=list[RiskAssessmentResponse],
)
def list_risk_assessments(
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("IT_ADMIN", "SECURITY_ANALYST")
    ),
):
    risks = (
        db.query(RiskAssessment)
        .order_by(RiskAssessment.created_at.desc(), RiskAssessment.id.desc())
        .all()
    )
    return risks


@app.post(
    "/api/security/risks",
    response_model=RiskAssessmentResponse,
    status_code=201,
)
def create_risk_assessment(
    risk_data: RiskAssessmentCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("IT_ADMIN", "SECURITY_ANALYST")
    ),
):
    risk_score = risk_data.likelihood * risk_data.impact
    risk = RiskAssessment(
        title=risk_data.title,
        description=risk_data.description,
        asset=risk_data.asset,
        category=risk_data.category,
        likelihood=risk_data.likelihood,
        impact=risk_data.impact,
        risk_score=risk_score,
        severity=calculate_risk_level(risk_score),
        status=risk_data.status,
        mitigation_plan=risk_data.mitigation_plan,
        owner=risk_data.owner,
        created_by=current_user.get("preferred_username", "unknown"),
    )

    try:
        db.add(risk)
        db.commit()
        db.refresh(risk)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Unable to create risk assessment due to a database conflict",
        ) from None

    record_audit_event(
        username=current_user.get("preferred_username", "unknown"),
        action="CREATE_RISK_ASSESSMENT",
        outcome="SUCCESS",
        resource_type="RISK_ASSESSMENT",
        resource_id=str(risk.id),
        details={
            "title": risk.title,
            "asset": risk.asset,
            "category": risk.category,
            "risk_score": risk.risk_score,
            "severity": risk.severity,
            "status": risk.status,
        },
        source_ip=request.client.host if request.client else None,
        keycloak_user_id=current_user.get("sub"),
    )
    return risk


@app.put(
    "/api/security/risks/{risk_id}",
    response_model=RiskAssessmentResponse,
)
def update_risk_assessment(
    risk_id: int,
    risk_data: RiskAssessmentUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("IT_ADMIN", "SECURITY_ANALYST")
    ),
):
    risk = (
        db.query(RiskAssessment)
        .filter(RiskAssessment.id == risk_id)
        .first()
    )
    if risk is None:
        raise HTTPException(status_code=404, detail="Risk assessment not found")

    changes = risk_data.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(
            status_code=400,
            detail="No update fields provided",
        )

    nullable_fields = {"mitigation_plan", "owner"}
    for field, value in changes.items():
        if value is None and field not in nullable_fields:
            raise HTTPException(
                status_code=422,
                detail=f"{field} cannot be null",
            )

    changed_fields = sorted(changes.keys())
    for field, value in changes.items():
        setattr(risk, field, value)

    # Always derive score and severity from the current likelihood and impact.
    risk.risk_score = risk.likelihood * risk.impact
    risk.severity = calculate_risk_level(risk.risk_score)

    try:
        db.commit()
        db.refresh(risk)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Unable to update risk assessment due to a database conflict",
        ) from None

    record_audit_event(
        username=current_user.get("preferred_username", "unknown"),
        action="UPDATE_RISK_ASSESSMENT",
        outcome="SUCCESS",
        resource_type="RISK_ASSESSMENT",
        resource_id=str(risk.id),
        details={
            "title": risk.title,
            "changed_fields": changed_fields,
            "risk_score": risk.risk_score,
            "severity": risk.severity,
            "status": risk.status,
        },
        source_ip=request.client.host if request.client else None,
        keycloak_user_id=current_user.get("sub"),
    )
    return risk


@app.delete("/api/security/risks/{risk_id}")
def delete_risk_assessment(
    risk_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("IT_ADMIN", "SECURITY_ANALYST")
    ),
):
    risk = (
        db.query(RiskAssessment)
        .filter(RiskAssessment.id == risk_id)
        .first()
    )
    if risk is None:
        raise HTTPException(status_code=404, detail="Risk assessment not found")

    deleted_title = risk.title
    db.delete(risk)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Unable to delete risk assessment",
        ) from None

    record_audit_event(
        username=current_user.get("preferred_username", "unknown"),
        action="DELETE_RISK_ASSESSMENT",
        outcome="SUCCESS",
        resource_type="RISK_ASSESSMENT",
        resource_id=str(risk_id),
        details={"title": deleted_title},
        source_ip=request.client.host if request.client else None,
        keycloak_user_id=current_user.get("sub"),
    )
    return {
        "message": "Risk assessment deleted successfully",
        "risk_id": risk_id,
    }

