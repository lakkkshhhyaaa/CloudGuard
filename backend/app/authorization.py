import logging

from fastapi import Depends, HTTPException, Request, status

from app.security import verify_token
from app.audit import record_audit_event


logger = logging.getLogger(__name__)


# CloudGuard application roles.
# Only these roles can grant access to protected CloudGuard endpoints.
CLOUDGUARD_ROLES = frozenset(
    {
        "IT_ADMIN",
        "SECURITY_ANALYST",
        "HR_MANAGER",
        "FINANCE_ANALYST",
    }
)


def require_roles(*allowed_roles: str):
    """
    Create a dependency that allows access only to users with at least
    one permitted CloudGuard application role.

    Invalid role configuration is rejected when the dependency is created.
    Malformed role claims are treated as having no CloudGuard permissions.
    """

    if not allowed_roles:
        raise ValueError("At least one allowed CloudGuard role is required")

    if any(
        not isinstance(role, str) or role not in CLOUDGUARD_ROLES
        for role in allowed_roles
    ):
        raise ValueError("Allowed roles must be valid CloudGuard application roles")

    # Remove duplicates while preserving the configured order.
    configured_roles = tuple(dict.fromkeys(allowed_roles))

    def role_checker(
        request: Request,
        current_user: dict = Depends(verify_token),
    ):
        # Be defensive even though verify_token normally returns a dictionary.
        if not isinstance(current_user, dict):
            current_user = {}

        realm_access = current_user.get("realm_access")
        if not isinstance(realm_access, dict):
            realm_access = {}

        raw_roles = realm_access.get("roles")

        # Keycloak emits roles as a JSON array. Ignore malformed structures
        # and non-string entries rather than allowing them to crash set().
        if isinstance(raw_roles, list):
            user_roles = {
                role for role in raw_roles if isinstance(role, str)
            }
        else:
            user_roles = set()

        # Ignore roles that do not belong to this application.
        cloudguard_roles = user_roles.intersection(CLOUDGUARD_ROLES)

        # A user needs at least one role explicitly permitted by this route.
        if not cloudguard_roles.intersection(configured_roles):
            username = current_user.get("preferred_username", "unknown")
            if not isinstance(username, str) or not username:
                username = "unknown"

            keycloak_user_id = current_user.get("sub")
            if not isinstance(keycloak_user_id, str):
                keycloak_user_id = None

            source_ip = request.client.host if request.client else None

            # Auditing is best-effort: an audit failure must never turn a
            # denied request into an allowed request or a server error.
            try:
                record_audit_event(
                    username=username,
                    action="AUTHORIZATION_DENIED",
                    outcome="DENIED",
                    resource_type="API",
                    resource_id=request.url.path,
                    details={
                        "user_roles": sorted(cloudguard_roles),
                        "required_roles": list(configured_roles),
                        "method": request.method,
                        "reason": "Insufficient permissions",
                    },
                    source_ip=source_ip,
                    keycloak_user_id=keycloak_user_id,
                )
            except Exception:
                logger.exception(
                    "Failed to record authorization denial audit event"
                )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource",
            )

        return current_user

    return role_checker
