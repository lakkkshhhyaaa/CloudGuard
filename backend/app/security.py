import logging
import os

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.audit import record_audit_event


logger = logging.getLogger(__name__)


# Keycloak configuration
KEYCLOAK_INTERNAL_URL = os.getenv(
    "KEYCLOAK_INTERNAL_URL",
    "http://keycloak:8080",
)
KEYCLOAK_PUBLIC_URL = os.getenv(
    "KEYCLOAK_PUBLIC_URL",
    "http://localhost:8080",
)
KEYCLOAK_REALM = os.getenv(
    "KEYCLOAK_REALM",
    "cloudguard",
)
KEYCLOAK_CLIENT_ID = os.getenv(
    "KEYCLOAK_CLIENT_ID",
    "cloudguard-frontend",
)
KEYCLOAK_API_AUDIENCE = os.getenv(
    "KEYCLOAK_API_AUDIENCE",
    "cloudguard-api",
)


# The public issuer must match the issuer claim in Keycloak access tokens.
ISSUER = f"{KEYCLOAK_PUBLIC_URL}/realms/{KEYCLOAK_REALM}"

# Use the internal Docker-network address to retrieve Keycloak signing keys.
JWKS_URL = (
    f"{KEYCLOAK_INTERNAL_URL}/realms/"
    f"{KEYCLOAK_REALM}/protocol/openid-connect/certs"
)

jwks_client = PyJWKClient(JWKS_URL)

# Let verify_token() handle missing credentials and create an audit event.
bearer_scheme = HTTPBearer(auto_error=False)


def _audit_authentication_failure(
    *,
    request: Request,
    source_ip: str | None,
    reason: str,
    username: str = "unknown",
    keycloak_user_id: str | None = None,
) -> None:
    """Record a safe authentication-failure event without storing credentials."""
    record_audit_event(
        username=username,
        action="AUTHENTICATION_FAILURE",
        outcome="FAILURE",
        resource_type="API",
        resource_id=request.url.path,
        details={"reason": reason},
        source_ip=source_ip,
        keycloak_user_id=keycloak_user_id,
    )


def verify_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
):
    source_ip = request.client.host if request.client else None

    if credentials is None:
        _audit_authentication_failure(
            request=request,
            source_ip=source_ip,
            reason="Missing bearer token",
            username="anonymous",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=KEYCLOAK_API_AUDIENCE,
            options={
                # Reject tokens that omit essential time/identity claims.
                "require": ["exp", "iat", "sub"],
            },
        )

        # The API accepts tokens issued to the configured frontend client.
        if payload.get("azp") != KEYCLOAK_CLIENT_ID:
            _audit_authentication_failure(
                request=request,
                source_ip=source_ip,
                reason="Invalid token client",
                username=payload.get("preferred_username", "unknown"),
                keycloak_user_id=payload.get("sub"),
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token client",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return payload

    except HTTPException:
        raise

    except PyJWKClientConnectionError:
        # Keycloak/JWKS could not be reached. This is an infrastructure
        # problem, not proof that the supplied token is invalid.
        logger.exception("Unable to connect to Keycloak JWKS endpoint")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to verify authentication token",
        )

    except PyJWKClientError:
        # For example, the token's key ID does not match a published key.
        _audit_authentication_failure(
            request=request,
            source_ip=source_ip,
            reason="Unable to find a valid signing key",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except jwt.PyJWTError:
        _audit_authentication_failure(
            request=request,
            source_ip=source_ip,
            reason="Invalid or expired access token",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except Exception:
        logger.exception("Unexpected authentication verification error")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to verify authentication token",
        )
