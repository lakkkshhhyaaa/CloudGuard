import json
import logging
from typing import Any

from app.database import SessionLocal
from app.models import AuditLog, User


logger = logging.getLogger(__name__)

# Audit metadata must never contain credentials or authentication material.
SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "credential",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "client_secret",
)

MAX_DETAILS_BYTES = 16 * 1024
MAX_STRING_LENGTH = 2_000
MAX_COLLECTION_ITEMS = 100
MAX_NESTING_DEPTH = 8


def _is_sensitive_key(key: str) -> bool:
    normalized = "".join(character.lower() for character in key if character.isalnum())
    return any(part.replace("_", "") in normalized for part in SENSITIVE_KEY_PARTS)


def _sanitize_value(value: Any, *, depth: int = 0) -> Any:
    """Convert audit metadata to bounded, JSON-safe data and redact secrets."""
    if depth > MAX_NESTING_DEPTH:
        return "[MAX_DEPTH_REACHED]"

    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        return value[:MAX_STRING_LENGTH]

    if isinstance(value, dict):
        sanitized = {}
        items = list(value.items())[:MAX_COLLECTION_ITEMS]
        for raw_key, raw_value in items:
            key = str(raw_key)[:100]
            if _is_sensitive_key(key):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = _sanitize_value(raw_value, depth=depth + 1)
        if len(value) > MAX_COLLECTION_ITEMS:
            sanitized["_truncated_items"] = len(value) - MAX_COLLECTION_ITEMS
        return sanitized

    if isinstance(value, (list, tuple, set)):
        items = list(value)
        sanitized = [
            _sanitize_value(item, depth=depth + 1)
            for item in items[:MAX_COLLECTION_ITEMS]
        ]
        if len(items) > MAX_COLLECTION_ITEMS:
            sanitized.append(
                f"[{len(items) - MAX_COLLECTION_ITEMS} ITEMS OMITTED]"
            )
        return sanitized

    # Avoid persisting arbitrary object representations that may expose secrets.
    return f"[UNSUPPORTED_TYPE:{type(value).__name__}]"


def sanitize_audit_details(details: dict | None) -> dict | None:
    """Redact sensitive keys and cap audit metadata size before persistence."""
    if details is None:
        return None

    if not isinstance(details, dict):
        return {"_audit_warning": "details_not_a_dictionary"}

    sanitized = _sanitize_value(details)

    try:
        serialized = json.dumps(
            sanitized,
            ensure_ascii=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        return {"_audit_warning": "details_serialization_failed"}

    if len(serialized.encode("utf-8")) > MAX_DETAILS_BYTES:
        return {
            "_truncated": True,
            "_reason": "audit_details_exceeded_size_limit",
            "_original_size_bytes": len(serialized.encode("utf-8")),
        }

    return sanitized


def record_audit_event(
    *,
    username: str,
    action: str,
    outcome: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict | None = None,
    source_ip: str | None = None,
    keycloak_user_id: str | None = None,
) -> bool:
    """
    Record an audit event in an independent database transaction.

    Sensitive metadata keys are redacted before persistence. Audit metadata
    is bounded to prevent unexpectedly large records.

    Returns True if the event was recorded.
    Returns False if audit logging failed.
    Audit failures never interrupt the main application flow.
    """
    db = None

    try:
        safe_details = sanitize_audit_details(details)
        db = SessionLocal()

        actor = None
        if keycloak_user_id:
            actor = (
                db.query(User)
                .filter(User.keycloak_id == keycloak_user_id)
                .first()
            )

        audit_entry = AuditLog(
            user_id=actor.id if actor else None,
            username=(username or "unknown")[:100],
            action=action[:100],
            resource_type=resource_type[:100] if resource_type else None,
            resource_id=resource_id[:255] if resource_id else None,
            outcome=outcome[:50],
            details=safe_details,
            source_ip=source_ip[:45] if source_ip else None,
        )

        db.add(audit_entry)
        db.commit()
        return True

    except Exception:
        if db is not None:
            try:
                db.rollback()
            except Exception:
                logger.exception("Failed to roll back audit transaction")

        logger.exception(
            "Failed to record audit event: action=%s outcome=%s",
            action,
            outcome,
        )
        return False

    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                logger.exception("Failed to close audit database session")
