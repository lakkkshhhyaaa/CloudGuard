from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    JSON,
    func,
)

from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    # Who performed the action?
    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
    )
    username = Column(String(100), nullable=False)

    # What happened?
    action = Column(String(100), nullable=False)
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(255), nullable=True)

    # What was the result?
    outcome = Column(String(50), nullable=False)

    # Additional investigation details
    details = Column(JSON, nullable=True)
    source_ip = Column(String(45), nullable=True)

    # When did it happen?
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )