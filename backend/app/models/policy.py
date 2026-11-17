
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    func,
)

from app.database import Base


class SecurityPolicy(Base):
    __tablename__ = "security_policies"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(
        String(120),
        unique=True,
        nullable=False,
        index=True,
    )

    description = Column(Text, nullable=False)

    category = Column(
        String(50),
        nullable=False,
    )

    severity = Column(
        String(20),
        nullable=False,
        default="MEDIUM",
    )

    is_enabled = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )

    created_by = Column(
        String(100),
        nullable=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
