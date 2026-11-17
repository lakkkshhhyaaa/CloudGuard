from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    func,
)

from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    # Identity provided by Keycloak
    keycloak_id = Column(String(255), unique=True, nullable=False)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=True)

    # Organizational information
    full_name = Column(String(150), nullable=True)
    department_id = Column(
        Integer,
        ForeignKey("departments.id"),
        nullable=True,
    )

    # Account status and creation time
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    department = relationship("Department", back_populates="users")