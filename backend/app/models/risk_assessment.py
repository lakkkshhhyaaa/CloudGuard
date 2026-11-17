from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    func,
)

from app.database import Base


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    __table_args__ = (
        CheckConstraint(
            "likelihood >= 1 AND likelihood <= 5",
            name="ck_risk_assessments_likelihood_range",
        ),
        CheckConstraint(
            "impact >= 1 AND impact <= 5",
            name="ck_risk_assessments_impact_range",
        ),
        CheckConstraint(
            "risk_score >= 1 AND risk_score <= 25",
            name="ck_risk_assessments_score_range",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)

    title = Column(String(150), nullable=False, index=True)
    description = Column(Text, nullable=False)
    asset = Column(String(150), nullable=False, index=True)
    category = Column(String(50), nullable=False)

    # Likelihood and impact are each rated from 1 (lowest) to 5 (highest).
    likelihood = Column(Integer, nullable=False)
    impact = Column(Integer, nullable=False)
    risk_score = Column(Integer, nullable=False)
    severity = Column(String(20), nullable=False)

    status = Column(
        String(20),
        nullable=False,
        default="OPEN",
        server_default="OPEN",
    )
    mitigation_plan = Column(Text, nullable=True)
    owner = Column(String(100), nullable=True)
    created_by = Column(String(100), nullable=False)

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
