"""add risk assessments table

Revision ID: 41302613af39
Revises: 56dad65d6d95
Create Date: 2026-11-16 21:17:27.743452
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "41302613af39"
down_revision = "56dad65d6d95"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=150), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("asset", sa.String(length=150), nullable=False),
        sa.Column("category", sa.String(length=50), nullable=False),
        sa.Column("likelihood", sa.Integer(), nullable=False),
        sa.Column("impact", sa.Integer(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default="OPEN",
            nullable=False,
        ),
        sa.Column("mitigation_plan", sa.Text(), nullable=True),
        sa.Column("owner", sa.String(length=100), nullable=True),
        sa.Column("created_by", sa.String(length=100), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "likelihood >= 1 AND likelihood <= 5",
            name="ck_risk_assessments_likelihood_range",
        ),
        sa.CheckConstraint(
            "impact >= 1 AND impact <= 5",
            name="ck_risk_assessments_impact_range",
        ),
        sa.CheckConstraint(
            "risk_score >= 1 AND risk_score <= 25",
            name="ck_risk_assessments_score_range",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_risk_assessments_id"),
        "risk_assessments",
        ["id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_risk_assessments_title"),
        "risk_assessments",
        ["title"],
        unique=False,
    )
    op.create_index(
        op.f("ix_risk_assessments_asset"),
        "risk_assessments",
        ["asset"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_risk_assessments_asset"), table_name="risk_assessments")
    op.drop_index(op.f("ix_risk_assessments_title"), table_name="risk_assessments")
    op.drop_index(op.f("ix_risk_assessments_id"), table_name="risk_assessments")
    op.drop_table("risk_assessments")

