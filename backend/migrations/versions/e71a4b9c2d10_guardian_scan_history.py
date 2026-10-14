from alembic import op
import sqlalchemy as sa

revision = "e71a4b9c2d10"
down_revision = "d8f1c4a7b209"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "coreworks_guardian_scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hosts_checked", sa.Integer(), nullable=False),
        sa.Column("ports_per_host", sa.Integer(), nullable=False),
        sa.Column("checks_completed", sa.Integer(), nullable=False),
        sa.Column("open_ports", sa.Integer(), nullable=False),
    )
    op.create_index("ix_coreworks_guardian_scans_id", "coreworks_guardian_scans", ["id"])
    op.create_index("ix_coreworks_guardian_scans_user_id", "coreworks_guardian_scans", ["user_id"])

    op.create_table(
        "coreworks_guardian_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("coreworks_guardian_scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("service", sa.String(100), nullable=False),
        sa.Column("product", sa.String(255), nullable=False),
        sa.Column("version", sa.String(255), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("confidence", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(50), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
    )
    op.create_index("ix_coreworks_guardian_findings_id", "coreworks_guardian_findings", ["id"])
    op.create_index("ix_coreworks_guardian_findings_scan_id", "coreworks_guardian_findings", ["scan_id"])


def downgrade():
    op.drop_table("coreworks_guardian_findings")
    op.drop_table("coreworks_guardian_scans")
