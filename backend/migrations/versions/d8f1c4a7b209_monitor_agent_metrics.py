"""Add authenticated Monitor agents and infrastructure metrics."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "d8f1c4a7b209"
down_revision = "c42a91e7d602"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "coreworks_monitor_hosts",
        sa.Column("agent_token_hash", sa.String(64), nullable=True),
    )
    op.add_column(
        "coreworks_monitor_hosts",
        sa.Column("agent_last_seen_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "coreworks_monitor_hosts",
        sa.Column("agent_version", sa.String(40), nullable=True),
    )
    op.add_column(
        "coreworks_monitor_hosts",
        sa.Column("agent_os", sa.String(255), nullable=True),
    )
    op.create_index(
        "uq_monitor_hosts_agent_token_hash",
        "coreworks_monitor_hosts",
        ["agent_token_hash"],
        unique=True,
        postgresql_where=sa.text("agent_token_hash IS NOT NULL"),
    )

    op.create_table(
        "coreworks_monitor_metrics",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "host_id",
            sa.BigInteger(),
            sa.ForeignKey("coreworks_monitor_hosts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("cpu_percent", sa.Float(), nullable=False),
        sa.Column("memory_total_bytes", sa.BigInteger(), nullable=False),
        sa.Column("memory_used_bytes", sa.BigInteger(), nullable=False),
        sa.Column("disk", postgresql.JSONB(), nullable=False),
        sa.Column("uptime_seconds", sa.BigInteger(), nullable=False),
        sa.Column("os_name", sa.String(255), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("agent_version", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "cpu_percent >= 0 AND cpu_percent <= 100",
            name="ck_monitor_metrics_cpu_percent",
        ),
        sa.CheckConstraint(
            "memory_total_bytes >= 0 AND memory_used_bytes >= 0 "
            "AND memory_used_bytes <= memory_total_bytes",
            name="ck_monitor_metrics_memory",
        ),
        sa.CheckConstraint(
            "uptime_seconds >= 0",
            name="ck_monitor_metrics_uptime",
        ),
    )
    op.create_index(
        "ix_monitor_metrics_host_recorded",
        "coreworks_monitor_metrics",
        ["host_id", "recorded_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_monitor_metrics_host_recorded",
        table_name="coreworks_monitor_metrics",
    )
    op.drop_table("coreworks_monitor_metrics")
    op.drop_index(
        "uq_monitor_hosts_agent_token_hash",
        table_name="coreworks_monitor_hosts",
    )
    op.drop_column("coreworks_monitor_hosts", "agent_os")
    op.drop_column("coreworks_monitor_hosts", "agent_version")
    op.drop_column("coreworks_monitor_hosts", "agent_last_seen_at")
    op.drop_column("coreworks_monitor_hosts", "agent_token_hash")
