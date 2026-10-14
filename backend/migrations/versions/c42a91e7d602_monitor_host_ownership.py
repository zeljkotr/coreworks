"""Add per-user ownership to Monitor hosts.

Revision ID: c42a91e7d602
Revises: 89b6127667df
"""
from alembic import op
import sqlalchemy as sa

revision = "c42a91e7d602"
down_revision = "89b6127667df"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "coreworks_monitor_hosts",
        sa.Column("owner_id", sa.Integer(), nullable=True),
    )
    op.create_foreign_key(
        "fk_monitor_hosts_owner_id_users",
        "coreworks_monitor_hosts",
        "users",
        ["owner_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # Assign legacy records only when exactly one user exists.
    # With multiple users, leave them unassigned rather than guessing.
    op.execute("""
        DO $$
        DECLARE sole_user_id INTEGER;
        DECLARE user_count BIGINT;
        BEGIN
            SELECT COUNT(*), MIN(id)
            INTO user_count, sole_user_id
            FROM users;

            IF user_count = 1 THEN
                UPDATE coreworks_monitor_hosts
                SET owner_id = sole_user_id
                WHERE owner_id IS NULL;
            END IF;
        END $$;
    """)

    op.drop_constraint(
        "coreworks_monitor_hosts_host_port_key",
        "coreworks_monitor_hosts",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_monitor_hosts_owner_host_port",
        "coreworks_monitor_hosts",
        ["owner_id", "host", "port"],
    )
    op.create_index(
        "ix_monitor_hosts_owner_id",
        "coreworks_monitor_hosts",
        ["owner_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_monitor_hosts_owner_id", table_name="coreworks_monitor_hosts")
    op.drop_constraint(
        "uq_monitor_hosts_owner_host_port",
        "coreworks_monitor_hosts",
        type_="unique",
    )
    # Preserve the original global uniqueness rule on downgrade.
    op.create_unique_constraint(
        "coreworks_monitor_hosts_host_port_key",
        "coreworks_monitor_hosts",
        ["host", "port"],
    )
    op.drop_constraint(
        "fk_monitor_hosts_owner_id_users",
        "coreworks_monitor_hosts",
        type_="foreignkey",
    )
    op.drop_column("coreworks_monitor_hosts", "owner_id")
