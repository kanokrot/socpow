"""Create feedback and FAQ tables for the SOC Room Help Desk."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path


def upgrade(connection: sqlite3.Connection) -> None:
    """Create helpdesk tables and indexes idempotently."""
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS helpdesk_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submitter_id INTEGER NOT NULL,
            type TEXT NOT NULL CHECK (
                type IN ('wrong_verdict', 'bug', 'suggestion')
            ),
            reference TEXT CHECK (reference IS NULL OR length(reference) <= 200),
            message TEXT NOT NULL CHECK (length(message) BETWEEN 1 AND 2000),
            status TEXT NOT NULL DEFAULT 'new' CHECK (
                status IN ('new', 'reviewed', 'resolved')
            ),
            admin_note TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (submitter_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS helpdesk_faq (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT NOT NULL CHECK (length(question) BETWEEN 1 AND 300),
            answer TEXT NOT NULL CHECK (length(answer) BETWEEN 1 AND 4000),
            sort_order INTEGER NOT NULL DEFAULT 0,
            is_published INTEGER NOT NULL DEFAULT 1 CHECK (is_published IN (0, 1)),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_by INTEGER
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS helpdesk_feedback_status_created_idx "
        "ON helpdesk_feedback(status, created_at, id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS helpdesk_faq_published_order_idx "
        "ON helpdesk_faq(is_published, sort_order, id)"
    )
    connection.commit()


def migrate(db_path: str | os.PathLike[str] | None = None) -> None:
    path = Path(db_path or os.getenv("AUTH_DB_PATH", "src/db/auth.db"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as connection:
        upgrade(connection)


if __name__ == "__main__":
    migrate(sys.argv[1] if len(sys.argv) > 1 else None)
