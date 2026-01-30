"""Storage module for checkpointing and audit logging."""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator

if TYPE_CHECKING:
    from mailwarden.decision_engine import Decision
    from mailwarden.executor import ExecutionResult

logger = logging.getLogger(__name__)


class Storage:
    """SQLite-based storage for checkpoints and audit logs."""

    SCHEMA_VERSION = 1

    def __init__(self, db_path: str | Path):
        """Initialize storage with database path."""
        self.db_path = Path(db_path)
        self._connection: sqlite3.Connection | None = None
        self._init_database()

    def _init_database(self) -> None:
        """Initialize the database schema."""
        with self._get_connection() as conn:
            conn.executescript(
                """
                -- Schema version tracking
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                );

                -- UID checkpoints per folder
                CREATE TABLE IF NOT EXISTS checkpoints (
                    folder TEXT PRIMARY KEY,
                    last_uid INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                -- Processed message tracking
                CREATE TABLE IF NOT EXISTS processed_messages (
                    message_id TEXT PRIMARY KEY,
                    uid INTEGER NOT NULL,
                    folder TEXT NOT NULL,
                    processed_at TEXT NOT NULL,
                    decision_json TEXT
                );

                -- Audit log
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    uid INTEGER NOT NULL,
                    message_id TEXT,
                    action TEXT NOT NULL,
                    source_folder TEXT,
                    target_folder TEXT,
                    category TEXT,
                    confidence REAL,
                    reason TEXT,
                    success INTEGER NOT NULL,
                    error TEXT,
                    details_json TEXT
                );

                -- Index for efficient queries
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
                CREATE INDEX IF NOT EXISTS idx_audit_uid ON audit_log(uid);
                CREATE INDEX IF NOT EXISTS idx_processed_folder ON processed_messages(folder);
                """
            )

            # Check/set schema version
            cursor = conn.execute("SELECT version FROM schema_version")
            row = cursor.fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?)",
                    (self.SCHEMA_VERSION,),
                )

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get a database connection with proper handling."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_checkpoint(self, folder: str) -> int | None:
        """Get the last processed UID for a folder."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT last_uid FROM checkpoints WHERE folder = ?", (folder,)
            )
            row = cursor.fetchone()
            return row["last_uid"] if row else None

    def set_checkpoint(self, folder: str, uid: int) -> None:
        """Set the checkpoint for a folder."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO checkpoints (folder, last_uid, updated_at)
                VALUES (?, ?, ?)
                """,
                (folder, uid, datetime.now().isoformat()),
            )
        logger.debug(f"Checkpoint set for {folder}: UID {uid}")

    def is_processed(self, message_id: str) -> bool:
        """Check if a message has been processed."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT 1 FROM processed_messages WHERE message_id = ?", (message_id,)
            )
            return cursor.fetchone() is not None

    def mark_processed(
        self, message_id: str, uid: int, folder: str, decision: Decision | None = None
    ) -> None:
        """Mark a message as processed."""
        with self._get_connection() as conn:
            decision_json = json.dumps(decision.to_dict()) if decision else None
            conn.execute(
                """
                INSERT OR REPLACE INTO processed_messages 
                (message_id, uid, folder, processed_at, decision_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (message_id, uid, folder, datetime.now().isoformat(), decision_json),
            )

    def log_action(
        self,
        decision: Decision,
        result: ExecutionResult,
        source_folder: str,
    ) -> None:
        """Log an action to the audit log."""
        with self._get_connection() as conn:
            # Prepare action description
            actions = [
                f"{a.action_type.value}:{a.target_folder or ','.join(a.flags_add)}"
                for a in decision.actions
            ]
            action_str = "; ".join(actions) if actions else "none"

            # Prepare details
            details = {
                "decision": decision.to_dict(),
                "result": result.to_dict(),
            }

            conn.execute(
                """
                INSERT INTO audit_log (
                    timestamp, uid, message_id, action, source_folder,
                    target_folder, category, confidence, reason, success,
                    error, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now().isoformat(),
                    decision.uid,
                    decision.message_id,
                    action_str,
                    source_folder,
                    decision.target_folder,
                    decision.category,
                    decision.confidence,
                    decision.reason,
                    1 if result.success else 0,
                    result.error,
                    json.dumps(details),
                ),
            )

    def get_audit_log(
        self,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get audit log entries."""
        with self._get_connection() as conn:
            if since:
                cursor = conn.execute(
                    """
                    SELECT * FROM audit_log 
                    WHERE timestamp >= ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (since.isoformat(), limit),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT * FROM audit_log 
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (limit,),
                )

            return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self, since: datetime | None = None) -> dict[str, Any]:
        """Get processing statistics."""
        with self._get_connection() as conn:
            where_clause = ""
            params: tuple = ()
            if since:
                where_clause = "WHERE timestamp >= ?"
                params = (since.isoformat(),)

            # Total processed
            cursor = conn.execute(
                f"SELECT COUNT(*) as total FROM audit_log {where_clause}", params
            )
            total = cursor.fetchone()["total"]

            # By category
            cursor = conn.execute(
                f"""
                SELECT category, COUNT(*) as count 
                FROM audit_log {where_clause}
                GROUP BY category
                """,
                params,
            )
            by_category = {row["category"]: row["count"] for row in cursor.fetchall()}

            # Success/failure
            cursor = conn.execute(
                f"""
                SELECT success, COUNT(*) as count 
                FROM audit_log {where_clause}
                GROUP BY success
                """,
                params,
            )
            success_counts = {
                "success": 0,
                "failed": 0,
            }
            for row in cursor.fetchall():
                if row["success"]:
                    success_counts["success"] = row["count"]
                else:
                    success_counts["failed"] = row["count"]

            # By target folder
            cursor = conn.execute(
                f"""
                SELECT target_folder, COUNT(*) as count 
                FROM audit_log {where_clause}
                GROUP BY target_folder
                """,
                params,
            )
            by_folder = {
                row["target_folder"]: row["count"] for row in cursor.fetchall()
            }

            return {
                "total_processed": total,
                "by_category": by_category,
                "by_folder": by_folder,
                "success": success_counts["success"],
                "failed": success_counts["failed"],
            }

    def export_audit_jsonl(self, output_path: str | Path) -> int:
        """Export audit log to JSONL format. Returns number of entries."""
        output_path = Path(output_path)
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM audit_log ORDER BY timestamp"
            )

            count = 0
            with open(output_path, "w", encoding="utf-8") as f:
                for row in cursor:
                    entry = dict(row)
                    # Parse nested JSON
                    if entry.get("details_json"):
                        entry["details"] = json.loads(entry["details_json"])
                        del entry["details_json"]
                    f.write(json.dumps(entry) + "\n")
                    count += 1

            return count

    def close(self) -> None:
        """Close any open connections."""
        pass  # Connections are closed after each operation

