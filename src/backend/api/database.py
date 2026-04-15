"""
Database Layer — SQLite queries for the management API.

Provides read-only access to the honeypot database for the
dashboard, attacker details, and log viewing.
"""

import sqlite3
from pathlib import Path
from typing import Optional, List, Dict
from contextlib import contextmanager


class HoneypotDatabase:
    """Read-only interface to the honeypot SQLite database."""

    def __init__(self, db_path: str = "data/honeypot.db"):
        self._db_path = db_path

    def _ensure_db(self):
        """Check database exists."""
        if not Path(self._db_path).exists():
            raise FileNotFoundError(
                f"Honeypot database not found: {self._db_path}"
            )

    @contextmanager
    def _get_conn(self):
        """Get a database connection with row factory."""
        self._ensure_db()
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def get_stats(self) -> dict:
        """Get overall dashboard statistics."""
        with self._get_conn() as conn:
            cursor = conn.cursor()

            # Total connections
            total = cursor.execute(
                "SELECT COUNT(*) as cnt FROM connections"
            ).fetchone()["cnt"]

            # Unique IPs
            unique_ips = cursor.execute(
                "SELECT COUNT(DISTINCT src_ip) as cnt FROM connections"
            ).fetchone()["cnt"]

            # Per-protocol counts
            protocols = {}
            for row in cursor.execute(
                "SELECT protocol, COUNT(*) as cnt FROM connections "
                "GROUP BY protocol ORDER BY cnt DESC"
            ):
                protocols[row["protocol"]] = row["cnt"]

            # Total credentials captured
            total_creds = cursor.execute(
                "SELECT COUNT(*) as cnt FROM credentials"
            ).fetchone()["cnt"]

            # Total events
            total_events = cursor.execute(
                "SELECT COUNT(*) as cnt FROM events"
            ).fetchone()["cnt"]

            # Recent activity (last 24h)
            recent = cursor.execute(
                "SELECT COUNT(*) as cnt FROM connections "
                "WHERE timestamp > datetime('now', '-1 day')"
            ).fetchone()["cnt"]

            return {
                "total_connections": total,
                "unique_attackers": unique_ips,
                "protocol_breakdown": protocols,
                "total_credentials": total_creds,
                "total_events": total_events,
                "connections_last_24h": recent,
            }

    def get_attackers(
        self,
        page: int = 1,
        per_page: int = 20,
        sort_by: str = "count",
        protocol: Optional[str] = None,
    ) -> dict:
        """Get paginated list of attacker IPs."""
        with self._get_conn() as conn:
            cursor = conn.cursor()

            where = ""
            params = []
            if protocol:
                where = "WHERE protocol = ?"
                params.append(protocol)

            # Get total
            total = cursor.execute(
                f"SELECT COUNT(DISTINCT src_ip) as cnt FROM connections {where}",
                params,
            ).fetchone()["cnt"]

            # Get paginated IPs
            offset = (page - 1) * per_page

            if sort_by == "recent":
                order = "MAX(timestamp) DESC"
            else:
                order = "COUNT(*) DESC"

            query = f"""
                SELECT src_ip, COUNT(*) as connection_count,
                       MIN(timestamp) as first_seen,
                       MAX(timestamp) as last_seen,
                       GROUP_CONCAT(DISTINCT protocol) as protocols
                FROM connections {where}
                GROUP BY src_ip
                ORDER BY {order}
                LIMIT ? OFFSET ?
            """

            attackers = []
            for row in cursor.execute(query, params + [per_page, offset]):
                # Get credential count for this IP
                cred_count = cursor.execute(
                    "SELECT COUNT(*) as cnt FROM credentials WHERE src_ip = ?",
                    (row["src_ip"],),
                ).fetchone()["cnt"]

                attackers.append({
                    "ip": row["src_ip"],
                    "connection_count": row["connection_count"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "protocols": row["protocols"].split(",") if row["protocols"] else [],
                    "credential_count": cred_count,
                })

            return {
                "total": total,
                "page": page,
                "per_page": per_page,
                "attackers": attackers,
            }

    def get_attacker_detail(self, ip: str) -> dict:
        """Get detailed information about a specific attacker IP."""
        with self._get_conn() as conn:
            cursor = conn.cursor()

            # Basic stats
            stats = cursor.execute(
                """SELECT COUNT(*) as cnt,
                          MIN(timestamp) as first_seen,
                          MAX(timestamp) as last_seen,
                          GROUP_CONCAT(DISTINCT protocol) as protocols
                   FROM connections WHERE src_ip = ?""",
                (ip,),
            ).fetchone()

            if stats["cnt"] == 0:
                return None

            # Credentials
            credentials = []
            for row in cursor.execute(
                "SELECT * FROM credentials WHERE src_ip = ? "
                "ORDER BY timestamp DESC LIMIT 50",
                (ip,),
            ):
                credentials.append({
                    "timestamp": row["timestamp"],
                    "protocol": row["protocol"],
                    "username": row["username"],
                    "password": row["password"],
                })

            # Recent events
            events = []
            for row in cursor.execute(
                """SELECT e.* FROM events e
                   JOIN connections c ON e.connection_id = c.id
                   WHERE c.src_ip = ?
                   ORDER BY e.timestamp DESC LIMIT 100""",
                (ip,),
            ):
                events.append({
                    "timestamp": row["timestamp"],
                    "event_type": row["event_type"],
                    "data": row["data"],
                })

            return {
                "ip": ip,
                "total_connections": stats["cnt"],
                "first_seen": stats["first_seen"],
                "last_seen": stats["last_seen"],
                "protocols": stats["protocols"].split(",") if stats["protocols"] else [],
                "credentials": credentials,
                "events": events,
            }

    def get_logs(
        self,
        page: int = 1,
        per_page: int = 50,
        protocol: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> dict:
        """Get paginated log entries."""
        with self._get_conn() as conn:
            cursor = conn.cursor()

            where_clauses = []
            params = []
            if protocol:
                where_clauses.append("c.protocol = ?")
                params.append(protocol)
            if ip:
                where_clauses.append("c.src_ip = ?")
                params.append(ip)

            where = ""
            if where_clauses:
                where = "WHERE " + " AND ".join(where_clauses)

            # Total
            total = cursor.execute(
                f"SELECT COUNT(*) as cnt FROM connections c {where}",
                params,
            ).fetchone()["cnt"]

            # Paginated results
            offset = (page - 1) * per_page
            entries = []
            for row in cursor.execute(
                f"""SELECT c.*, 
                           (SELECT COUNT(*) FROM events WHERE connection_id = c.id) as event_count,
                           (SELECT COUNT(*) FROM credentials WHERE connection_id = c.id) as cred_count
                    FROM connections c {where}
                    ORDER BY c.timestamp DESC
                    LIMIT ? OFFSET ?""",
                params + [per_page, offset],
            ):
                entries.append({
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "protocol": row["protocol"],
                    "src_ip": row["src_ip"],
                    "src_port": row["src_port"],
                    "session_id": row["session_id"],
                    "event_count": row["event_count"],
                    "cred_count": row["cred_count"],
                })

            return {
                "total": total,
                "page": page,
                "per_page": per_page,
                "entries": entries,
            }

    def get_recent_connections(self, limit: int = 10) -> List[dict]:
        """Get most recent connections for live feed."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            results = []
            for row in cursor.execute(
                "SELECT * FROM connections ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ):
                results.append({
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "protocol": row["protocol"],
                    "src_ip": row["src_ip"],
                    "src_port": row["src_port"],
                })
            return results

    def get_credentials(
        self,
        page: int = 1,
        per_page: int = 50,
    ) -> dict:
        """Get paginated credential entries."""
        with self._get_conn() as conn:
            cursor = conn.cursor()

            total = cursor.execute(
                "SELECT COUNT(*) as cnt FROM credentials"
            ).fetchone()["cnt"]

            offset = (page - 1) * per_page
            entries = []
            for row in cursor.execute(
                "SELECT * FROM credentials ORDER BY timestamp DESC "
                "LIMIT ? OFFSET ?",
                (per_page, offset),
            ):
                entries.append({
                    "timestamp": row["timestamp"],
                    "protocol": row["protocol"],
                    "src_ip": row["src_ip"],
                    "username": row["username"],
                    "password": row["password"],
                })

            return {
                "total": total,
                "page": page,
                "per_page": per_page,
                "credentials": entries,
            }

    # --- Ingestion Methods ---

    def insert_connection(self, session_id: str, ip: str, port: int, protocol: str, timestamp: str = None):
        """Insert a connection log."""
        if not timestamp:
            from datetime import datetime, timezone
            timestamp = datetime.now(timezone.utc).isoformat()
            
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO connections (timestamp, protocol, src_ip, src_port, session_id) VALUES (?, ?, ?, ?, ?)",
                (timestamp, protocol, ip, port, session_id)
            )
            conn.commit()

    def insert_event(self, session_id: str, event_type: str, data: str, timestamp: str = None):
        """Insert an event log."""
        if not timestamp:
            from datetime import datetime, timezone
            timestamp = datetime.now(timezone.utc).isoformat()
            
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO events (timestamp, session_id, event_type, data) VALUES (?, ?, ?, ?)",
                (timestamp, session_id, event_type, data)
            )
            conn.commit()

    def insert_credential(self, session_id: str, protocol: str, ip: str, username: str, password: str, timestamp: str = None):
        """Insert credential attempt log."""
        if not timestamp:
            from datetime import datetime, timezone
            timestamp = datetime.now(timezone.utc).isoformat()
            
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO credentials (timestamp, protocol, src_ip, session_id, username, password) VALUES (?, ?, ?, ?, ?, ?)",
                (timestamp, protocol, ip, session_id, username, password)
            )
            conn.commit()
