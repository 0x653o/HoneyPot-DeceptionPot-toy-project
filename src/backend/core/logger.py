"""
Dual-sink logger for the honeypot system.
Writes to both a text log file (for analyzer regex compatibility)
and a SQLite database (for API queries).
"""

import logging
import sqlite3
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from .config import LoggingConfig


class HoneypotLogger:
    """
    Centralized logger with dual sinks:
    1. Text file (honeypot.log) — regex-compatible format for the analyzer
    2. SQLite database (honeypot.db) — structured storage for the API
    """

    LOG_FORMAT = "[{timestamp}] [{protocol}] Connection from: {ip}:{port}"
    DATA_FORMAT = "  Data Sent: {data}"

    def __init__(self, config: LoggingConfig):
        self._config = config
        self._lock = threading.Lock()

        # --- Setup text file logger ---
        self._file_logger = logging.getLogger("honeypot.file")
        self._file_logger.setLevel(getattr(logging, config.log_level, logging.INFO))
        self._file_logger.handlers.clear()

        log_path = Path(config.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            str(log_path),
            maxBytes=config.max_file_size,
            backupCount=config.backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(logging.Formatter("%(message)s"))
        self._file_logger.addHandler(file_handler)

        # --- Setup console logger ---
        self._console_logger = logging.getLogger("honeypot.console")
        self._console_logger.setLevel(getattr(logging, config.log_level, logging.INFO))
        self._console_logger.handlers.clear()

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
        self._console_logger.addHandler(console_handler)

        # --- Setup SQLite database ---
        self._db_path = config.db_file
        self._init_database()

    def _init_database(self):
        """Initialize the SQLite database with required tables."""
        db_path = Path(self._db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                protocol TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                session_id TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                data TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (connection_id) REFERENCES connections(id)
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                protocol TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                username TEXT,
                password TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (connection_id) REFERENCES connections(id)
            );

            CREATE INDEX IF NOT EXISTS idx_connections_ip ON connections(src_ip);
            CREATE INDEX IF NOT EXISTS idx_connections_protocol ON connections(protocol);
            CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON connections(timestamp);
            CREATE INDEX IF NOT EXISTS idx_credentials_ip ON credentials(src_ip);
            CREATE INDEX IF NOT EXISTS idx_events_connection ON events(connection_id);
        """)

        conn.commit()
        conn.close()

    def _get_db_connection(self) -> sqlite3.Connection:
        """Get a thread-local SQLite connection."""
        return sqlite3.connect(str(self._db_path))

    def _now(self) -> str:
        """Get current UTC timestamp in ISO 8601 format."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def log_connection(
        self,
        protocol: str,
        src_ip: str,
        src_port: int,
        session_id: Optional[str] = None,
    ) -> int:
        """
        Log a new connection attempt.
        
        Returns:
            connection_id from the database for subsequent event logging.
        """
        timestamp = self._now()

        # Write to text log (analyzer-compatible format)
        log_line = self.LOG_FORMAT.format(
            timestamp=timestamp,
            protocol=protocol.upper(),
            ip=src_ip,
            port=src_port,
        )
        self._file_logger.info(log_line)
        self._console_logger.info(
            f"[{protocol.upper()}] Connection from {src_ip}:{src_port}"
        )

        # Write to SQLite
        connection_id = 0
        with self._lock:
            try:
                conn = self._get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO connections 
                       (timestamp, protocol, src_ip, src_port, session_id)
                       VALUES (?, ?, ?, ?, ?)""",
                    (timestamp, protocol, src_ip, src_port, session_id),
                )
                connection_id = cursor.lastrowid
                conn.commit()
                conn.close()
            except Exception as e:
                self._console_logger.error(f"DB write error: {e}")

        return connection_id

    def log_event(
        self,
        connection_id: int,
        event_type: str,
        data: str,
    ):
        """
        Log an event (data sent, command received, etc.) for a connection.
        
        Args:
            connection_id: ID from log_connection().
            event_type: Type of event (e.g., "data_sent", "command", "auth_attempt").
            data: The actual data/payload.
        """
        timestamp = self._now()

        # Write to text log
        data_line = self.DATA_FORMAT.format(data=data)
        self._file_logger.info(data_line)

        # Write to SQLite
        with self._lock:
            try:
                conn = self._get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO events 
                       (connection_id, timestamp, event_type, data)
                       VALUES (?, ?, ?, ?)""",
                    (connection_id, timestamp, event_type, data),
                )
                conn.commit()
                conn.close()
            except Exception as e:
                self._console_logger.error(f"DB event write error: {e}")

    def log_credentials(
        self,
        connection_id: int,
        protocol: str,
        src_ip: str,
        username: str,
        password: str,
    ):
        """
        Log captured credentials for a connection.
        Also writes to the text log as a data event.
        """
        timestamp = self._now()

        # Write to text log
        cred_line = f"  Data Sent: AUTH {username}:{password}"
        self._file_logger.info(cred_line)
        self._console_logger.warning(
            f"[{protocol.upper()}] Credentials captured from {src_ip}: "
            f"{username}:{password}"
        )

        # Write to SQLite
        with self._lock:
            try:
                conn = self._get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO credentials 
                       (connection_id, timestamp, protocol, src_ip, username, password)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (connection_id, timestamp, protocol, src_ip, username, password),
                )
                conn.commit()
                conn.close()
            except Exception as e:
                self._console_logger.error(f"DB credentials write error: {e}")

    def log_system(self, level: str, message: str):
        """Log a system-level message (not attacker-facing)."""
        log_fn = getattr(self._console_logger, level.lower(), self._console_logger.info)
        log_fn(message)
