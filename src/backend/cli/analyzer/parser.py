"""
Log Parser — Regex-based parser for honeypot.log files.

Parses the structured text log format into usable data structures:
- Connection entries: timestamp, protocol, IP, port
- Event entries: data payloads, credentials, commands

Compatible with the log format produced by honeypot/logger.py.
"""

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from pathlib import Path


# Regex patterns matching the logger output format
CONNECTION_REGEX = re.compile(
    r"\[(.*?)\] \[(.*?)\] Connection from: "
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)"
)

DATA_REGEX = re.compile(r"\s+Data Sent: (.*)")

AUTH_REGEX = re.compile(r"\s+Data Sent: AUTH (.*?):(.*)")


@dataclass
class ConnectionEntry:
    """A single connection recorded in the log."""
    timestamp: str
    protocol: str
    ip: str
    port: int
    payloads: List[str] = field(default_factory=list)
    credentials: List[tuple] = field(default_factory=list)


@dataclass
class IPSummary:
    """Aggregated data for a single attacker IP."""
    ip: str
    total_connections: int = 0
    protocols_used: set = field(default_factory=set)
    payload_counter: Counter = field(default_factory=Counter)
    credentials: List[tuple] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    info: Optional[dict] = None


@dataclass
class AnalysisResult:
    """Complete analysis result for a log file."""
    total_connections: int = 0
    total_unique_ips: int = 0
    protocol_counts: Counter = field(default_factory=Counter)
    ip_summaries: Dict[str, IPSummary] = field(default_factory=dict)
    overall_payloads: Counter = field(default_factory=Counter)
    overall_credentials: List[dict] = field(default_factory=list)
    timeline: List[dict] = field(default_factory=list)


def parse_log_file(
    logfile: str,
    protocol_filter: Optional[str] = None,
) -> AnalysisResult:
    """
    Parse a honeypot log file into structured data.
    
    Args:
        logfile: Path to the honeypot.log file.
        protocol_filter: Optional, only include entries for this protocol.
        
    Returns:
        AnalysisResult with all parsed data.
        
    Raises:
        FileNotFoundError: If log file doesn't exist.
    """
    log_path = Path(logfile)
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {logfile}")

    result = AnalysisResult()
    current_entry: Optional[ConnectionEntry] = None

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")

            # Try to match a connection line
            conn_match = CONNECTION_REGEX.search(line)
            if conn_match:
                # Save previous entry if exists
                if current_entry:
                    _process_entry(result, current_entry)

                timestamp, protocol, ip, port = conn_match.groups()

                # Apply protocol filter
                if protocol_filter and protocol.lower() != protocol_filter.lower():
                    current_entry = None
                    continue

                current_entry = ConnectionEntry(
                    timestamp=timestamp,
                    protocol=protocol,
                    ip=ip,
                    port=int(port),
                )
                continue

            # Try to match auth/credential line
            auth_match = AUTH_REGEX.search(line)
            if auth_match and current_entry:
                username, password = auth_match.groups()
                current_entry.credentials.append((username, password))
                continue

            # Try to match data line
            data_match = DATA_REGEX.search(line)
            if data_match and current_entry:
                payload = data_match.group(1).strip()
                if payload:
                    current_entry.payloads.append(payload)
                continue

    # Process last entry
    if current_entry:
        _process_entry(result, current_entry)

    # Calculate totals
    result.total_unique_ips = len(result.ip_summaries)

    return result


def _process_entry(result: AnalysisResult, entry: ConnectionEntry):
    """Process a single connection entry into the analysis result."""
    result.total_connections += 1
    result.protocol_counts[entry.protocol] += 1

    # Update IP summary
    if entry.ip not in result.ip_summaries:
        result.ip_summaries[entry.ip] = IPSummary(
            ip=entry.ip,
            first_seen=entry.timestamp,
        )

    ip_summary = result.ip_summaries[entry.ip]
    ip_summary.total_connections += 1
    ip_summary.protocols_used.add(entry.protocol)
    ip_summary.last_seen = entry.timestamp

    # Payloads
    for payload in entry.payloads:
        ip_summary.payload_counter[payload] += 1
        result.overall_payloads[payload] += 1

    # Credentials
    for username, password in entry.credentials:
        ip_summary.credentials.append((username, password))
        result.overall_credentials.append({
            "ip": entry.ip,
            "protocol": entry.protocol,
            "username": username,
            "password": password,
            "timestamp": entry.timestamp,
        })

    # Timeline
    result.timeline.append({
        "timestamp": entry.timestamp,
        "protocol": entry.protocol,
        "ip": entry.ip,
        "port": entry.port,
        "payload_count": len(entry.payloads),
    })


def parse_log_from_db(
    db_path: str,
    protocol_filter: Optional[str] = None,
    limit: int = 1000,
) -> AnalysisResult:
    """
    Parse honeypot data from SQLite database.
    
    Args:
        db_path: Path to honeypot.db.
        protocol_filter: Optional protocol filter.
        limit: Max number of connections to process.
        
    Returns:
        AnalysisResult with all parsed data.
    """
    import sqlite3

    db = Path(db_path)
    if not db.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    result = AnalysisResult()

    # Query connections
    query = "SELECT * FROM connections"
    params = []
    if protocol_filter:
        query += " WHERE protocol = ?"
        params.append(protocol_filter.lower())
    query += " ORDER BY timestamp"
    query += " LIMIT ?"
    params.append(limit)

    for row in cursor.execute(query, params):
        conn_id = row["id"]
        ip = row["src_ip"]
        protocol = row["protocol"].upper()
        timestamp = row["timestamp"]
        port = row["src_port"]

        result.total_connections += 1
        result.protocol_counts[protocol] += 1

        # IP summary
        if ip not in result.ip_summaries:
            result.ip_summaries[ip] = IPSummary(
                ip=ip, first_seen=timestamp
            )
        ip_s = result.ip_summaries[ip]
        ip_s.total_connections += 1
        ip_s.protocols_used.add(protocol)
        ip_s.last_seen = timestamp

        # Events for this connection
        for event in cursor.execute(
            "SELECT * FROM events WHERE connection_id = ?",
            (conn_id,)
        ):
            payload = event["data"]
            if payload:
                ip_s.payload_counter[payload] += 1
                result.overall_payloads[payload] += 1

        # Credentials
        for cred in cursor.execute(
            "SELECT * FROM credentials WHERE connection_id = ?",
            (conn_id,)
        ):
            username = cred["username"]
            password = cred["password"]
            ip_s.credentials.append((username, password))
            result.overall_credentials.append({
                "ip": ip,
                "protocol": protocol,
                "username": username,
                "password": password,
                "timestamp": cred["timestamp"],
            })

        result.timeline.append({
            "timestamp": timestamp,
            "protocol": protocol,
            "ip": ip,
            "port": port,
        })

    result.total_unique_ips = len(result.ip_summaries)
    conn.close()

    return result
