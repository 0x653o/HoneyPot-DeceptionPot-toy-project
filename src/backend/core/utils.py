"""
Utility functions: rate limiter, IP blacklist/whitelist.
"""

import time
import threading
from collections import defaultdict
from typing import Set

from .config import RateLimitConfig


class RateLimiter:
    """
    Per-IP connection rate limiter using a sliding window.
    Thread-safe for concurrent access from asyncio handlers.
    """

    def __init__(self, config: RateLimitConfig):
        self._config = config
        self._connections: dict = defaultdict(list)
        self._lock = threading.Lock()
        self._whitelist: Set[str] = set(config.whitelist)
        self._blacklist: Set[str] = set(config.blacklist)

    def is_allowed(self, ip: str) -> bool:
        """
        Check if a connection from this IP should be allowed.
        
        Returns:
            True if allowed, False if rate-limited or blacklisted.
        """
        if not self._config.enabled:
            return True

        # Whitelist always passes
        if ip in self._whitelist:
            return True

        # Blacklist always blocks
        if ip in self._blacklist:
            return False

        now = time.time()
        window_start = now - self._config.window_seconds

        with self._lock:
            # Clean old entries
            self._connections[ip] = [
                t for t in self._connections[ip] if t > window_start
            ]

            # Check count
            if len(self._connections[ip]) >= self._config.max_connections:
                return False

            # Record this connection
            self._connections[ip].append(now)
            return True

    def get_connection_count(self, ip: str) -> int:
        """Get current connection count for an IP within the window."""
        now = time.time()
        window_start = now - self._config.window_seconds

        with self._lock:
            self._connections[ip] = [
                t for t in self._connections[ip] if t > window_start
            ]
            return len(self._connections[ip])

    def add_to_blacklist(self, ip: str):
        """Dynamically add an IP to the blacklist."""
        self._blacklist.add(ip)

    def remove_from_blacklist(self, ip: str):
        """Remove an IP from the blacklist."""
        self._blacklist.discard(ip)

    def add_to_whitelist(self, ip: str):
        """Dynamically add an IP to the whitelist."""
        self._whitelist.add(ip)

    def cleanup(self):
        """Remove all expired entries from the tracking dict."""
        now = time.time()
        window_start = now - self._config.window_seconds

        with self._lock:
            expired = [
                ip for ip, times in self._connections.items()
                if all(t <= window_start for t in times)
            ]
            for ip in expired:
                del self._connections[ip]


def generate_session_id() -> str:
    """Generate a unique session ID for connection tracking."""
    import uuid
    return str(uuid.uuid4())[:12]
