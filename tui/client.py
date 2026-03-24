"""
HTTP/WebSocket client for the TUI to communicate with the Management API.
"""

import httpx
import json
from typing import Optional, Callable


class HoneypotClient:
    """Synchronous HTTP client for the honeypot management API."""

    def __init__(self, base_url: str = "http://127.0.0.1:9090"):
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(base_url=self._base_url, timeout=10.0)

    def get_stats(self) -> dict:
        """Fetch dashboard statistics."""
        resp = self._client.get("/api/stats")
        resp.raise_for_status()
        return resp.json()

    def get_attackers(
        self, page: int = 1, per_page: int = 20,
        sort_by: str = "count", protocol: Optional[str] = None,
    ) -> dict:
        params = {"page": page, "per_page": per_page, "sort_by": sort_by}
        if protocol:
            params["protocol"] = protocol
        resp = self._client.get("/api/attackers", params=params)
        resp.raise_for_status()
        return resp.json()

    def get_attacker_detail(self, ip: str) -> dict:
        resp = self._client.get(f"/api/attackers/{ip}")
        resp.raise_for_status()
        return resp.json()

    def get_logs(
        self, page: int = 1, per_page: int = 50,
        protocol: Optional[str] = None, ip: Optional[str] = None,
    ) -> dict:
        params = {"page": page, "per_page": per_page}
        if protocol:
            params["protocol"] = protocol
        if ip:
            params["ip"] = ip
        resp = self._client.get("/api/logs", params=params)
        resp.raise_for_status()
        return resp.json()

    def get_recent_logs(self, limit: int = 20) -> list:
        resp = self._client.get("/api/logs/recent", params={"limit": limit})
        resp.raise_for_status()
        return resp.json()

    def run_analysis(
        self, protocol: Optional[str] = None,
        top_n: int = 20, enrich: bool = True,
    ) -> dict:
        params = {"top_n": top_n, "enrich": enrich}
        if protocol:
            params["protocol"] = protocol
        resp = self._client.post("/api/analyze", params=params)
        resp.raise_for_status()
        return resp.json()

    def health_check(self) -> bool:
        try:
            resp = self._client.get("/api/health")
            return resp.status_code == 200
        except Exception:
            return False

    def close(self):
        self._client.close()
