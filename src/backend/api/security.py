"""
Security module for Management API.
Enforces API key authentication across all dashboard endpoints.
"""

import os
import yaml
from pathlib import Path
from fastapi import Security, HTTPException, status, Query, Request
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def get_configured_api_key() -> str:
    """Get the API key from environment or config file."""
    # Try environment variable first
    key = os.environ.get("HONEYPOT_API_KEY")
    if key:
        return key

    # Fallback to config.yaml mapping if it exists
    config_path = os.environ.get("HONEYPOT_CONFIG", "config.yaml")
    if Path(config_path).exists():
        try:
            with open(config_path, "r") as f:
                cfg = yaml.safe_load(f) or {}
                config_key = cfg.get("management", {}).get("api_key")
                if config_key:
                    return config_key
        except Exception:
            pass
            
    # Default fallback if absolutely nothing is specified
    return "default_secret"


def verify_api_key(
    request: Request,
    api_key: str = Security(api_key_header),
    token: str = Query(None)
):
    """
    FastAPI dependency to verify the API key.
    Checks the X-API-Key header OR the ?token= query parameter (for WebSockets).
    """
    configured_key = get_configured_api_key()
    supplied_key = api_key or token

    if supplied_key != configured_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
        )
    
    return supplied_key
