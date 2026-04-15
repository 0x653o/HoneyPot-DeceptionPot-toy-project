"""
FastAPI dependencies for the management sector.
Provides database and config injection.
"""

from fastapi import Request
from .database import HoneypotDatabase

def get_db(request: Request) -> HoneypotDatabase:
    """Dependency to retrieve the initialized database instance from app state."""
    # Stored during lifespan
    return request.app.state.db

def get_config(request: Request) -> dict:
    """Dependency to retrieve config from app state."""
    return getattr(request.app.state, "config", {})
