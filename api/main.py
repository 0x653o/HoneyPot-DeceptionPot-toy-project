"""
FastAPI Application — Management API for the honeypot.

This server runs on a separate internal network (mgmt_net),
invisible from honeypot-facing ports. It provides:
- REST API for dashboard data
- WebSocket for live log streaming  
- Analysis endpoint for on-demand reports
"""

import os
import yaml
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .database import HoneypotDatabase
from .routes import dashboard, logs, analyze


def _load_config():
    """Load config.yaml for management settings."""
    config_path = os.environ.get("HONEYPOT_CONFIG", "config.yaml")
    if Path(config_path).exists():
        with open(config_path, "r") as f:
            return yaml.safe_load(f) or {}
    return {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: setup and teardown."""
    config = _load_config()

    # Initialize database
    db_path = config.get("logging", {}).get("db_file", "data/honeypot.db")
    db = HoneypotDatabase(db_path)

    # Inject database into route modules
    dashboard.set_database(db)
    logs.set_database(db)
    analyze.set_database(db)
    analyze.set_config(config)

    yield  # Application runs

    # Cleanup
    pass


# Create FastAPI app
app = FastAPI(
    title="Honeypot Management API",
    description=(
        "Internal management API for the honeypot system. "
        "This API is isolated on a management-only network and is NOT "
        "accessible from honeypot-facing ports."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS — only allow configured origins
config = _load_config()
cors_origins = config.get("management", {}).get("cors_origins", [
    "http://localhost:9090",
    "http://127.0.0.1:9090",
    "http://localhost:5173",  # Vite dev server
])

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include route modules
app.include_router(dashboard.router)
app.include_router(logs.router)
app.include_router(analyze.router)


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "honeypot-mgmt"}


# Serve Web UI static files if available (only when NOT behind Nginx)
# This must be LAST since it mounts on "/" and would catch everything
import os as _os
if not _os.environ.get("NGINX_PROXY"):
    web_dist = Path(__file__).parent.parent / "web" / "dist"
    if web_dist.exists():
        app.mount(
            "/",
            StaticFiles(directory=str(web_dist), html=True),
            name="web-ui",
        )

