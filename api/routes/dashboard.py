"""
Dashboard API routes.
GET /api/stats — overall statistics
GET /api/attackers — paginated attacker list
GET /api/attackers/{ip} — single attacker detail
GET /api/credentials — paginated credential list
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional

from ..dependencies import get_db
from ..database import HoneypotDatabase
from ..models import (
    StatsResponse,
    AttackerListResponse,
    AttackerDetailResponse,
    CredentialListResponse,
)

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/stats", response_model=StatsResponse)
async def get_stats(db: HoneypotDatabase = Depends(get_db)):
    """Get overall honeypot statistics."""
    try:
        return db.get_stats()
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Honeypot database not available yet. "
                   "Start the honeypot to begin collecting data.",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attackers", response_model=AttackerListResponse)
async def get_attackers(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    sort_by: str = Query("count", pattern="^(count|recent)$"),
    protocol: Optional[str] = None,
    db: HoneypotDatabase = Depends(get_db)
):
    """Get paginated list of attacker IPs."""
    try:
        return db.get_attackers(
            page=page,
            per_page=per_page,
            sort_by=sort_by,
            protocol=protocol,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="Database not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attackers/{ip}", response_model=AttackerDetailResponse)
async def get_attacker_detail(ip: str, db: HoneypotDatabase = Depends(get_db)):
    """Get detailed information about a specific attacker."""
    try:
        result = db.get_attacker_detail(ip)
        if result is None:
            raise HTTPException(
                status_code=404, detail=f"No data for IP: {ip}"
            )
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/credentials", response_model=CredentialListResponse)
async def get_credentials(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    db: HoneypotDatabase = Depends(get_db)
):
    """Get paginated credential entries."""
    try:
        return db.get_credentials(page=page, per_page=per_page)
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="Database not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
