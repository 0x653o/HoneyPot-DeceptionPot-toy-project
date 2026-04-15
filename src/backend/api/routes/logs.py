"""
Logs API routes + WebSocket live feed.
GET /api/logs — paginated log entries
GET /api/logs/recent — most recent connections
WS  /ws/live — real-time log stream
"""

import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect, Depends, Request

from ..dependencies import get_db
from ..database import HoneypotDatabase
from ..models import LogListResponse, IngestEventReq

router = APIRouter(tags=["logs"])

# Connected WebSocket clients
_ws_clients: set = set()


@router.get("/api/logs", response_model=LogListResponse)
async def get_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    protocol: Optional[str] = None,
    ip: Optional[str] = None,
    db: HoneypotDatabase = Depends(get_db)
):
    """Get paginated log entries."""
    try:
        return db.get_logs(
            page=page,
            per_page=per_page,
            protocol=protocol,
            ip=ip,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="Database not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/logs/recent")
async def get_recent_logs(
    limit: int = Query(10, ge=1, le=100),
    db: HoneypotDatabase = Depends(get_db)
):
    """Get most recent connections."""
    try:
        return db.get_recent_connections(limit=limit)
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="Database not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket, db: HoneypotDatabase = Depends(get_db)):
    """
    WebSocket endpoint for real-time log streaming.
    Polls the database for new connections and broadcasts to all clients.
    """
    await websocket.accept()
    _ws_clients.add(websocket)

    try:
        last_id = 0

        # Get current max ID
        try:
            db._ensure_db()
            conn = sqlite3.connect(db._db_path)
            cursor = conn.cursor()
            result = cursor.execute(
                "SELECT MAX(id) FROM connections"
            ).fetchone()
            last_id = result[0] or 0
            conn.close()
        except Exception:
            pass

        while True:
            # Check for new connections
            try:
                conn = sqlite3.connect(db._db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                new_entries = cursor.execute(
                    "SELECT * FROM connections WHERE id > ? "
                    "ORDER BY id ASC LIMIT 20",
                    (last_id,),
                ).fetchall()

                for entry in new_entries:
                    msg = {
                        "type": "connection",
                        "id": entry["id"],
                        "timestamp": entry["timestamp"],
                        "protocol": entry["protocol"],
                        "src_ip": entry["src_ip"],
                        "src_port": entry["src_port"],
                    }
                    await websocket.send_json(msg)
                    last_id = entry["id"]

                conn.close()
            except Exception:
                pass

            # Poll interval
            await asyncio.sleep(1)

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _ws_clients.discard(websocket)


# ==============================================================
# INTERNAL INGESTION API
# ==============================================================
# These endpoints are used by the child honeypots (Node, PHP, etc)
# to report attacks back to the central sqlite database.

@router.post("/api/internal/ingest/event")
async def ingest_event(
    req: IngestEventReq,
    request: Request,
    db: HoneypotDatabase = Depends(get_db)
):
    """Log an attack event from a polyglot honeypot."""
    # We verify API key at the router inclusion level, so if it 
    # reaches here it is already authenticated inside the mgmt_net.
    try:
        if req.event_type == "connection":
            db.insert_connection(req.session_id, req.ip, req.port, req.protocol, req.timestamp)
        else:
            # Always ensure the connection exists first, or just insert the event.
            # Realistically we should log the connection too if we want dashboard stats.
            db.insert_connection(req.session_id, req.ip, req.port, req.protocol, req.timestamp)
            db.insert_event(req.session_id, req.event_type, req.data, req.timestamp)
            
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
