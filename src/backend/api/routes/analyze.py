"""
Analysis API route.
POST /api/analyze — trigger full analysis and return JSON report.
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional

from ..dependencies import get_db, get_config
from ..database import HoneypotDatabase
from ..models import AnalysisReport

import sys
import os

router = APIRouter(prefix="/api", tags=["analysis"])


@router.post("/analyze")
async def run_analysis(
    protocol: Optional[str] = Query(None),
    top_n: int = Query(20, ge=1, le=100),
    enrich: bool = Query(True),
    db: HoneypotDatabase = Depends(get_db),
    _config: dict = Depends(get_config),
):
    """
    Run full analysis on the honeypot data.
    
    Returns a comprehensive JSON report with attacker details,
    payload analysis, credential statistics, and optionally
    IP enrichment (GeoIP + reverse DNS).
    """
    try:
        # Import analyzer modules
        from analyzer.parser import parse_log_from_db, parse_log_file
        from analyzer.enrichment import enrich_analysis_result
        from analyzer.report import generate_json_report

        # Try database first, fall back to log file
        try:
            db._ensure_db()
            result = parse_log_from_db(
                db._db_path,
                protocol_filter=protocol,
            )
        except FileNotFoundError:
            # Try log file
            log_path = "data/honeypot.log"
            if not os.path.exists(log_path):
                raise HTTPException(
                    status_code=503,
                    detail="No honeypot data available. "
                           "Start the honeypot to begin collecting data.",
                )
            result = parse_log_file(
                log_path,
                protocol_filter=protocol,
            )

        # Enrich with GeoIP/DNS if requested
        if enrich:
            geoip_path = None
            if _config:
                geoip_path = _config.get("geoip", {}).get("db_path")
            if not geoip_path:
                geoip_path = "data/GeoLite2-City.mmdb"
            
            if os.path.exists(geoip_path):
                enrich_analysis_result(result, geoip_path)
            else:
                enrich_analysis_result(result)

        # Generate report
        report = generate_json_report(result, top_n=top_n)
        return report

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")
