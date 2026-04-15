"""
IP Enrichment — GeoIP + Reverse DNS lookups (public APIs only).

Uses:
- MaxMind GeoLite2-City.mmdb (free, offline, no API key at runtime)
- System DNS for reverse lookups (no external API)

Caches results per IP to avoid redundant lookups.
"""

import socket
import logging
from typing import Optional, Dict
from pathlib import Path

logger = logging.getLogger("analyzer.enrichment")

# Global GeoIP reader (loaded once)
_geoip_reader = None


def init_geoip(db_path: str) -> bool:
    """
    Initialize the GeoIP database reader.
    
    Args:
        db_path: Path to GeoLite2-City.mmdb file.
        
    Returns:
        True if successfully loaded, False otherwise.
    """
    global _geoip_reader

    if not Path(db_path).exists():
        logger.warning(f"GeoIP database not found at: {db_path}")
        return False

    try:
        import geoip2.database
        _geoip_reader = geoip2.database.Reader(db_path)
        logger.info(f"GeoIP database loaded from {db_path}")
        return True
    except ImportError:
        logger.warning(
            "geoip2 library not installed. "
            "Run 'pip install geoip2' for geolocation support."
        )
        return False
    except Exception as e:
        logger.error(f"Failed to load GeoIP database: {e}")
        return False


def close_geoip():
    """Close the GeoIP database reader."""
    global _geoip_reader
    if _geoip_reader:
        try:
            _geoip_reader.close()
        except Exception:
            pass
        _geoip_reader = None


# Cache for IP lookups
_ip_cache: Dict[str, dict] = {}


def get_ip_info(ip_address: str, use_cache: bool = True) -> dict:
    """
    Gather enrichment data for an IP address.
    
    Returns:
        Dict with keys: hostname, city, country, country_code, latitude,
        longitude, org, asn.
    """
    if use_cache and ip_address in _ip_cache:
        return _ip_cache[ip_address]

    info = {
        "hostname": "N/A",
        "city": "N/A",
        "country": "N/A",
        "country_code": "N/A",
        "latitude": None,
        "longitude": None,
        "org": "N/A",
        "asn": "N/A",
        "location": "N/A",
    }

    # 1. Reverse DNS lookup
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        info["hostname"] = hostname
    except socket.herror:
        info["hostname"] = "No reverse DNS record"
    except socket.gaierror:
        info["hostname"] = "DNS resolution failed"
    except Exception as e:
        info["hostname"] = f"DNS Error: {type(e).__name__}"

    # 2. GeoIP lookup
    if _geoip_reader:
        try:
            response = _geoip_reader.city(ip_address)
            info["city"] = response.city.name or "Unknown City"
            info["country"] = response.country.name or "Unknown Country"
            info["country_code"] = response.country.iso_code or "??"
            info["latitude"] = response.location.latitude
            info["longitude"] = response.location.longitude
            info["location"] = f"{info['city']}, {info['country']}"

            # ASN info if available
            if hasattr(response, "traits"):
                info["org"] = getattr(
                    response.traits, "organization", "N/A"
                ) or "N/A"
                info["asn"] = getattr(
                    response.traits, "autonomous_system_number", "N/A"
                ) or "N/A"

        except Exception as e:
            info["location"] = "Local/Private IP or DB Error"

    # Build location string
    if info["location"] == "N/A" and info["city"] != "N/A":
        info["location"] = f"{info['city']}, {info['country']}"

    # Cache result
    if use_cache:
        _ip_cache[ip_address] = info

    return info


def enrich_analysis_result(result, geoip_db_path: Optional[str] = None):
    """
    Enrich an AnalysisResult by adding IP info to all IP summaries.
    
    Args:
        result: AnalysisResult from parser.
        geoip_db_path: Optional path to GeoLite2 database.
    """
    if geoip_db_path:
        init_geoip(geoip_db_path)

    for ip, summary in result.ip_summaries.items():
        logger.info(f"Enriching IP: {ip}")
        summary.info = get_ip_info(ip)

    if geoip_db_path:
        close_geoip()


def clear_cache():
    """Clear the IP info cache."""
    global _ip_cache
    _ip_cache.clear()
