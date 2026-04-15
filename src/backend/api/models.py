"""
Pydantic models for the API request/response schemas.
"""

from pydantic import BaseModel
from typing import Optional, List, Dict


# --- Response Models ---

class StatsResponse(BaseModel):
    total_connections: int
    unique_attackers: int
    protocol_breakdown: Dict[str, int]
    total_credentials: int
    total_events: int
    connections_last_24h: int


class AttackerSummary(BaseModel):
    ip: str
    connection_count: int
    first_seen: str
    last_seen: str
    protocols: List[str]
    credential_count: int


class AttackerListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    attackers: List[AttackerSummary]


class CredentialEntry(BaseModel):
    timestamp: str
    protocol: str
    src_ip: Optional[str] = None
    username: str
    password: str


class EventEntry(BaseModel):
    timestamp: str
    event_type: str
    data: Optional[str]


class AttackerDetailResponse(BaseModel):
    ip: str
    total_connections: int
    first_seen: str
    last_seen: str
    protocols: List[str]
    credentials: List[CredentialEntry]
    events: List[EventEntry]


class LogEntry(BaseModel):
    id: int
    timestamp: str
    protocol: str
    src_ip: str
    src_port: int
    session_id: Optional[str]
    event_count: int
    cred_count: int


class LogListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    entries: List[LogEntry]


class PayloadEntry(BaseModel):
    payload: str
    count: int


class CredentialPairEntry(BaseModel):
    username: str
    password: str
    count: int
    protocols: List[str]


class AnalysisMetadata(BaseModel):
    total_connections: int
    total_unique_attackers: int
    protocol_breakdown: Dict[str, int]


class AttackerAnalysis(BaseModel):
    ip: str
    total_connections: int
    protocols: List[str]
    first_seen: str
    last_seen: str
    hostname: str
    location: str
    country_code: str
    latitude: Optional[float]
    longitude: Optional[float]
    top_payloads: List[PayloadEntry]
    credentials: List[dict]


class AnalysisReport(BaseModel):
    metadata: AnalysisMetadata
    top_payloads: List[PayloadEntry]
    top_credentials: List[CredentialPairEntry]
    attackers: List[AttackerAnalysis]


class RecentConnection(BaseModel):
    id: int
    timestamp: str
    protocol: str
    src_ip: str
    src_port: int


class CredentialListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    credentials: List[CredentialEntry]


# --- Ingestion Models ---

class IngestEventReq(BaseModel):
    session_id: str
    ip: str
    port: int
    protocol: str
    event_type: str
    data: str
    timestamp: Optional[str] = None
