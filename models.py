from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class DNSRecords(BaseModel):
    a: List[str] = []
    mx: List[str] = []
    ns: List[str] = []
    txt: List[str] = []
    ttl: Dict[str, int] = {}
    hosting_info: Optional[Dict[str, Any]] = None
    cdn: Optional[str] = None
    mx_provider: Optional[str] = None
    reverse_dns: Optional[str] = None

class EmailAuth(BaseModel):
    spf: Dict[str, Any] = {"exists": False, "valid": False, "raw": "", "size": 0, "includes_count": 0, "includes": []}
    dkim: Dict[str, Any] = {"exists": False, "selectors": []}
    dmarc: Dict[str, Any] = {"exists": False, "policy": "none", "raw": ""}
    bimi: Dict[str, Any] = {"exists": False, "raw": ""}
    google_verification: bool = False

class DomainMetadata(BaseModel):
    age_days: Optional[int] = None
    created_date: Optional[str] = None
    registrar: Optional[str] = None
    tld: str

class WebAnalysis(BaseModel):
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    https: bool = False
    title: Optional[str] = None
    meta_description: Optional[str] = None
    links_count: int = 0
    content_length: int = 0

class Reputation(BaseModel):
    blacklisted: bool = False
    blacklist_count: int = 0
    mx_quality: str = "Unknown"

class DomainReport(BaseModel):
    domain: str
    score: int = 0
    dns: DNSRecords
    email_auth: EmailAuth
    metadata: DomainMetadata
    web: WebAnalysis
    reputation: Reputation
    timestamp: datetime = Field(default_factory=datetime.now)

class ComparisonReport(BaseModel):
    best_domains: List[DomainReport]
    bad_domains: List[DomainReport]
    summary: Dict[str, Any]
    insights: List[str]
    differences: List[Dict[str, Any]]
    unique_factors: Dict[str, List[str]]

class AnalysisRequest(BaseModel):
    best: List[str]
    bad: List[str]
