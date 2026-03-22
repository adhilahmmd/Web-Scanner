from pydantic import BaseModel
from typing import Optional, List, Dict
from enum import Enum


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HeaderCheckType(str, Enum):
    CSP = "Content-Security-Policy"
    X_FRAME = "X-Frame-Options"
    X_CONTENT_TYPE = "X-Content-Type-Options"
    REFERRER = "Referrer-Policy"
    PERMISSIONS = "Permissions-Policy"
    XSS_PROTECTION = "X-XSS-Protection"
    INFO_LEAK = "Information Leaking Header"
    MISCONFIGURATION = "Header Misconfiguration"


class HeaderStatus(str, Enum):
    PRESENT = "present"
    MISSING = "missing"
    MISCONFIGURED = "misconfigured"
    WEAK = "weak"


class HeaderDetail(BaseModel):
    name: str
    status: HeaderStatus
    value: Optional[str] = None
    issues: List[str] = []
    recommendations: List[str] = []


class CSPAnalysis(BaseModel):
    raw_value: str
    directives: Dict[str, str]
    has_unsafe_inline: bool
    has_unsafe_eval: bool
    has_wildcard: bool
    has_http_sources: bool
    missing_directives: List[str]
    weak_directives: List[str]
    score: int  # 0–100


class InfoLeakDetail(BaseModel):
    header_name: str
    value: str
    leaked_info: str
    severity: SeverityLevel


class HeaderFinding(BaseModel):
    check_type: HeaderCheckType
    target_url: str
    header_name: str
    status: HeaderStatus
    evidence: str
    severity: SeverityLevel
    description: str
    remediation: str
    detail: Optional[Dict] = {}


class HeaderSummary(BaseModel):
    total_headers_checked: int
    headers_present: int
    headers_missing: int
    headers_misconfigured: int
    vulnerabilities_found: int
    info_leaks_found: int
    csp_score: Optional[int] = None
    security_score: int  # 0–100 overall
    grade: str
    risk_level: SeverityLevel


class HeaderRequest(BaseModel):
    url: str
    timeout: Optional[int] = 10
    follow_redirects: Optional[bool] = True

    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://example.com",
                "timeout": 10,
                "follow_redirects": True
            }
        }


class HeaderResult(BaseModel):
    url: str
    scan_type: str = "HTTP Security Headers"
    status: str
    summary: HeaderSummary
    findings: List[HeaderFinding]
    header_details: List[HeaderDetail]
    csp_analysis: Optional[CSPAnalysis] = None
    info_leaks: List[InfoLeakDetail] = []
    raw_headers: Dict[str, str] = {}
    errors: Optional[List[str]] = []