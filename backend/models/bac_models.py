from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from enum import Enum


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConfidenceLevel(str, Enum):
    HIGH = "high"      # Strong evidence: status change + sensitive content confirmed
    MEDIUM = "medium"  # Moderate evidence: status change OR significant body difference
    LOW = "low"        # Weak evidence: minor response difference, possible false positive


class BACType(str, Enum):
    IDOR = "IDOR"
    FORCED_BROWSING = "Forced Browsing"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    MISSING_AUTH = "Missing Authentication"
    METHOD_TAMPERING = "HTTP Method Tampering"


class BypassTechnique(str, Enum):
    PARAM_TAMPER = "Parameter Tampering"
    URL_MANIPULATION = "URL Path Manipulation"
    HEADER_BYPASS = "Header Bypass"
    COOKIE_TAMPER = "Cookie/Token Manipulation"


class BACRequest(BaseModel):
    url: str
    timeout: Optional[int] = 10
    cookies: Optional[Dict[str, str]] = Field(default_factory=dict)
    headers: Optional[Dict[str, str]] = Field(default_factory=dict)

    class Config:
        json_schema_extra = {
            "example": {
                "url": "http://testphp.vulnweb.com/userinfo.php?uid=1",
                "timeout": 10,
                "cookies": {"auth": "user_token"},
                "headers": {}
            }
        }


class BACFinding(BaseModel):
    check_type: BACType
    bypass_technique: BypassTechnique
    target_url: str
    method: str
    parameter: Optional[str] = None
    original_value: Optional[str] = None
    tampered_value: Optional[str] = None
    payloads_tested: Optional[List[str]] = Field(default_factory=list)
    evidence: str
    severity: SeverityLevel
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    description: str
    remediation: str


class BACSummary(BaseModel):
    total_checks: int
    vulnerabilities_found: int
    idor_findings: int
    forced_browsing_findings: int
    privilege_escalation_findings: int
    missing_auth_findings: int
    method_tampering_findings: int
    risk_level: SeverityLevel


class BACResult(BaseModel):
    url: str
    scan_type: str = "Broken Access Control"
    status: str
    summary: BACSummary
    findings: List[BACFinding]
    errors: Optional[List[str]] = []