from pydantic import BaseModel
from typing import Optional, List
from enum import Enum


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class XSSType(str, Enum):
    REFLECTED = "Reflected XSS"
    STORED = "Stored XSS"
    DOM = "DOM-based XSS"


class InjectionPoint(str, Enum):
    URL_PARAM = "URL Parameter"
    FORM_GET = "Form (GET)"
    FORM_POST = "Form (POST)"
    HEADER = "HTTP Header"
    JSON = "JSON API"


class XSSRequest(BaseModel):
    url: str
    timeout: Optional[int] = 10
    test_forms: Optional[bool] = True
    test_headers: Optional[bool] = True
    test_json: Optional[bool] = True

    class Config:
        json_schema_extra = {
            "example": {
                "url": "http://testphp.vulnweb.com/search.php?test=query",
                "timeout": 10,
                "test_forms": True,
                "test_headers": True,
                "test_json": True
            }
        }


class XSSFinding(BaseModel):
    xss_type: XSSType
    injection_point: InjectionPoint
    parameter: str
    payload: str
    evidence: str
    severity: SeverityLevel
    description: str
    remediation: str


class XSSSummary(BaseModel):
    total_parameters_tested: int
    total_payloads_tested: int
    vulnerabilities_found: int
    reflected_xss: int
    stored_xss: int
    dom_xss: int
    risk_level: SeverityLevel


class XSSResult(BaseModel):
    url: str
    scan_type: str = "XSS Scanner"
    status: str
    summary: XSSSummary
    findings: List[XSSFinding]
    errors: Optional[List[str]] = []