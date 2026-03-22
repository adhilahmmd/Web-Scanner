from pydantic import BaseModel, HttpUrl
from typing import Optional, List
from enum import Enum


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanRequest(BaseModel):
    url: str
    timeout: Optional[int] = 10
    crawl_forms: Optional[bool] = False

    class Config:
        json_schema_extra = {
            "example": {
                "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
                "timeout": 10,
                "crawl_forms": False
            }
        }


class VulnerabilityFinding(BaseModel):
    parameter: str
    payload: str
    evidence: str
    severity: SeverityLevel
    description: str
    remediation: str


class ScanSummary(BaseModel):
    total_parameters: int
    total_payloads_tested: int
    vulnerabilities_found: int
    risk_level: SeverityLevel


class ScanResult(BaseModel):
    url: str
    scan_type: str = "SQL Injection"
    status: str
    summary: ScanSummary
    findings: List[VulnerabilityFinding]
    errors: Optional[List[str]] = []