from pydantic import BaseModel
from typing import Optional, List, Dict
from enum import Enum


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SSLCheckType(str, Enum):
    CERTIFICATE = "Certificate Validity & Expiry"
    CIPHER_SUITE = "Weak Cipher Suites"
    PROTOCOL_VERSION = "Outdated Protocol Version"
    HSTS = "HSTS"
    CERT_CHAIN = "Certificate Chain & Trust"
    MIXED_CONTENT = "Mixed Content"
    BEAST = "BEAST Attack"
    POODLE = "POODLE Attack"
    HEARTBLEED = "Heartbleed"
    CRIME_BREACH = "CRIME/BREACH"


class CertificateDetail(BaseModel):
    subject: Dict[str, str]
    issuer: Dict[str, str]
    serial_number: str
    not_before: str
    not_after: str
    days_until_expiry: int
    is_expired: bool
    is_self_signed: bool
    san_domains: List[str]
    signature_algorithm: str
    key_size: Optional[int] = None
    key_type: Optional[str] = None


class ProtocolSupport(BaseModel):
    sslv2: bool = False
    sslv3: bool = False
    tls10: bool = False
    tls11: bool = False
    tls12: bool = False
    tls13: bool = False


class CipherDetail(BaseModel):
    name: str
    protocol: str
    key_exchange: Optional[str]
    authentication: Optional[str]
    encryption: Optional[str]
    bits: Optional[int]
    is_weak: bool
    weakness_reason: Optional[str]


class SSLFinding(BaseModel):
    check_type: SSLCheckType
    target: str
    evidence: str
    severity: SeverityLevel
    description: str
    remediation: str
    detail: Optional[Dict] = {}


class SSLSummary(BaseModel):
    total_checks: int
    vulnerabilities_found: int
    certificate_issues: int
    protocol_issues: int
    cipher_issues: int
    hsts_issues: int
    known_vuln_issues: int
    mixed_content_issues: int
    grade: str
    risk_level: SeverityLevel


class SSLRequest(BaseModel):
    url: str
    timeout: Optional[int] = 10

    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://example.com",
                "timeout": 10
            }
        }


class SSLResult(BaseModel):
    url: str
    scan_type: str = "SSL/TLS Analysis"
    status: str
    summary: SSLSummary
    findings: List[SSLFinding]
    certificate: Optional[CertificateDetail] = None
    protocol_support: Optional[ProtocolSupport] = None
    ciphers: Optional[List[CipherDetail]] = []
    errors: Optional[List[str]] = []