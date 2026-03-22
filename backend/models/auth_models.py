from pydantic import BaseModel
from typing import Optional, List, Dict
from enum import Enum


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthCheckType(str, Enum):
    WEAK_CREDENTIALS = "Weak/Default Credentials"
    SESSION_TOKEN = "Session Token Analysis"
    SESSION_FIXATION = "Session Fixation"
    COOKIE_FLAGS = "Insecure Cookie Flags"
    PASSWORD_POLICY = "Password Policy"
    ACCOUNT_LOCKOUT = "Account Lockout"
    LOGIN_PROBE = "Login Endpoint Probe"
    TOKEN_EXPIRY = "Token Expiry & Invalidation"
    MULTI_SESSION = "Multi-Session Detection"


class AuthRequest(BaseModel):
    url: str
    login_path: Optional[str] = "/login"
    username_field: Optional[str] = "username"
    password_field: Optional[str] = "password"
    timeout: Optional[int] = 10
    cookies: Optional[Dict[str, str]] = {}

    class Config:
        json_schema_extra = {
            "example": {
                "url": "http://testphp.vulnweb.com",
                "login_path": "/login",
                "username_field": "uname",
                "password_field": "pass",
                "timeout": 10,
                "cookies": {}
            }
        }


class CookieDetail(BaseModel):
    name: str
    value_sample: str
    http_only: bool
    secure: bool
    same_site: Optional[str]
    path: Optional[str]
    domain: Optional[str]
    expires: Optional[str]
    issues: List[str]


class TokenEntropyDetail(BaseModel):
    token_sample: str
    length: int
    entropy_bits: float
    is_predictable: bool
    charset_analysis: str


class AuthFinding(BaseModel):
    check_type: AuthCheckType
    target_url: str
    evidence: str
    severity: SeverityLevel
    description: str
    remediation: str
    detail: Optional[Dict] = {}


class AuthSummary(BaseModel):
    total_checks: int
    vulnerabilities_found: int
    weak_credentials: int
    session_issues: int
    cookie_issues: int
    lockout_issues: int
    policy_issues: int
    risk_level: SeverityLevel


class AuthResult(BaseModel):
    url: str
    scan_type: str = "Broken Authentication & Session Management"
    status: str
    summary: AuthSummary
    findings: List[AuthFinding]
    cookie_details: Optional[List[CookieDetail]] = []
    token_analysis: Optional[List[TokenEntropyDetail]] = []
    errors: Optional[List[str]] = []