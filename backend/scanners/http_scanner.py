"""
HTTP Security Headers Scanner Module

Checks:
1. Content-Security-Policy    — presence + deep directive analysis
2. X-Frame-Options            — presence + value validation
3. X-Content-Type-Options     — presence + nosniff check
4. Referrer-Policy            — presence + privacy-level grading
5. Permissions-Policy         — presence + dangerous feature exposure
6. X-XSS-Protection           — presence + value + deprecation note
7. Information-Leaking Headers— Server, X-Powered-By, X-AspNet-Version etc.
8. Misconfiguration Analysis  — wrong values, conflicting directives
"""

import httpx
import asyncio
from urllib.parse import urlparse
from typing import List, Dict, Optional, Tuple
from models.http_models import (
    HeaderFinding, HeaderSummary, HeaderDetail,
    CSPAnalysis, InfoLeakDetail,
    HeaderCheckType, HeaderStatus, SeverityLevel
)


# ──────────────────────────────────────────────
# Security header definitions & expected values
# ──────────────────────────────────────────────

SECURITY_HEADERS = {
    "content-security-policy": {
        "display": "Content-Security-Policy",
        "check_type": HeaderCheckType.CSP,
        "missing_severity": SeverityLevel.HIGH,
        "description": "CSP prevents XSS and data injection by controlling allowed resource origins.",
    },
    "x-frame-options": {
        "display": "X-Frame-Options",
        "check_type": HeaderCheckType.X_FRAME,
        "missing_severity": SeverityLevel.MEDIUM,
        "description": "Prevents clickjacking by controlling whether the page can be embedded in a frame.",
    },
    "x-content-type-options": {
        "display": "X-Content-Type-Options",
        "check_type": HeaderCheckType.X_CONTENT_TYPE,
        "missing_severity": SeverityLevel.MEDIUM,
        "description": "Prevents MIME-type sniffing attacks by forcing declared content type.",
    },
    "referrer-policy": {
        "display": "Referrer-Policy",
        "check_type": HeaderCheckType.REFERRER,
        "missing_severity": SeverityLevel.LOW,
        "description": "Controls how much referrer information is sent with requests.",
    },
    "permissions-policy": {
        "display": "Permissions-Policy",
        "check_type": HeaderCheckType.PERMISSIONS,
        "missing_severity": SeverityLevel.LOW,
        "description": "Controls access to browser features like camera, microphone, geolocation.",
    },
    "x-xss-protection": {
        "display": "X-XSS-Protection",
        "check_type": HeaderCheckType.XSS_PROTECTION,
        "missing_severity": SeverityLevel.LOW,
        "description": "Legacy XSS filter for older browsers — should be set to disable or mode=block.",
    },
}

# ──────────────────────────────────────────────
# CSP analysis configuration
# ──────────────────────────────────────────────

CSP_IMPORTANT_DIRECTIVES = [
    "default-src", "script-src", "style-src", "img-src",
    "connect-src", "font-src", "object-src", "media-src",
    "frame-src", "frame-ancestors", "base-uri", "form-action",
    "upgrade-insecure-requests", "block-all-mixed-content",
]

CSP_MUST_HAVE = ["default-src", "script-src", "object-src"]

UNSAFE_CSP_KEYWORDS = ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'"]

WEAK_REFERRER_VALUES = [
    "unsafe-url",
    "no-referrer-when-downgrade",
]

STRONG_REFERRER_VALUES = [
    "no-referrer",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "same-origin",
]

# Information-leaking headers and what they reveal
INFO_LEAK_HEADERS = {
    "server": "Web server software and version",
    "x-powered-by": "Backend language/framework and version",
    "x-aspnet-version": "ASP.NET version",
    "x-aspnetmvc-version": "ASP.NET MVC version",
    "x-generator": "CMS or framework generator",
    "x-drupal-cache": "Drupal CMS fingerprint",
    "x-wp-nonce": "WordPress fingerprint",
    "x-joomla-version": "Joomla CMS version",
    "via": "Proxy server information",
    "x-runtime": "Application runtime (Ruby on Rails)",
    "x-version": "Application version",
    "x-debug": "Debug mode indicator",
    "x-request-id": "Internal request tracking (minor)",
    "x-correlation-id": "Internal correlation ID (minor)",
}

# Dangerous Permissions-Policy features
DANGEROUS_PERMISSIONS = [
    "camera", "microphone", "geolocation", "payment",
    "usb", "bluetooth", "midi", "magnetometer",
    "accelerometer", "gyroscope", "ambient-light-sensor",
    "display-capture", "screen-wake-lock", "serial",
]


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def calculate_security_score(findings: List[HeaderFinding], total_checks: int) -> int:
    """Score 0–100 based on findings severity."""
    penalty = 0
    for f in findings:
        if f.severity == SeverityLevel.CRITICAL:
            penalty += 25
        elif f.severity == SeverityLevel.HIGH:
            penalty += 15
        elif f.severity == SeverityLevel.MEDIUM:
            penalty += 8
        elif f.severity == SeverityLevel.LOW:
            penalty += 3
        elif f.severity == SeverityLevel.INFO:
            penalty += 1
    return max(0, 100 - penalty)


def score_to_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    elif score >= 85:
        return "A"
    elif score >= 75:
        return "B+"
    elif score >= 65:
        return "B"
    elif score >= 50:
        return "C"
    elif score >= 35:
        return "D"
    return "F"


def calculate_risk(findings: List[HeaderFinding]) -> SeverityLevel:
    if not findings:
        return SeverityLevel.LOW
    severities = [f.severity for f in findings]
    if SeverityLevel.CRITICAL in severities:
        return SeverityLevel.CRITICAL
    if SeverityLevel.HIGH in severities:
        return SeverityLevel.HIGH
    if SeverityLevel.MEDIUM in severities:
        return SeverityLevel.MEDIUM
    if SeverityLevel.LOW in severities:
        return SeverityLevel.LOW
    return SeverityLevel.INFO


def parse_csp(csp_value: str) -> Dict[str, str]:
    """Parse CSP string into directive → value dict."""
    directives = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split(None, 1)
        directive = tokens[0].lower()
        value = tokens[1] if len(tokens) > 1 else ""
        directives[directive] = value
    return directives


def analyze_csp(csp_value: str) -> CSPAnalysis:
    """Deep analysis of CSP directive values."""
    directives = parse_csp(csp_value)
    csp_lower = csp_value.lower()

    has_unsafe_inline = "'unsafe-inline'" in csp_lower
    has_unsafe_eval = "'unsafe-eval'" in csp_lower
    has_wildcard = (
        "* " in csp_value or
        csp_value.strip().endswith("*") or
        " *;" in csp_value
    )
    has_http_sources = "http://" in csp_lower

    missing_directives = [d for d in CSP_MUST_HAVE if d not in directives]
    weak_directives = []

    for directive, value in directives.items():
        val_lower = value.lower()
        if "'unsafe-inline'" in val_lower:
            weak_directives.append(f"{directive}: contains 'unsafe-inline'")
        if "'unsafe-eval'" in val_lower:
            weak_directives.append(f"{directive}: contains 'unsafe-eval'")
        if "http://" in val_lower:
            weak_directives.append(f"{directive}: allows HTTP sources")
        if val_lower.strip() == "*":
            weak_directives.append(f"{directive}: wildcard (*) allows any source")
        if "data:" in val_lower and directive == "script-src":
            weak_directives.append(f"{directive}: data: URI allows inline script injection")

    # Score CSP quality (0–100)
    score = 100
    if has_unsafe_inline:
        score -= 30
    if has_unsafe_eval:
        score -= 25
    if has_wildcard:
        score -= 20
    if has_http_sources:
        score -= 10
    score -= len(missing_directives) * 10
    score -= len(weak_directives) * 5
    score = max(0, score)

    return CSPAnalysis(
        raw_value=csp_value,
        directives=directives,
        has_unsafe_inline=has_unsafe_inline,
        has_unsafe_eval=has_unsafe_eval,
        has_wildcard=has_wildcard,
        has_http_sources=has_http_sources,
        missing_directives=missing_directives,
        weak_directives=weak_directives,
        score=score,
    )


# ──────────────────────────────────────────────
# 1. Content-Security-Policy
# ──────────────────────────────────────────────

def check_csp(
    headers: Dict[str, str],
    url: str,
    findings: List[HeaderFinding],
    header_details: List[HeaderDetail],
    checks: List[str],
) -> Optional[CSPAnalysis]:
    checks.append("CSP")
    csp_value = headers.get("content-security-policy", "")
    csp_ro = headers.get("content-security-policy-report-only", "")
    issues = []
    recommendations = []
    csp_analysis = None

    if not csp_value:
        status = HeaderStatus.MISSING
        if csp_ro:
            # Report-only only — not enforced
            issues.append("Only Content-Security-Policy-Report-Only is set — not enforced")
            recommendations.append("Switch to Content-Security-Policy to enforce the policy")
            severity = SeverityLevel.MEDIUM
            evidence = "CSP is in report-only mode — not enforced, XSS not mitigated"
        else:
            recommendations.append(
                "Add: Content-Security-Policy: default-src 'self'; "
                "script-src 'self'; object-src 'none'; base-uri 'self'"
            )
            severity = SeverityLevel.HIGH
            evidence = "Content-Security-Policy header is completely absent"

        findings.append(HeaderFinding(
            check_type=HeaderCheckType.CSP,
            target_url=url,
            header_name="Content-Security-Policy",
            status=status,
            evidence=evidence,
            severity=severity,
            description=(
                "No Content-Security-Policy header is present. "
                "CSP is the primary defence against XSS attacks. "
                "Without it, injected scripts execute without restriction."
            ),
            remediation=(
                "Implement a strict CSP. Start with: "
                "Content-Security-Policy: default-src 'self'; "
                "script-src 'self'; style-src 'self'; "
                "object-src 'none'; base-uri 'self'; form-action 'self'"
            ),
            detail={"report_only": bool(csp_ro)},
        ))
    else:
        csp_analysis = analyze_csp(csp_value)

        # Report individual weak directives
        if csp_analysis.has_unsafe_inline:
            issues.append("'unsafe-inline' in script-src bypasses XSS protection")
            findings.append(HeaderFinding(
                check_type=HeaderCheckType.CSP,
                target_url=url,
                header_name="Content-Security-Policy",
                status=HeaderStatus.WEAK,
                evidence=f"CSP contains 'unsafe-inline': {csp_value[:120]}",
                severity=SeverityLevel.HIGH,
                description=(
                    "'unsafe-inline' allows execution of inline scripts/styles. "
                    "This effectively negates XSS protection provided by CSP."
                ),
                remediation=(
                    "Remove 'unsafe-inline'. Use nonces or hashes instead: "
                    "script-src 'nonce-{random}' or script-src 'sha256-{hash}'"
                ),
                detail={"directive_value": csp_value[:200]},
            ))

        if csp_analysis.has_unsafe_eval:
            issues.append("'unsafe-eval' allows dynamic code execution")
            findings.append(HeaderFinding(
                check_type=HeaderCheckType.CSP,
                target_url=url,
                header_name="Content-Security-Policy",
                status=HeaderStatus.WEAK,
                evidence=f"CSP contains 'unsafe-eval'",
                severity=SeverityLevel.HIGH,
                description=(
                    "'unsafe-eval' permits eval(), setTimeout(string), "
                    "new Function() — all common XSS vectors."
                ),
                remediation=(
                    "Remove 'unsafe-eval'. Refactor code to avoid eval(). "
                    "Use JSON.parse() instead of eval() for data parsing."
                ),
                detail={},
            ))

        if csp_analysis.has_wildcard:
            issues.append("Wildcard (*) source allows any origin")
            findings.append(HeaderFinding(
                check_type=HeaderCheckType.CSP,
                target_url=url,
                header_name="Content-Security-Policy",
                status=HeaderStatus.WEAK,
                evidence="CSP uses wildcard (*) source — any domain allowed",
                severity=SeverityLevel.HIGH,
                description=(
                    "A wildcard source in CSP allows resources from any domain, "
                    "defeating the purpose of the policy."
                ),
                remediation=(
                    "Replace '*' with explicit trusted domains. "
                    "Use 'self' for same-origin resources."
                ),
                detail={},
            ))

        if csp_analysis.missing_directives:
            issues.append(f"Missing directives: {', '.join(csp_analysis.missing_directives)}")
            findings.append(HeaderFinding(
                check_type=HeaderCheckType.CSP,
                target_url=url,
                header_name="Content-Security-Policy",
                status=HeaderStatus.MISCONFIGURED,
                evidence=f"CSP missing key directives: {', '.join(csp_analysis.missing_directives)}",
                severity=SeverityLevel.MEDIUM,
                description=(
                    f"The CSP is missing: {', '.join(csp_analysis.missing_directives)}. "
                    "Missing directives inherit from default-src or fall back to allow-all."
                ),
                remediation=(
                    "Add missing directives explicitly. "
                    "Use 'object-src: none' to block Flash/plugins. "
                    "Use 'base-uri: self' to prevent base tag injection."
                ),
                detail={"missing": csp_analysis.missing_directives},
            ))

        if csp_analysis.has_http_sources:
            findings.append(HeaderFinding(
                check_type=HeaderCheckType.CSP,
                target_url=url,
                header_name="Content-Security-Policy",
                status=HeaderStatus.WEAK,
                evidence="CSP allows HTTP (non-HTTPS) resource sources",
                severity=SeverityLevel.MEDIUM,
                description=(
                    "CSP permits loading resources over plain HTTP. "
                    "An attacker could intercept and tamper with HTTP resources."
                ),
                remediation=(
                    "Replace all http:// sources with https:// equivalents. "
                    "Add 'upgrade-insecure-requests' directive."
                ),
                detail={},
            ))

        if csp_analysis.score >= 80:
            status = HeaderStatus.PRESENT
        elif csp_analysis.score >= 50:
            status = HeaderStatus.WEAK
        else:
            status = HeaderStatus.MISCONFIGURED

        if not issues:
            recommendations.append("CSP is well configured — consider adding 'upgrade-insecure-requests'")

    header_details.append(HeaderDetail(
        name="Content-Security-Policy",
        status=status if csp_value else HeaderStatus.MISSING,
        value=csp_value[:200] if csp_value else None,
        issues=issues,
        recommendations=recommendations,
    ))

    return csp_analysis


# ──────────────────────────────────────────────
# 2. X-Frame-Options
# ──────────────────────────────────────────────

def check_x_frame_options(
    headers: Dict[str, str],
    url: str,
    findings: List[HeaderFinding],
    header_details: List[HeaderDetail],
    checks: List[str],
):
    checks.append("X-FRAME-OPTIONS")
    value = headers.get("x-frame-options", "")
    issues = []
    recommendations = []

    if not value:
        # Check if CSP frame-ancestors covers this
        csp = headers.get("content-security-policy", "")
        if "frame-ancestors" in csp.lower():
            header_details.append(HeaderDetail(
                name="X-Frame-Options",
                status=HeaderStatus.MISSING,
                value=None,
                issues=["Header absent but CSP frame-ancestors provides equivalent protection"],
                recommendations=["Consider adding X-Frame-Options for legacy browser support"],
            ))
            return

        findings.append(HeaderFinding(
            check_type=HeaderCheckType.X_FRAME,
            target_url=url,
            header_name="X-Frame-Options",
            status=HeaderStatus.MISSING,
            evidence="X-Frame-Options header is absent — page can be embedded in iframes",
            severity=SeverityLevel.MEDIUM,
            description=(
                "Without X-Frame-Options, the page can be embedded in an iframe on any domain. "
                "This enables clickjacking attacks where users are tricked into clicking hidden elements."
            ),
            remediation=(
                "Add: X-Frame-Options: DENY  (never allow framing) "
                "or X-Frame-Options: SAMEORIGIN  (only same domain). "
                "Modern alternative: CSP frame-ancestors 'none' or 'self'"
            ),
            detail={},
        ))
        issues.append("Header absent — clickjacking possible")
        recommendations.append("Add X-Frame-Options: DENY or SAMEORIGIN")
        status = HeaderStatus.MISSING

    else:
        val_upper = value.strip().upper()

        if val_upper == "DENY":
            status = HeaderStatus.PRESENT
            recommendations.append("Good — DENY blocks all framing")
        elif val_upper == "SAMEORIGIN":
            status = HeaderStatus.PRESENT
            recommendations.append("Good — SAMEORIGIN allows only same-origin framing")
        elif val_upper.startswith("ALLOW-FROM"):
            status = HeaderStatus.MISCONFIGURED
            issues.append("ALLOW-FROM is deprecated and not supported in Chrome/Firefox")
            findings.append(HeaderFinding(
                check_type=HeaderCheckType.X_FRAME,
                target_url=url,
                header_name="X-Frame-Options",
                status=HeaderStatus.MISCONFIGURED,
                evidence=f"X-Frame-Options uses deprecated ALLOW-FROM directive: '{value}'",
                severity=SeverityLevel.MEDIUM,
                description=(
                    "ALLOW-FROM is not supported in Chrome or Firefox. "
                    "Pages using it are unprotected in those browsers."
                ),
                remediation=(
                    "Replace ALLOW-FROM with CSP: "
                    "Content-Security-Policy: frame-ancestors 'self' https://trusted-domain.com"
                ),
                detail={"value": value},
            ))
        else:
            status = HeaderStatus.MISCONFIGURED
            issues.append(f"Unrecognised value: '{value}' — expected DENY or SAMEORIGIN")
            findings.append(HeaderFinding(
                check_type=HeaderCheckType.X_FRAME,
                target_url=url,
                header_name="X-Frame-Options",
                status=HeaderStatus.MISCONFIGURED,
                evidence=f"X-Frame-Options has invalid value: '{value}'",
                severity=SeverityLevel.MEDIUM,
                description=f"'{value}' is not a valid X-Frame-Options value.",
                remediation="Use: X-Frame-Options: DENY or SAMEORIGIN",
                detail={"value": value},
            ))

    header_details.append(HeaderDetail(
        name="X-Frame-Options",
        status=status,
        value=value or None,
        issues=issues,
        recommendations=recommendations,
    ))


# ──────────────────────────────────────────────
# 3. X-Content-Type-Options
# ──────────────────────────────────────────────

def check_x_content_type(
    headers: Dict[str, str],
    url: str,
    findings: List[HeaderFinding],
    header_details: List[HeaderDetail],
    checks: List[str],
):
    checks.append("X-CONTENT-TYPE-OPTIONS")
    value = headers.get("x-content-type-options", "")
    issues = []
    recommendations = []

    if not value:
        status = HeaderStatus.MISSING
        issues.append("Missing — browsers may MIME-sniff responses")
        recommendations.append("Add: X-Content-Type-Options: nosniff")
        findings.append(HeaderFinding(
            check_type=HeaderCheckType.X_CONTENT_TYPE,
            target_url=url,
            header_name="X-Content-Type-Options",
            status=HeaderStatus.MISSING,
            evidence="X-Content-Type-Options header is absent",
            severity=SeverityLevel.MEDIUM,
            description=(
                "Without X-Content-Type-Options: nosniff, browsers may interpret "
                "files differently from their declared Content-Type. "
                "An attacker could serve a script as an image to bypass CSP."
            ),
            remediation="Add: X-Content-Type-Options: nosniff",
            detail={},
        ))
    elif value.strip().lower() != "nosniff":
        status = HeaderStatus.MISCONFIGURED
        issues.append(f"Invalid value '{value}' — only 'nosniff' is valid")
        findings.append(HeaderFinding(
            check_type=HeaderCheckType.X_CONTENT_TYPE,
            target_url=url,
            header_name="X-Content-Type-Options",
            status=HeaderStatus.MISCONFIGURED,
            evidence=f"X-Content-Type-Options has invalid value: '{value}'",
            severity=SeverityLevel.LOW,
            description=f"The only valid value is 'nosniff'. '{value}' provides no protection.",
            remediation="Change to: X-Content-Type-Options: nosniff",
            detail={"value": value},
        ))
    else:
        status = HeaderStatus.PRESENT
        recommendations.append("nosniff is correctly set")

    header_details.append(HeaderDetail(
        name="X-Content-Type-Options",
        status=status,
        value=value or None,
        issues=issues,
        recommendations=recommendations,
    ))


# ──────────────────────────────────────────────
# 4. Referrer-Policy
# ──────────────────────────────────────────────

def check_referrer_policy(
    headers: Dict[str, str],
    url: str,
    findings: List[HeaderFinding],
    header_details: List[HeaderDetail],
    checks: List[str],
):
    checks.append("REFERRER-POLICY")
    value = headers.get("referrer-policy", "")
    issues = []
    recommendations = []

    if not value:
        status = HeaderStatus.MISSING
        issues.append("Missing — browser default may leak URLs in Referer header")
        recommendations.append("Add: Referrer-Policy: strict-origin-when-cross-origin")
        findings.append(HeaderFinding(
            check_type=HeaderCheckType.REFERRER,
            target_url=url,
            header_name="Referrer-Policy",
            status=HeaderStatus.MISSING,
            evidence="Referrer-Policy header is absent",
            severity=SeverityLevel.LOW,
            description=(
                "Without Referrer-Policy, the browser sends the full Referer URL "
                "to third-party sites, potentially leaking sensitive path/query parameters."
            ),
            remediation=(
                "Add: Referrer-Policy: strict-origin-when-cross-origin "
                "or 'no-referrer' for maximum privacy."
            ),
            detail={},
        ))
    else:
        val_lower = value.strip().lower()
        if val_lower in WEAK_REFERRER_VALUES:
            status = HeaderStatus.WEAK
            issues.append(f"'{value}' leaks full URLs to cross-origin destinations")
            findings.append(HeaderFinding(
                check_type=HeaderCheckType.REFERRER,
                target_url=url,
                header_name="Referrer-Policy",
                status=HeaderStatus.WEAK,
                evidence=f"Referrer-Policy set to weak value: '{value}'",
                severity=SeverityLevel.MEDIUM,
                description=(
                    f"'{value}' sends the full URL including path and query string "
                    "to third-party sites. This may leak tokens, user IDs, or sensitive paths."
                ),
                remediation=(
                    "Change to: Referrer-Policy: strict-origin-when-cross-origin "
                    "or no-referrer"
                ),
                detail={"current_value": value},
            ))
        elif val_lower in STRONG_REFERRER_VALUES:
            status = HeaderStatus.PRESENT
            recommendations.append(f"Good — '{value}' provides strong referrer protection")
        else:
            status = HeaderStatus.PRESENT
            recommendations.append(f"Value '{value}' is acceptable")

    header_details.append(HeaderDetail(
        name="Referrer-Policy",
        status=status,
        value=value or None,
        issues=issues,
        recommendations=recommendations,
    ))


# ──────────────────────────────────────────────
# 5. Permissions-Policy
# ──────────────────────────────────────────────

def check_permissions_policy(
    headers: Dict[str, str],
    url: str,
    findings: List[HeaderFinding],
    header_details: List[HeaderDetail],
    checks: List[str],
):
    checks.append("PERMISSIONS-POLICY")
    # Also check old name Feature-Policy
    value = (
        headers.get("permissions-policy", "") or
        headers.get("feature-policy", "")
    )
    issues = []
    recommendations = []

    if not value:
        status = HeaderStatus.MISSING
        issues.append("Missing — browser features like camera/mic unrestricted")
        recommendations.append(
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
        )
        findings.append(HeaderFinding(
            check_type=HeaderCheckType.PERMISSIONS,
            target_url=url,
            header_name="Permissions-Policy",
            status=HeaderStatus.MISSING,
            evidence="Permissions-Policy (and Feature-Policy) header is absent",
            severity=SeverityLevel.LOW,
            description=(
                "Without Permissions-Policy, the page and embedded iframes may access "
                "sensitive browser features (camera, mic, geolocation, payment) by default."
            ),
            remediation=(
                "Add: Permissions-Policy: "
                "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
            ),
            detail={},
        ))
    else:
        status = HeaderStatus.PRESENT
        # Check if dangerous features are explicitly allowed (*)
        for feature in DANGEROUS_PERMISSIONS:
            if f"{feature}=*" in value.lower() or f"{feature}=(*))" in value.lower():
                issues.append(f"'{feature}' allowed for all origins (*)")
                findings.append(HeaderFinding(
                    check_type=HeaderCheckType.PERMISSIONS,
                    target_url=url,
                    header_name="Permissions-Policy",
                    status=HeaderStatus.MISCONFIGURED,
                    evidence=f"Permissions-Policy allows '{feature}' for all origins",
                    severity=SeverityLevel.MEDIUM,
                    description=(
                        f"The Permissions-Policy allows '{feature}' access from any origin. "
                        f"Malicious iframes could access {feature} without user awareness."
                    ),
                    remediation=(
                        f"Restrict '{feature}': change to {feature}=() to disable entirely "
                        f"or {feature}=(self) to allow only same-origin."
                    ),
                    detail={"feature": feature, "policy": value[:100]},
                ))
                status = HeaderStatus.MISCONFIGURED

        if not issues:
            recommendations.append("Policy is configured — verify all sensitive features are restricted")

    header_details.append(HeaderDetail(
        name="Permissions-Policy",
        status=status,
        value=value[:200] if value else None,
        issues=issues,
        recommendations=recommendations,
    ))


# ──────────────────────────────────────────────
# 6. X-XSS-Protection
# ──────────────────────────────────────────────

def check_xss_protection(
    headers: Dict[str, str],
    url: str,
    findings: List[HeaderFinding],
    header_details: List[HeaderDetail],
    checks: List[str],
):
    checks.append("X-XSS-PROTECTION")
    value = headers.get("x-xss-protection", "")
    issues = []
    recommendations = []

    if not value:
        status = HeaderStatus.MISSING
        issues.append("Absent — modern browsers ignore this, but older ones unprotected")
        recommendations.append("Add: X-XSS-Protection: 0  (recommended for modern apps using CSP)")
        # Low severity — deprecated in modern browsers
        findings.append(HeaderFinding(
            check_type=HeaderCheckType.XSS_PROTECTION,
            target_url=url,
            header_name="X-XSS-Protection",
            status=HeaderStatus.MISSING,
            evidence="X-XSS-Protection header is absent",
            severity=SeverityLevel.LOW,
            description=(
                "X-XSS-Protection is deprecated in modern browsers but still relevant "
                "for IE/older browsers. Recommended to explicitly set to 0 to disable "
                "the buggy IE XSS auditor which can itself be exploited."
            ),
            remediation=(
                "If using CSP: set X-XSS-Protection: 0 to disable the buggy IE auditor. "
                "For legacy support: X-XSS-Protection: 1; mode=block"
            ),
            detail={},
        ))
    else:
        val = value.strip()
        if val == "0":
            status = HeaderStatus.PRESENT
            recommendations.append("Good — disabling the XSS auditor is correct when CSP is used")
        elif "mode=block" in val.lower() and val.startswith("1"):
            status = HeaderStatus.PRESENT
            recommendations.append("'1; mode=block' is acceptable for legacy browser support")
        elif val == "1" and "mode=block" not in val.lower():
            status = HeaderStatus.WEAK
            issues.append("'1' without mode=block can expose data via redirect")
            findings.append(HeaderFinding(
                check_type=HeaderCheckType.XSS_PROTECTION,
                target_url=url,
                header_name="X-XSS-Protection",
                status=HeaderStatus.WEAK,
                evidence=f"X-XSS-Protection: {val} — missing mode=block",
                severity=SeverityLevel.LOW,
                description=(
                    "X-XSS-Protection: 1 without mode=block allows the browser to "
                    "sanitize the page, which can leak data via redirects."
                ),
                remediation=(
                    "Change to: X-XSS-Protection: 1; mode=block "
                    "or X-XSS-Protection: 0 if strong CSP is in place."
                ),
                detail={"value": val},
            ))
        else:
            status = HeaderStatus.MISCONFIGURED
            issues.append(f"Unrecognised value: '{val}'")

    header_details.append(HeaderDetail(
        name="X-XSS-Protection",
        status=status,
        value=value or None,
        issues=issues,
        recommendations=recommendations,
    ))


# ──────────────────────────────────────────────
# 7. Information-Leaking Headers
# ──────────────────────────────────────────────

def check_info_leaks(
    headers: Dict[str, str],
    url: str,
    findings: List[HeaderFinding],
    info_leaks: List[InfoLeakDetail],
    checks: List[str],
):
    checks.append("INFO-LEAKS")

    for header_name, leak_description in INFO_LEAK_HEADERS.items():
        value = headers.get(header_name, "")
        if not value:
            continue

        # Determine severity based on how specific the version info is
        has_version = any(
            char.isdigit() for char in value
        ) and any(c in value for c in [".", "/", "-"])

        severity = SeverityLevel.MEDIUM if has_version else SeverityLevel.LOW

        info_leaks.append(InfoLeakDetail(
            header_name=header_name.title(),
            value=value,
            leaked_info=leak_description,
            severity=severity,
        ))

        findings.append(HeaderFinding(
            check_type=HeaderCheckType.INFO_LEAK,
            target_url=url,
            header_name=header_name.title(),
            status=HeaderStatus.MISCONFIGURED,
            evidence=f"Header '{header_name}' reveals: {value}",
            severity=severity,
            description=(
                f"The '{header_name}' header exposes {leak_description}. "
                "Version information helps attackers identify known CVEs for the stack."
            ),
            remediation=(
                f"Remove or obscure the '{header_name}' header in your server configuration. "
                "Nginx: server_tokens off;  "
                "Apache: ServerTokens Prod; ServerSignature Off  "
                "Express.js: app.disable('x-powered-by')"
            ),
            detail={"header": header_name, "value": value},
        ))


# ──────────────────────────────────────────────
# 8. Deprecated / Dangerous Header Detection
# ──────────────────────────────────────────────

def check_dangerous_headers(
    headers: Dict[str, str],
    url: str,
    findings: List[HeaderFinding],
    checks: List[str],
):
    checks.append("DANGEROUS-HEADERS")

    # Access-Control-Allow-Origin wildcard
    acao = headers.get("access-control-allow-origin", "")
    if acao == "*":
        findings.append(HeaderFinding(
            check_type=HeaderCheckType.MISCONFIGURATION,
            target_url=url,
            header_name="Access-Control-Allow-Origin",
            status=HeaderStatus.MISCONFIGURED,
            evidence="Access-Control-Allow-Origin: * — any origin can read responses",
            severity=SeverityLevel.HIGH,
            description=(
                "A wildcard CORS policy allows any website to make cross-origin "
                "requests and read responses. Combined with credentials, this is critical."
            ),
            remediation=(
                "Restrict to specific trusted origins: "
                "Access-Control-Allow-Origin: https://your-domain.com"
            ),
            detail={"value": acao},
        ))

    # Pragma: no-cache without Cache-Control
    pragma = headers.get("pragma", "")
    cache_control = headers.get("cache-control", "")
    if pragma and not cache_control:
        findings.append(HeaderFinding(
            check_type=HeaderCheckType.MISCONFIGURATION,
            target_url=url,
            header_name="Cache-Control",
            status=HeaderStatus.MISSING,
            evidence="Pragma: no-cache set but Cache-Control header is absent",
            severity=SeverityLevel.LOW,
            description=(
                "Pragma: no-cache is a legacy HTTP/1.0 header ignored by modern caches. "
                "Cache-Control is required for proper cache management."
            ),
            remediation=(
                "Add: Cache-Control: no-store, no-cache, must-revalidate "
                "for pages with sensitive data."
            ),
            detail={"pragma": pragma},
        ))

    # Public-Key-Pins (HPKP) — deprecated and dangerous
    hpkp = headers.get("public-key-pins", "")
    if hpkp:
        findings.append(HeaderFinding(
            check_type=HeaderCheckType.MISCONFIGURATION,
            target_url=url,
            header_name="Public-Key-Pins",
            status=HeaderStatus.MISCONFIGURED,
            evidence="Public-Key-Pins (HPKP) is present — deprecated and dangerous",
            severity=SeverityLevel.MEDIUM,
            description=(
                "HPKP is deprecated and removed from Chrome/Firefox. "
                "A misconfigured HPKP can permanently lock users out of your site."
            ),
            remediation=(
                "Remove the Public-Key-Pins header. "
                "Use Certificate Transparency (Expect-CT) instead."
            ),
            detail={"value": hpkp[:80]},
        ))


# ──────────────────────────────────────────────
# Main Scanner Entry Point
# ──────────────────────────────────────────────

async def run_headers_scan(
    url: str,
    timeout: int = 10,
    follow_redirects: bool = True,
) -> dict:
    findings: List[HeaderFinding] = []
    info_leaks: List[InfoLeakDetail] = []
    header_details: List[HeaderDetail] = []
    errors: List[str] = []
    checks: List[str] = []
    csp_analysis: Optional[CSPAnalysis] = None

    async with httpx.AsyncClient(
        follow_redirects=follow_redirects,
        verify=False,
        headers={"User-Agent": "WebVulnScanner/1.0 (educational use)"},
    ) as client:
        try:
            resp = await client.get(url, timeout=timeout)
        except Exception as e:
            return {
                "url": url,
                "status": "unreachable",
                "summary": HeaderSummary(
                    total_headers_checked=0, headers_present=0,
                    headers_missing=0, headers_misconfigured=0,
                    vulnerabilities_found=0, info_leaks_found=0,
                    csp_score=None, security_score=0,
                    grade="F", risk_level=SeverityLevel.CRITICAL,
                ),
                "findings": [],
                "header_details": [],
                "csp_analysis": None,
                "info_leaks": [],
                "raw_headers": {},
                "errors": [f"Could not reach target: {str(e)}"],
            }

        # Normalise all header names to lowercase
        raw_headers = {k.lower(): v for k, v in resp.headers.items()}
        raw_headers_display = {k: v for k, v in resp.headers.items()}

        # Run all checks
        csp_analysis = check_csp(raw_headers, url, findings, header_details, checks)
        check_x_frame_options(raw_headers, url, findings, header_details, checks)
        check_x_content_type(raw_headers, url, findings, header_details, checks)
        check_referrer_policy(raw_headers, url, findings, header_details, checks)
        check_permissions_policy(raw_headers, url, findings, header_details, checks)
        check_xss_protection(raw_headers, url, findings, header_details, checks)
        check_info_leaks(raw_headers, url, findings, info_leaks, checks)
        check_dangerous_headers(raw_headers, url, findings, checks)

    # Deduplicate findings
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.check_type, f.header_name, f.status)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Tally header statuses
    present = sum(1 for h in header_details if h.status == HeaderStatus.PRESENT)
    missing = sum(1 for h in header_details if h.status == HeaderStatus.MISSING)
    misconfigured = sum(1 for h in header_details if h.status in (
        HeaderStatus.MISCONFIGURED, HeaderStatus.WEAK
    ))

    security_score = calculate_security_score(unique_findings, len(SECURITY_HEADERS))

    summary = HeaderSummary(
        total_headers_checked=len(SECURITY_HEADERS),
        headers_present=present,
        headers_missing=missing,
        headers_misconfigured=misconfigured,
        vulnerabilities_found=len(unique_findings),
        info_leaks_found=len(info_leaks),
        csp_score=csp_analysis.score if csp_analysis else None,
        security_score=security_score,
        grade=score_to_grade(security_score),
        risk_level=calculate_risk(unique_findings),
    )

    return {
        "url": url,
        "status": "completed",
        "summary": summary,
        "findings": unique_findings,
        "header_details": header_details,
        "csp_analysis": csp_analysis,
        "info_leaks": info_leaks,
        "raw_headers": raw_headers_display,
        "errors": errors,
    }