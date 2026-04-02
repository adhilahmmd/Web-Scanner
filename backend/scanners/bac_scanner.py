"""
Broken Access Control Scanner Module

Checks for:
1. IDOR              — parameter ID tampering
2. Forced Browsing   — direct access to restricted/admin paths
3. Privilege Escalation — role/admin parameter manipulation
4. Missing Auth      — sensitive endpoints accessible without credentials
5. Method Tampering  — HTTP verb abuse
6. Header Bypass     — X-Original-URL, X-Rewrite-URL tricks
7. JWT Alg:None      — strip JWT signature + set alg to none
8. Mass Assignment   — inject admin/role fields into JSON POST bodies
"""

import httpx
import asyncio
import uuid
import json
import base64
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from typing import List, Dict, Tuple, Optional
from models.bac_models import (
    BACFinding, BACSummary, SeverityLevel,
    BACType, BypassTechnique, ConfidenceLevel
)


# ──────────────────────────────────────────────
# Restricted paths for forced browsing
# ──────────────────────────────────────────────
RESTRICTED_PATHS = [
    "/admin", "/admin/", "/admin/dashboard", "/admin/users",
    "/admin/settings", "/admin/config", "/admin/panel",
    "/administrator", "/administrator/index.php",
    "/manage", "/management", "/manager",
    "/dashboard", "/control", "/controlpanel",
    "/superuser", "/superadmin", "/root",
    "/user/1", "/user/2", "/users/1", "/users/2",
    "/account/1", "/account/2", "/profile/1", "/profile/2",
    "/api/admin", "/api/users", "/api/user/1",
    "/api/v1/admin", "/api/v1/users",
    "/config", "/settings", "/system",
    "/backup", "/logs", "/log",
    "/debug", "/console", "/shell",
    "/internal", "/private", "/secret",
    "/wp-admin", "/wp-admin/admin.php",
    "/phpmyadmin", "/phpinfo.php",
    "/actuator", "/actuator/env", "/actuator/health",
    "/.env", "/.git/config",
]

# URL path manipulation tricks
PATH_BYPASS_TRICKS = [
    "{path}",             # original
    "{path}/",            # trailing slash
    "{path}%20",          # URL encoded space
    "{path}%09",          # tab
    "{path}/*",           # wildcard
    "{path}.html",        # extension append
    "{path}.json",
    "{path}..;/",         # path traversal bypass
    "//{path}",           # double slash
    "{path}?",            # query trick
    "{path}#",            # fragment trick
    "/{path}",            # extra leading slash
]

# HTTP methods to tamper with
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# Role/privilege related parameter names
ROLE_PARAMS = ["role", "user_role", "userRole", "admin", "isAdmin", "is_admin",
               "privilege", "level", "access", "type", "user_type", "userType",
               "group", "permission", "permissions"]

ROLE_VALUES = ["admin", "administrator", "superuser", "root", "1", "true",
               "ADMIN", "Administrator", "manager", "supervisor", "staff"]

# Cookie/token manipulation patterns
COOKIE_ROLE_KEYS = ["role", "user_role", "admin", "is_admin", "isAdmin",
                    "privilege", "level", "access", "userType", "type"]

COOKIE_ELEVATED_VALUES = ["admin", "administrator", "1", "true", "superuser", "root"]

# Header bypass patterns
BYPASS_HEADERS = [
    {"X-Original-URL": "{path}"},
    {"X-Rewrite-URL": "{path}"},
    {"X-Override-URL": "{path}"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"Referer": "{base_url}/admin"},
    {"X-Frame-Options": "ALLOWALL"},
]


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def extract_params(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] for k, v in params.items()}


def inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def get_base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


# Sensitive keywords that indicate real privileged content
SENSITIVE_KEYWORDS = [
    "admin", "dashboard", "control panel", "manage users",
    "system settings", "user list", "delete user",
    "config", "secret", "private", "internal",
    "password", "credential", "token", "api_key",
]


def is_sensitive_response(status: int, original_status: int, body: str) -> Tuple[bool, str, ConfidenceLevel]:
    """Determine if a response indicates unauthorized access and assign confidence."""
    lower_body = body.lower()
    has_kw = any(kw in lower_body for kw in SENSITIVE_KEYWORDS)

    # Strongest signal: status changed from blocked to 200 + sensitive content
    if original_status in (401, 403) and status == 200:
        if has_kw:
            kw = next(kw for kw in SENSITIVE_KEYWORDS if kw in lower_body)
            return True, f"Status changed {original_status}→200 + sensitive keyword '{kw}' found", ConfidenceLevel.HIGH
        return True, f"Status changed from {original_status}→200 (bypass confirmed)", ConfidenceLevel.MEDIUM

    return False, "", ConfidenceLevel.LOW


def has_sensitive_content(body: str) -> Tuple[bool, str]:
    """Check if a response body contains sensitive keywords (no status-change assumption)."""
    lower_body = body.lower()
    for kw in SENSITIVE_KEYWORDS:
        if kw in lower_body:
            return True, f"Sensitive keyword '{kw}' found in accessible response"
    return False, ""


def significant_body_diff(body_a: str, body_b: str, threshold: int = 200, percentage: float = 0.05) -> bool:
    """
    Return True if two response bodies differ by more than `threshold` bytes OR 
    if their lengths differ by more than `percentage` % of the larger body.
    This helps detect SPA catch-all pages that inject slight token/ad differences.
    """
    len_a = len(body_a)
    len_b = len(body_b)
    diff = abs(len_a - len_b)
    
    # If the byte difference is small, it's NOT a significant change
    if diff <= threshold:
        return False
        
    # Check if the difference is beyond the percentage tolerance
    max_len = max(len_a, len_b, 1) # avoid div by zero
    if (diff / max_len) > percentage:
        return True
        
    return False


def calculate_risk(findings: List[BACFinding]) -> SeverityLevel:
    if not findings:
        return SeverityLevel.LOW
    severities = [f.severity for f in findings]
    if SeverityLevel.CRITICAL in severities:
        return SeverityLevel.CRITICAL
    if SeverityLevel.HIGH in severities:
        return SeverityLevel.HIGH
    if SeverityLevel.MEDIUM in severities:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


# ──────────────────────────────────────────────
# 1. IDOR — Parameter ID Tampering
# ──────────────────────────────────────────────

async def test_idor(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    findings: List[BACFinding],
    errors: List[str],
    checks: List[str],
):
    params = extract_params(url)
    id_params = {k: v for k, v in params.items()
                 if any(x in k.lower() for x in ["id", "uid", "user", "account",
                                                   "profile", "order", "invoice",
                                                   "file", "doc", "record", "num"])}
    if not id_params:
        return

    # Get baseline response
    try:
        baseline = await client.get(url, timeout=timeout)
        baseline_len = len(baseline.text)
        baseline_status = baseline.status_code
    except Exception as e:
        errors.append(f"IDOR baseline failed: {str(e)}")
        return

    semaphore = asyncio.Semaphore(5)

    async def _test_idor_id(p, v, t_id):
        async with semaphore:
            checks.append(f"IDOR:{p}={t_id}")
            tampered_url = inject_param(url, p, str(t_id))
            try:
                resp = await client.get(tampered_url, timeout=timeout)
                diff = abs(len(resp.text) - baseline_len)

                # Raised threshold to 500 bytes to avoid FP on pages with volatile
                # dynamic content (ads, timestamps, random tokens, etc.)
                if (
                    resp.status_code == 200
                    and diff > 500
                    and resp.status_code == baseline_status
                    and str(t_id) != str(v)
                ):
                    findings.append(BACFinding(
                        check_type=BACType.IDOR,
                        bypass_technique=BypassTechnique.PARAM_TAMPER,
                        target_url=tampered_url,
                        method="GET",
                        parameter=p,
                        original_value=str(v),
                        tampered_value=str(t_id),
                        evidence=(
                            f"Parameter '{p}' changed from '{v}' → '{t_id}' "
                            f"returned HTTP 200 with significantly different content "
                            f"(size diff: {diff} bytes — threshold: 500)"
                        ),
                        severity=SeverityLevel.HIGH,
                        description=(
                            f"The parameter '{p}' appears to directly reference an internal "
                            f"object (ID={t_id}) and returns different data without access control. "
                            f"An attacker could enumerate other users' data by changing this ID."
                        ),
                        remediation=(
                            "Implement server-side authorization checks on every object access. "
                            "Use indirect object references (UUIDs/tokens) instead of sequential IDs. "
                            "Verify the requesting user owns the requested resource before returning data."
                        ),
                    ))
                    return True
            except Exception as e:
                errors.append(f"IDOR test error on {p}={t_id}: {str(e)}")
            return False

    tasks = []
    for param, value in id_params.items():
        try:
            original_id = int(value)
            test_ids = [original_id - 1, original_id + 1, original_id + 100, 0, 999]
        except ValueError:
            test_ids = [1, 2, 3, 999]
        
        for t_id in test_ids:
            tasks.append(_test_idor_id(param, value, t_id))
    
    await asyncio.gather(*tasks)


# ──────────────────────────────────────────────
# 2. Forced Browsing + URL Path Manipulation
# ──────────────────────────────────────────────

async def test_forced_browsing(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    findings: List[BACFinding],
    errors: List[str],
    checks: List[str],
    catch_all_status: int = 404,
    catch_all_body: str = "",
):
    base_url = get_base_url(url)

    semaphore = asyncio.Semaphore(10)

    async def _test_path(restricted_path):
        async with semaphore:
            target = base_url + restricted_path
            checks.append(f"FORCED:{target}")
            try:
                resp = await client.get(target, timeout=timeout)
                if resp.status_code == 200 and len(resp.text) > 200:
                    # SPA Catch-All check
                    if catch_all_status == 200 and not significant_body_diff(resp.text, catch_all_body):
                        return

                    sensitive, evidence = has_sensitive_content(resp.text)
                    content_type = resp.headers.get("content-type", "")
                    is_json_data = "application/json" in content_type

                    # Only flag if we have meaningful evidence: sensitive content OR JSON data response
                    if sensitive or is_json_data:
                        confidence = ConfidenceLevel.HIGH if sensitive else ConfidenceLevel.MEDIUM
                        severity = SeverityLevel.HIGH if sensitive else SeverityLevel.MEDIUM
                        findings.append(BACFinding(
                            check_type=BACType.FORCED_BROWSING,
                            bypass_technique=BypassTechnique.URL_MANIPULATION,
                            target_url=target,
                            method="GET",
                            evidence=(
                                evidence or
                                f"Restricted path '{restricted_path}' returned HTTP 200 with JSON data "
                                f"({len(resp.text)} bytes) without authentication"
                            ),
                            severity=severity,
                            confidence=confidence,
                            description=(
                                f"The path '{restricted_path}' is accessible without authentication. "
                                f"This may expose administrative functionality or sensitive data."
                            ),
                            remediation=(
                                "Implement proper authentication and authorization on all restricted endpoints. "
                                "Use a centralized access control middleware. "
                                "Return 401/403 for unauthenticated/unauthorized access — never 200."
                            ),
                        ))
                elif resp.status_code == 403:
                    await test_path_bypass(
                        client, base_url, restricted_path,
                        timeout, findings, errors, checks
                    )
            except Exception as e:
                errors.append(f"Forced browse error {target}: {str(e)}")

    tasks = [_test_path(rp) for rp in RESTRICTED_PATHS[:30]]
    await asyncio.gather(*tasks)


async def test_path_bypass(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    timeout: int,
    findings: List[BACFinding],
    errors: List[str],
    checks: List[str],
):
    """Try URL manipulation tricks to bypass a 403 response."""
    semaphore = asyncio.Semaphore(5)

    async def _test_trick(trick):
        async with semaphore:
            bypass_path = trick.replace("{path}", path.lstrip("/"))
            bypass_url = base_url + "/" + bypass_path
            checks.append(f"BYPASS:{bypass_url}")
            try:
                resp = await client.get(bypass_url, timeout=timeout)
                if resp.status_code == 200 and len(resp.text) > 200:
                    # Require sensitive content OR JSON data — a generic landing page
                    # returning 200 after a URL trick should NOT automatically be CRITICAL.
                    sensitive, evidence = has_sensitive_content(resp.text)
                    content_type = resp.headers.get("content-type", "")
                    is_json_data = "application/json" in content_type

                    if not sensitive and not is_json_data:
                        return  # Not enough evidence — likely a generic redirect/landing page

                    severity = SeverityLevel.CRITICAL if sensitive else SeverityLevel.HIGH
                    findings.append(BACFinding(
                        check_type=BACType.FORCED_BROWSING,
                        bypass_technique=BypassTechnique.URL_MANIPULATION,
                        target_url=bypass_url,
                        method="GET",
                        original_value=f"{path} → 403",
                        tampered_value=bypass_path,
                        evidence=(
                            evidence or
                            f"URL manipulation trick '{trick}' bypassed 403 on '{path}' "
                            f"and returned HTTP 200 with JSON data ({len(resp.text)} bytes)"
                        ),
                        severity=severity,
                        confidence=ConfidenceLevel.HIGH if sensitive else ConfidenceLevel.MEDIUM,
                        description=(
                            f"A URL manipulation trick bypassed access control on '{path}'. "
                            f"The server returned 403 for the direct path but 200 for the "
                            f"manipulated version with {'sensitive content' if sensitive else 'JSON data'}."
                        ),
                        remediation=(
                            "Normalize all URL paths server-side before applying access control. "
                            "Do not rely on path-matching alone — verify session permissions at the handler level. "
                            "Use a WAF to block path traversal patterns."
                        ),
                    ))
                    return True
            except Exception:
                pass
            return False

    tasks = [_test_trick(t) for t in PATH_BYPASS_TRICKS]
    await asyncio.gather(*tasks)


# ──────────────────────────────────────────────
# 3. Privilege Escalation — Role/Param Tampering
# ──────────────────────────────────────────────

async def test_privilege_escalation(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    findings: List[BACFinding],
    errors: List[str],
    checks: List[str],
):
    params = extract_params(url)

    semaphore = asyncio.Semaphore(5)

    # Fetch baseline for content comparison
    try:
        baseline_resp = await client.get(url, timeout=timeout)
        baseline_body = baseline_resp.text
        baseline_status = baseline_resp.status_code
    except Exception as e:
        errors.append(f"Privilege escalation baseline failed: {str(e)}")
        baseline_body = ""
        baseline_status = 200

    # Grouped param findings: param_name -> list of working payloads
    param_hits: Dict[str, list] = {}

    async def _test_role_param(rp, rv):
        async with semaphore:
            tampered_url = inject_param(url, rp, rv)
            try:
                resp = await client.get(tampered_url, timeout=timeout)
                if resp.status_code == 200:
                    sensitive, evidence = has_sensitive_content(resp.text)
                    body_changed = significant_body_diff(resp.text, baseline_body)
                    # Require BOTH sensitive content AND a meaningful body change
                    if sensitive and body_changed:
                        if rp not in param_hits:
                            param_hits[rp] = []
                        param_hits[rp].append((rv, evidence))
            except Exception as e:
                errors.append(f"Privilege escalation test error: {str(e)}")

    role_param_tasks = []
    for role_param in ROLE_PARAMS:
        for role_value in ROLE_VALUES[:4]:
            role_param_tasks.append(_test_role_param(role_param, role_value))

    await asyncio.gather(*role_param_tasks)

    # Emit one grouped finding per vulnerable parameter
    for rp, hits in param_hits.items():
        payloads = [h[0] for h in hits]
        first_evidence = hits[0][1]
        findings.append(BACFinding(
            check_type=BACType.PRIVILEGE_ESCALATION,
            bypass_technique=BypassTechnique.PARAM_TAMPER,
            target_url=url,
            method="GET",
            parameter=rp,
            original_value="user",
            tampered_value=payloads[0],
            payloads_tested=payloads,
            evidence=(
                f"{first_evidence} — {len(payloads)} payload(s) confirmed: "
                + ", ".join(f"{rp}={v}" for v in payloads)
            ),
            severity=SeverityLevel.CRITICAL,
            confidence=ConfidenceLevel.HIGH,
            description=(
                f"The URL parameter '{rp}' can be set to elevated values to gain privileged access. "
                f"{len(payloads)} payload(s) confirmed: {', '.join(payloads)}. "
                f"The server trusts client-supplied role values."
            ),
            remediation=(
                "Never trust client-supplied role or privilege parameters. "
                "Store and verify roles server-side (session/JWT). "
                "Implement Role-Based Access Control (RBAC) at the server layer."
            ),
        ))

    # Test cookie/token role manipulation
    # Use the real baseline fetched above for accurate status comparison
    original_cookies = dict(client.cookies)

    # Grouped cookie findings: cookie_key -> list of working (value, evidence, confidence)
    cookie_hits: Dict[str, list] = {}

    async def _test_cookie_role(c_key, c_val):
        async with semaphore:
            try:
                resp = await client.get(
                    url,
                    cookies={**original_cookies, c_key: c_val},
                    timeout=timeout,
                )
                # Use the REAL baseline status (not hardcoded 403)
                found, evidence, confidence = is_sensitive_response(
                    resp.status_code, baseline_status, resp.text
                )
                # Secondary check: same status but body differs significantly + has sensitive content
                if not found and resp.status_code == 200:
                    sensitive, kw_evidence = has_sensitive_content(resp.text)
                    if sensitive and significant_body_diff(resp.text, baseline_body):
                        found = True
                        evidence = kw_evidence + " (body significantly changed after cookie injection)"
                        confidence = ConfidenceLevel.MEDIUM

                if found:
                    if c_key not in cookie_hits:
                        cookie_hits[c_key] = []
                    cookie_hits[c_key].append((c_val, evidence, confidence))
            except Exception as e:
                errors.append(f"Cookie tamper test error: {str(e)}")

    cookie_tasks = []
    for cookie_key in COOKIE_ROLE_KEYS:
        for cookie_val in COOKIE_ELEVATED_VALUES[:3]:
            cookie_tasks.append(_test_cookie_role(cookie_key, cookie_val))

    await asyncio.gather(*cookie_tasks)

    # Emit one grouped finding per vulnerable cookie key
    for c_key, hits in cookie_hits.items():
        payloads = [h[0] for h in hits]
        best_confidence = hits[0][2]  # first hit is usually the strongest
        first_evidence = hits[0][1]
        # Severity: CRITICAL only if HIGH confidence, else HIGH
        severity = SeverityLevel.CRITICAL if best_confidence == ConfidenceLevel.HIGH else SeverityLevel.HIGH
        findings.append(BACFinding(
            check_type=BACType.PRIVILEGE_ESCALATION,
            bypass_technique=BypassTechnique.COOKIE_TAMPER,
            target_url=url,
            method="GET",
            parameter=f"Cookie: {c_key}",
            original_value="user",
            tampered_value=payloads[0],
            payloads_tested=payloads,
            evidence=(
                f"{first_evidence} — {len(payloads)} payload(s) confirmed: "
                + ", ".join(f"{c_key}={v}" for v in payloads)
            ),
            severity=severity,
            confidence=best_confidence,
            description=(
                f"Setting the '{c_key}' cookie to elevated values granted privileged access. "
                f"{len(payloads)} payload(s) confirmed: {', '.join(payloads)}. "
                f"The application trusts client-controlled cookie values for authorization."
            ),
            remediation=(
                "Never use client-readable/writable cookies for authorization decisions. "
                "Use signed, server-verified session tokens (e.g. HttpOnly, Secure cookies). "
                "Implement server-side session storage for role/permission data."
            ),
        ))


# ──────────────────────────────────────────────
# 4. Missing Authentication on Sensitive Endpoints
# ──────────────────────────────────────────────

async def test_missing_auth(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    findings: List[BACFinding],
    errors: List[str],
    checks: List[str],
    catch_all_status: int = 404,
    catch_all_body: str = "",
):
    base_url = get_base_url(url)

    # Common auth-required endpoints
    auth_required_paths = [
        "/api/users", "/api/user", "/api/admin",
        "/api/v1/users", "/api/v1/admin", "/api/v2/users",
        "/api/profile", "/api/account", "/api/settings",
        "/api/orders", "/api/payments", "/api/transactions",
        "/api/keys", "/api/tokens", "/api/secrets",
        "/user/profile", "/account/settings",
        "/admin/api/users", "/admin/api/config",
    ]

    semaphore = asyncio.Semaphore(10)

    async def _test_missing_auth(auth_path):
        async with semaphore:
            target = base_url + auth_path
            checks.append(f"AUTH:{target}")
            try:
                # Make request with NO auth cookies/headers
                resp = await client.get(
                    target,
                    cookies={},
                    headers={"Authorization": ""},
                    timeout=timeout,
                )
                if resp.status_code == 200 and len(resp.text) > 100:
                    # Check for catch_all
                    if catch_all_status == 200 and not significant_body_diff(resp.text, catch_all_body):
                        return
                        
                    content_type = resp.headers.get("content-type", "")
                    # Require JSON for missing auth on API paths to avoid HTML fallback false positives
                    is_data = "application/json" in content_type
                    # Exclude standard JSON errors that return 200
                    if is_data and ("error" in resp.text.lower() or "unauthorized" in resp.text.lower()):
                        # Quick check: often APIs return {error: "unauthorized"} but status 200
                        if "admin" not in resp.text.lower() and "token" not in resp.text.lower():
                            is_data = False

                    if is_data:
                        findings.append(BACFinding(
                            check_type=BACType.MISSING_AUTH,
                            bypass_technique=BypassTechnique.URL_MANIPULATION,
                            target_url=target,
                            method="GET",
                            evidence=(
                                f"'{auth_path}' returned HTTP 200 with {len(resp.text)} bytes "
                                f"of content without any authentication credentials"
                            ),
                            severity=SeverityLevel.CRITICAL,
                            description=(
                                f"The endpoint '{auth_path}' appears to be accessible without authentication. "
                                f"Sensitive API endpoints should always require valid credentials."
                            ),
                            remediation=(
                                "Implement authentication middleware on all sensitive endpoints. "
                                "Return 401 Unauthorized when no valid credentials are provided. "
                                "Use JWT or session-based auth and verify on every request."
                            ),
                        ))
            except Exception:
                pass

    tasks = [_test_missing_auth(p) for p in auth_required_paths]
    await asyncio.gather(*tasks)


# ──────────────────────────────────────────────
# 5. HTTP Method Tampering
# ──────────────────────────────────────────────

async def test_method_tampering(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    findings: List[BACFinding],
    errors: List[str],
    checks: List[str],
):
    # Get baseline with GET
    try:
        baseline = await client.get(url, timeout=timeout)
        baseline_status = baseline.status_code
        baseline_body = baseline.text
    except Exception as e:
        errors.append(f"Method tamper baseline failed: {str(e)}")
        return

    semaphore = asyncio.Semaphore(5)

    async def _test_method(m):
        async with semaphore:
            checks.append(f"METHOD:{m}:{url}")
            try:
                resp = await client.request(m, url, timeout=timeout)
                if resp.status_code == 200 and m in ("DELETE", "PUT"):
                    # Check if the server just ignored the method and returned the GET baseline
                    if not significant_body_diff(resp.text, baseline_body):
                        return
                        
                    findings.append(BACFinding(
                        check_type=BACType.METHOD_TAMPERING,
                        bypass_technique=BypassTechnique.URL_MANIPULATION,
                        target_url=url,
                        method=m,
                        original_value="GET",
                        tampered_value=m,
                        evidence=(
                            f"HTTP {m} on '{url}' returned 200 "
                            f"— destructive method accepted without restriction"
                        ),
                        severity=SeverityLevel.HIGH,
                        description=(
                            f"The endpoint accepts HTTP {m} requests and returns 200. "
                            f"Allowing {m} without proper authorization could enable "
                            f"unauthorized data modification or deletion."
                        ),
                        remediation=(
                            "Explicitly allowlist only the HTTP methods each endpoint should accept. "
                            "Return 405 Method Not Allowed for unsupported methods. "
                            "Apply the same authorization checks regardless of HTTP method."
                        ),
                    ))
            except Exception as e:
                errors.append(f"Method tamper error {m}: {str(e)}")

    async def _test_override(om):
        async with semaphore:
            checks.append(f"METHOD_OVERRIDE:{om}")
            try:
                override_resp = await client.post(
                    url,
                    headers={"X-HTTP-Method-Override": om},
                    timeout=timeout,
                )
                if override_resp.status_code == 200:
                    # Verify it wasn't just a standard POST ignoring the override
                    if not significant_body_diff(override_resp.text, baseline_body):
                        return
                        
                    findings.append(BACFinding(
                        check_type=BACType.METHOD_TAMPERING,
                        bypass_technique=BypassTechnique.HEADER_BYPASS,
                        target_url=url,
                        method=f"POST + X-HTTP-Method-Override: {om}",
                        original_value="GET",
                        tampered_value=f"X-HTTP-Method-Override: {om}",
                        evidence=(
                            f"X-HTTP-Method-Override: {om} returned 200 — "
                            f"method override header is accepted by the server"
                        ),
                        severity=SeverityLevel.HIGH,
                        description=(
                            f"The server honours the X-HTTP-Method-Override header, "
                            f"allowing a POST to act as {om}."
                        ),
                        remediation=(
                            "Disable X-HTTP-Method-Override unless explicitly required. "
                            "If used, apply the same authorization checks as the real method."
                        ),
                    ))
            except Exception as e:
                errors.append(f"Method override error {om}: {str(e)}")

    method_tasks = [_test_method(m) for m in ["POST", "PUT", "DELETE", "PATCH"]]
    override_tasks = [_test_override(om) for om in ["DELETE", "PUT"]]
    
    await asyncio.gather(*(method_tasks + override_tasks))


# ──────────────────────────────────────────────
# 6. Header-Based Access Control Bypass
# ──────────────────────────────────────────────

async def test_header_bypass(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    findings: List[BACFinding],
    errors: List[str],
    checks: List[str],
    catch_all_status: int = 404,
    catch_all_body: str = "",
):
    base_url = get_base_url(url)
    parsed = urlparse(url)
    path = parsed.path or "/"

    # Fetch baseline for exact URL to compare
    try:
        baseline_resp = await client.get(url, timeout=timeout)
        baseline_body = baseline_resp.text
    except Exception:
        baseline_body = ""

    # Test bypass headers against admin-like paths
    test_paths = ["/admin", "/dashboard", "/api/admin"]

    semaphore = asyncio.Semaphore(5)

    async def _test_header_path(tp, ht):
        async with semaphore:
            header = {
                k: v.replace("{path}", tp).replace("{base_url}", base_url)
                for k, v in ht.items()
            }
            h_name = list(header.keys())[0]
            h_val = list(header.values())[0]
            checks.append(f"HEADER:{h_name}:{h_val}")
            try:
                resp = await client.get(
                    url,
                    headers=header,
                    timeout=timeout,
                )
                if resp.status_code == 200 and len(resp.text) > 300:
                    if catch_all_status == 200 and not significant_body_diff(resp.text, catch_all_body):
                        return
                    if not significant_body_diff(resp.text, baseline_body):
                        return

                    sensitive, evidence = has_sensitive_content(resp.text)
                    if sensitive:
                        findings.append(BACFinding(
                            check_type=BACType.FORCED_BROWSING,
                            bypass_technique=BypassTechnique.HEADER_BYPASS,
                            target_url=url,
                            method="GET",
                            parameter=h_name,
                            original_value="(not set)",
                            tampered_value=h_val,
                            evidence=(
                                f"Header '{h_name}: {h_val}' returned HTTP 200 "
                                f"with sensitive content — access control bypassed via header"
                            ),
                            severity=SeverityLevel.CRITICAL,
                            description=(
                                f"The server uses the '{h_name}' header to route or authorize requests. "
                                f"An attacker can supply this header to bypass access controls."
                            ),
                            remediation=(
                                "Do not use X-Original-URL, X-Rewrite-URL, or similar headers "
                                "for access control decisions. Apply authorization at the application layer, "
                                "not the routing/proxy layer. Strip untrusted headers at the edge."
                            ),
                        ))
                        return True
            except Exception as e:
                errors.append(f"Header bypass error '{h_name}': {str(e)}")
            return False

    header_tasks = []
    for test_path in test_paths:
        for header_template in BYPASS_HEADERS:
            header_tasks.append(_test_header_path(test_path, header_template))
    
    await asyncio.gather(*header_tasks)



# ──────────────────────────────────────────────
# 7. JWT Algorithm Confusion — alg:none Attack
# ──────────────────────────────────────────────

def _b64url_decode(data: str) -> bytes:
    """Base64url decode with padding."""
    padded = data + "=" * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge_alg_none_jwt(token: str) -> Optional[str]:
    """
    Given a valid JWT, return a forged version with:
      - alg set to 'none' / 'None' / 'NONE'
      - signature stripped
    Returns None if token is not a valid 3-part JWT.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header_json = json.loads(_b64url_decode(parts[0]))
        header_json["alg"] = "none"
        new_header = _b64url_encode(json.dumps(header_json, separators=(",", ":")).encode())
        # alg:none JWT has no signature — just header.payload.
        return f"{new_header}.{parts[1]}."
    except Exception:
        return None


def _extract_jwt_from_headers(headers: dict) -> Optional[str]:
    """Look for a JWT in the Authorization header (Bearer scheme)."""
    auth = headers.get("Authorization", "") or headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        if len(token.split(".")) == 3:
            return token
    return None


def _extract_jwt_from_cookies(cookies) -> Optional[str]:
    """Look for a JWT-like value in cookies."""
    for name, value in cookies.items():
        if isinstance(value, str) and len(value.split(".")) == 3:
            try:
                _b64url_decode(value.split(".")[0])
                return value
            except Exception:
                continue
    return None


async def test_jwt_alg_none(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    findings: List[BACFinding],
    errors: List[str],
    checks: List[str],
):
    """
    Test for JWT algorithm confusion vulnerability (alg:none attack).

    Steps:
      1. Make a baseline request and look for JWTs in headers/cookies.
      2. Forge a tampered JWT with alg=none and no signature.
      3. Replay the request with the forged token.
      4. If the server accepts it (same or expanded response), report CRITICAL.
    """
    checks.append("JWT_ALG_NONE")
    try:
        baseline_resp = await client.get(url, timeout=timeout)
        baseline_body = baseline_resp.text
        baseline_status = baseline_resp.status_code

        # Find a JWT — check headers first, then cookies
        token = (_extract_jwt_from_headers(dict(baseline_resp.headers))
                 or _extract_jwt_from_cookies(dict(client.cookies))
                 or _extract_jwt_from_cookies(dict(baseline_resp.cookies)))

        if not token:
            return

        forged = _forge_alg_none_jwt(token)
        if not forged:
            return

        # Try each alg:none variant (servers may check case-sensitively)
        for alg_variant in ["none", "None", "NONE"]:
            try:
                header_json = json.loads(_b64url_decode(token.split(".")[0]))
                header_json["alg"] = alg_variant
                new_header = _b64url_encode(json.dumps(header_json, separators=(",", ":")).encode())
                forged_variant = f"{new_header}.{token.split('.')[1]}."

                resp = await client.get(
                    url,
                    headers={"Authorization": f"Bearer {forged_variant}"},
                    timeout=timeout,
                )

                # If server responds with 200 (or same status as baseline) to a signature-less token
                if resp.status_code == 200 and resp.status_code == baseline_status:
                    sensitive, evidence = has_sensitive_content(resp.text)
                    body_changed = significant_body_diff(resp.text, baseline_body)

                    if sensitive or not body_changed:
                        findings.append(BACFinding(
                            check_type=BACType.PRIVILEGE_ESCALATION,
                            bypass_technique=BypassTechnique.HEADER_BYPASS,
                            target_url=url,
                            method="GET",
                            parameter="Authorization: Bearer (JWT)",
                            original_value=token[:30] + "...",
                            tampered_value=forged_variant[:30] + "...",
                            evidence=(
                                f"Server accepted JWT with alg='{alg_variant}' and NO signature. "
                                f"HTTP {resp.status_code} returned with {'sensitive content' if sensitive else 'unchanged body'}."
                            ),
                            severity=SeverityLevel.CRITICAL,
                            confidence=ConfidenceLevel.HIGH,
                            description=(
                                "The server accepts JWTs with algorithm set to 'none', which disables "
                                "cryptographic signature verification entirely. An attacker can forge any "
                                "JWT payload (e.g. set admin:true, user_id:<any>) without knowing the secret."
                            ),
                            remediation=(
                                "Explicitly validate the 'alg' header field in JWT verification. "
                                "Reject tokens with alg='none'. "
                                "Use asymmetric algorithms (RS256, ES256) instead of HS256 where possible. "
                                "Use a battle-tested JWT library that rejects alg confusion by default."
                            ),
                        ))
                        return
            except Exception as e:
                errors.append(f"JWT alg:{alg_variant} test error: {str(e)}")

    except Exception as e:
        errors.append(f"JWT alg:none test error on {url}: {str(e)}")


# ──────────────────────────────────────────────
# 8. Mass Assignment Attack
# ──────────────────────────────────────────────

MASS_ASSIGNMENT_FIELDS = [
    {"admin": True},
    {"admin": 1},
    {"role": "admin"},
    {"role": "administrator"},
    {"isAdmin": True},
    {"is_admin": True},
    {"privilege": "admin"},
    {"user_type": "admin"},
    {"access_level": 9},
    {"permissions": ["admin", "write", "delete"]},
    {"verified": True},
    {"active": True, "role": "admin"},
    {"_id": 1},
    {"id": 1},
    {"userId": 1},
]

# Common JSON API endpoints to probe for mass assignment
MASS_ASSIGNMENT_PATHS = [
    "/api/user/update",
    "/api/users/update",
    "/api/profile/update",
    "/api/account/update",
    "/api/settings",
    "/api/user",
    "/api/register",
    "/api/signup",
    "/api/v1/user/update",
    "/api/v1/profile",
]


async def test_mass_assignment(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    findings: List[BACFinding],
    errors: List[str],
    checks: List[str],
):
    """
    Test for Mass Assignment vulnerabilities.

    Probes JSON POST/PUT endpoints by injecting privilege-escalation fields
    ('admin':true, 'role':'admin', etc.) and look for:
      - Sensitive keywords in response (evidence of privilege being applied)
      - Status code changes (auth state changes)
      - Significant response body differences
    """
    checks.append("MASS_ASSIGNMENT")
    base_url = get_base_url(url)
    json_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    # Also test the current URL path
    paths_to_test = MASS_ASSIGNMENT_PATHS + [urlparse(url).path]

    semaphore = asyncio.Semaphore(5)

    async def _test_path_fields(path, extra_fields):
        async with semaphore:
            target = base_url + path
            checks.append(f"MASSASSIGN:{target}")
            try:
                # Baseline with empty object
                baseline_resp = await client.post(
                    target,
                    json={},
                    headers=json_headers,
                    timeout=timeout,
                )
                baseline_body = baseline_resp.text

                # Inject escalation fields
                tampered_resp = await client.post(
                    target,
                    json=extra_fields,
                    headers=json_headers,
                    timeout=timeout,
                )

                if tampered_resp.status_code in (200, 201):
                    sensitive, evidence = has_sensitive_content(tampered_resp.text)
                    body_changed = significant_body_diff(tampered_resp.text, baseline_body)

                    if sensitive and body_changed:
                        field_str = json.dumps(extra_fields)
                        findings.append(BACFinding(
                            check_type=BACType.PRIVILEGE_ESCALATION,
                            bypass_technique=BypassTechnique.PARAM_TAMPER,
                            target_url=target,
                            method="POST",
                            parameter="JSON body (mass assignment)",
                            original_value="{}",
                            tampered_value=field_str[:100],
                            evidence=(
                                f"{evidence} — injected {field_str[:80]} into POST body "
                                f"and received HTTP {tampered_resp.status_code} with sensitive content"
                            ),
                            severity=SeverityLevel.HIGH,
                            confidence=ConfidenceLevel.HIGH,
                            description=(
                                f"The endpoint '{path}' accepted mass-assigned privilege fields. "
                                f"Injecting {list(extra_fields.keys())} into the JSON body produced "
                                f"a response containing sensitive content, indicating the server "
                                f"applied the supplied role/privilege values."
                            ),
                            remediation=(
                                "Use an allowlist (whitelist) of permitted fields when binding request body to models. "
                                "Never directly bind raw JSON to ORM/database models. "
                                "Use DTOs (Data Transfer Objects) that only expose safe fields. "
                                "Apply role checks on the server — never trust client-supplied privilege flags."
                            ),
                        ))
            except Exception:
                pass

    tasks = [
        _test_path_fields(path, fields)
        for path in paths_to_test
        for fields in MASS_ASSIGNMENT_FIELDS[:8]  # Test top 8 field sets
    ]
    await asyncio.gather(*tasks)


# ──────────────────────────────────────────────
# Main Scanner Entry Point
# ──────────────────────────────────────────────

async def run_bac_scan(

    urls: List[str],
    timeout: int = 10,
    cookies: Dict = None,
    extra_headers: Dict = None,
) -> dict:
    if cookies is None: cookies = {}
    if extra_headers is None: extra_headers = {}
    
    findings: List[BACFinding] = []
    errors: List[str] = []
    checks: List[str] = []

    if isinstance(urls, str):
        urls = [urls]

    if not urls:
        return {
            "url": "none",
            "status": "completed",
            "summary": BACSummary(
                total_checks=0,
                vulnerabilities_found=0,
                idor_findings=0,
                forced_browsing_findings=0,
                privilege_escalation_findings=0,
                missing_auth_findings=0,
                method_tampering_findings=0,
                risk_level=SeverityLevel.LOW,
            ),
            "findings": [],
            "errors": ["No URLs provided to test."],
        }

    primary_url = urls[0]
    base_url = get_base_url(primary_url)

    async with httpx.AsyncClient(
        follow_redirects=True,
        cookies=cookies,
        headers={
            "User-Agent": "WebVulnScanner/1.0 (educational use)",
            **extra_headers,
        },
    ) as client:
        # Soft reachability check — log the error but continue scanning.
        # Forced browsing, header bypass, and path tests probe common paths on
        # the base domain and remain valid even if this specific URL is slow/blocked.
        try:
            probe = await client.get(primary_url, timeout=timeout)
        except Exception as e:
            errors.append(f"Primary URL probe failed (continuing scan): {str(e)}")

        # Fetch Catch-All Baseline (to detect SPAs that return 200 for 404s)
        try:
            catch_all_url = urljoin(base_url, f"/does-not-exist-{uuid.uuid4().hex[:8]}")
            catch_all_probe = await client.get(catch_all_url, timeout=timeout)
            catch_all_status = catch_all_probe.status_code
            catch_all_body = catch_all_probe.text
        except Exception:
            catch_all_status = 404
            catch_all_body = ""

        # Run testing for all URLs concurrently within limits
        for url in urls:
            await asyncio.gather(
                test_idor(client, url, timeout, findings, errors, checks),
                test_forced_browsing(client, url, timeout, findings, errors, checks, catch_all_status, catch_all_body),
                test_privilege_escalation(client, url, timeout, findings, errors, checks),
                test_missing_auth(client, url, timeout, findings, errors, checks, catch_all_status, catch_all_body),
                test_method_tampering(client, url, timeout, findings, errors, checks),
                test_header_bypass(client, url, timeout, findings, errors, checks, catch_all_status, catch_all_body),
                test_jwt_alg_none(client, url, timeout, findings, errors, checks),
                test_mass_assignment(client, url, timeout, findings, errors, checks),
            )

    # Deduplicate by (check_type, target_url, parameter, tampered_value)
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.check_type, f.target_url, f.parameter, getattr(f, "tampered_value", ""))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    summary = BACSummary(
        total_checks=len(checks),
        vulnerabilities_found=len(unique_findings),
        idor_findings=sum(1 for f in unique_findings if f.check_type == BACType.IDOR),
        forced_browsing_findings=sum(1 for f in unique_findings if f.check_type == BACType.FORCED_BROWSING),
        privilege_escalation_findings=sum(1 for f in unique_findings if f.check_type == BACType.PRIVILEGE_ESCALATION),
        missing_auth_findings=sum(1 for f in unique_findings if f.check_type == BACType.MISSING_AUTH),
        method_tampering_findings=sum(1 for f in unique_findings if f.check_type == BACType.METHOD_TAMPERING),
        risk_level=calculate_risk(unique_findings),
    )

    return {
        "url": primary_url,
        "status": "completed",
        "summary": summary,
        "findings": unique_findings,
        "errors": errors,
    }