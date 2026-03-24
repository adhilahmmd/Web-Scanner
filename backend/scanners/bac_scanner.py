"""
Broken Access Control Scanner Module

Checks for:
1. IDOR           — parameter ID tampering to access other users' data
2. Forced Browsing — direct access to restricted/admin paths without auth
3. Privilege Escalation — role/admin parameter manipulation
4. Missing Auth   — sensitive endpoints accessible without credentials
5. Method Tampering — GET→POST→PUT→DELETE on restricted endpoints

Bypass techniques:
- Parameter tampering (IDs, roles)
- URL path manipulation (path traversal, case, suffix tricks)
- Header bypasses (X-Original-URL, X-Rewrite-URL, X-Forwarded-For)
- Cookie/token role manipulation
"""

import httpx
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from typing import List, Dict, Tuple, Optional
from models.bac_models import (
    BACFinding, BACSummary, SeverityLevel,
    BACType, BypassTechnique
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


def is_sensitive_response(status: int, original_status: int, body: str) -> Tuple[bool, str]:
    """Determine if a response indicates unauthorized access."""
    # Only signal status-change bypass when we actually verified original was blocked
    if original_status in (401, 403) and status == 200:
        return True, f"Status changed from {original_status} → 200 (bypass successful)"

    sensitive_keywords = [
        "admin", "dashboard", "control panel", "manage users",
        "system settings", "user list", "delete user",
        "config", "secret", "private", "internal",
        "password", "credential", "token", "api_key",
    ]
    lower_body = body.lower()
    for kw in sensitive_keywords:
        if kw in lower_body and status == 200:
            return True, f"Sensitive keyword '{kw}' found in accessible response"

    return False, ""


def has_sensitive_content(body: str) -> Tuple[bool, str]:
    """Check if a response body contains sensitive keywords (no status-change assumption)."""
    sensitive_keywords = [
        "admin", "dashboard", "control panel", "manage users",
        "system settings", "user list", "delete user",
        "config", "secret", "private", "internal",
        "password", "credential", "token", "api_key",
    ]
    lower_body = body.lower()
    for kw in sensitive_keywords:
        if kw in lower_body:
            return True, f"Sensitive keyword '{kw}' found in accessible response"
    return False, ""


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

                if (resp.status_code == 200
                        and diff > 100
                        and resp.status_code == baseline_status
                        and str(t_id) != str(v)):
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
                            f"returned HTTP 200 with different content "
                            f"(size diff: {diff} bytes)"
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
                    sensitive, evidence = has_sensitive_content(resp.text)
                    findings.append(BACFinding(
                        check_type=BACType.FORCED_BROWSING,
                        bypass_technique=BypassTechnique.URL_MANIPULATION,
                        target_url=target,
                        method="GET",
                        evidence=(
                            evidence or
                            f"Restricted path '{restricted_path}' returned HTTP 200 "
                            f"({len(resp.text)} bytes) without authentication"
                        ),
                        severity=SeverityLevel.HIGH,
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
                    findings.append(BACFinding(
                        check_type=BACType.FORCED_BROWSING,
                        bypass_technique=BypassTechnique.URL_MANIPULATION,
                        target_url=bypass_url,
                        method="GET",
                        original_value=f"{path} → 403",
                        tampered_value=bypass_path,
                        evidence=(
                            f"URL manipulation trick '{trick}' bypassed 403 on '{path}' "
                            f"and returned HTTP 200 ({len(resp.text)} bytes)"
                        ),
                        severity=SeverityLevel.CRITICAL,
                        description=(
                            f"A URL manipulation trick bypassed access control on '{path}'. "
                            f"The server returned 403 for the direct path but 200 for the manipulated version."
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

    async def _test_role_param(rp, rv):
        async with semaphore:
            tampered_url = inject_param(url, rp, rv)
            try:
                resp = await client.get(tampered_url, timeout=timeout)
                if resp.status_code == 200:
                    sensitive, evidence = has_sensitive_content(resp.text)
                    if sensitive:
                        findings.append(BACFinding(
                            check_type=BACType.PRIVILEGE_ESCALATION,
                            bypass_technique=BypassTechnique.PARAM_TAMPER,
                            target_url=tampered_url,
                            method="GET",
                            parameter=rp,
                            original_value="user",
                            tampered_value=rv,
                            evidence=evidence,
                            severity=SeverityLevel.CRITICAL,
                            description=(
                                f"Adding/modifying the '{rp}={rv}' URL parameter "
                                f"granted elevated access. The server trusts client-supplied role values."
                            ),
                            remediation=(
                                "Never trust client-supplied role or privilege parameters. "
                                "Store and verify roles server-side (session/JWT). "
                                "Implement Role-Based Access Control (RBAC) at the server layer."
                            ),
                        ))
                        return True
            except Exception as e:
                errors.append(f"Privilege escalation test error: {str(e)}")
            return False

    role_param_tasks = []
    for role_param in ROLE_PARAMS:
        for role_value in ROLE_VALUES[:4]:
            role_param_tasks.append(_test_role_param(role_param, role_value))
    
    await asyncio.gather(*role_param_tasks)

    # Test cookie/token role manipulation
    original_cookies = dict(client.cookies)
    async def _test_cookie_role(c_key, c_val):
        async with semaphore:
            try:
                resp = await client.get(
                    url,
                    cookies={**original_cookies, c_key: c_val},
                    timeout=timeout,
                )
                if resp.status_code == 200:
                    sensitive, evidence = is_sensitive_response(200, 403, resp.text)
                    if sensitive:
                        findings.append(BACFinding(
                            check_type=BACType.PRIVILEGE_ESCALATION,
                            bypass_technique=BypassTechnique.COOKIE_TAMPER,
                            target_url=url,
                            method="GET",
                            parameter=f"Cookie: {c_key}",
                            original_value="user",
                            tampered_value=c_val,
                            evidence=evidence,
                            severity=SeverityLevel.CRITICAL,
                            description=(
                                f"Setting cookie '{c_key}={c_val}' granted elevated access. "
                                f"The application trusts client-controlled cookie values for authorization."
                            ),
                            remediation=(
                                "Never use client-readable/writable cookies for authorization decisions. "
                                "Use signed, server-verified session tokens (e.g. HttpOnly, Secure cookies). "
                                "Implement server-side session storage for role/permission data."
                            ),
                        ))
                        return True
            except Exception as e:
                errors.append(f"Cookie tamper test error: {str(e)}")
            return False

    cookie_tasks = []
    for cookie_key in COOKIE_ROLE_KEYS:
        for cookie_val in COOKIE_ELEVATED_VALUES[:3]:
            cookie_tasks.append(_test_cookie_role(cookie_key, cookie_val))
    
    await asyncio.gather(*cookie_tasks)


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
                    content_type = resp.headers.get("content-type", "")
                    is_data = "application/json" in content_type or len(resp.text) > 500
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
):
    base_url = get_base_url(url)
    parsed = urlparse(url)
    path = parsed.path or "/"

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

        # Run testing for all URLs concurrently within limits
        for url in urls:
            await asyncio.gather(
                test_idor(client, url, timeout, findings, errors, checks),
                test_forced_browsing(client, url, timeout, findings, errors, checks),
                test_privilege_escalation(client, url, timeout, findings, errors, checks),
                test_missing_auth(client, url, timeout, findings, errors, checks),
                test_method_tampering(client, url, timeout, findings, errors, checks),
                test_header_bypass(client, url, timeout, findings, errors, checks),
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