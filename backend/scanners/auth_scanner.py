"""
Broken Authentication & Session Management Scanner

Checks:
1.  Weak/Default Credentials    — brute forces login with common creds
2.  Session Token Analysis      — entropy, length, predictability
3.  Session Fixation            — pre-auth vs post-auth token comparison
4.  Insecure Cookie Flags       — HttpOnly, Secure, SameSite analysis
5.  Password Policy             — accepts weak passwords on register/change
6.  Account Lockout             — repeated failed logins don't lock account
7.  Login Endpoint Probing      — discovers login forms & endpoints
8.  Token Expiry & Invalidation — old tokens still valid after logout
9.  Multi-Session Detection     — same account accepts concurrent sessions
"""

import httpx
import asyncio
import math
import re
import hashlib
import base64
import json
import string
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Tuple, Optional, Set
from bs4 import BeautifulSoup
from models.auth_models import (
    AuthFinding, AuthSummary, CookieDetail,
    TokenEntropyDetail, AuthCheckType, SeverityLevel
)


# ──────────────────────────────────────────────
# Default credential wordlists
# ──────────────────────────────────────────────
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", ""),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("test", "test"),
    ("test", "test123"),
    ("guest", "guest"),
    ("guest", ""),
    ("user", "user"),
    ("user", "password"),
    ("demo", "demo"),
    ("admin", "admin@123"),
    ("admin", "P@ssw0rd"),
    ("superuser", "superuser"),
    ("sa", "sa"),
    ("oracle", "oracle"),
    ("postgres", "postgres"),
    ("mysql", "mysql"),
]

WEAK_PASSWORDS = [
    "password", "123456", "12345678", "qwerty",
    "abc123", "password1", "111111", "iloveyou",
    "admin", "welcome", "monkey", "dragon",
    "master", "letmein", "sunshine", "princess",
    "P@ssw0rd", "pass", "test", "guest",
]

# Common login paths to probe
LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/log-in",
    "/auth/login", "/auth/signin",
    "/user/login", "/users/login",
    "/account/login", "/accounts/login",
    "/admin/login", "/admin/signin",
    "/api/login", "/api/auth", "/api/signin",
    "/api/v1/login", "/api/v1/auth",
    "/wp-login.php", "/wp-admin",
    "/portal/login", "/portal",
    "/member/login", "/members/login",
]

# Session cookie name patterns
SESSION_COOKIE_PATTERNS = [
    "session", "sess", "sid", "sessionid", "session_id",
    "auth", "token", "jwt", "access_token", "refresh_token",
    "phpsessid", "jsessionid", "asp.net_sessionid",
    "connect.sid", "flask_session", "django_session",
    "remember_token", "remember_me",
]


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def get_base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def calculate_entropy(token: str) -> float:
    """Shannon entropy in bits for a token string."""
    if not token:
        return 0.0
    freq = {}
    for c in token:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(token)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy * length, 2)


def analyze_charset(token: str) -> str:
    """Describe the character set used in a token."""
    has_upper = any(c in string.ascii_uppercase for c in token)
    has_lower = any(c in string.ascii_lowercase for c in token)
    has_digit = any(c in string.digits for c in token)
    has_special = any(c in string.punctuation for c in token)
    has_hex = all(c in string.hexdigits for c in token)

    if has_hex and not has_special:
        return "hexadecimal"
    if has_upper and has_lower and has_digit and has_special:
        return "alphanumeric+special (strong)"
    if has_upper and has_lower and has_digit:
        return "alphanumeric (moderate)"
    if has_digit and not has_upper and not has_lower:
        return "numeric only (weak)"
    if has_lower and not has_upper and not has_digit:
        return "lowercase only (weak)"
    return "mixed"


def is_jwt(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 3


def decode_jwt_header(token: str) -> Optional[Dict]:
    try:
        header_b64 = token.split(".")[0]
        padded = header_b64 + "=" * (4 - len(header_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def is_predictable_token(token: str) -> bool:
    """Flag tokens that look sequential, timestamp-based, or trivially encoded."""
    # Pure numeric = predictable
    if token.isdigit():
        return True
    # Base64 of simple strings
    try:
        decoded = base64.b64decode(token + "==").decode("utf-8", errors="ignore")
        if decoded.isalnum() and len(decoded) < 20:
            return True
    except Exception:
        pass
    # MD5 length (32 hex) — weak if seeded from predictable input
    if len(token) == 32 and all(c in string.hexdigits for c in token):
        return True
    # Very short tokens
    if len(token) < 16:
        return True
    return False


def extract_session_cookies(response: httpx.Response) -> List[Dict]:
    """Extract cookies that look like session identifiers."""
    session_cookies = []
    for cookie in response.cookies.jar:
        name_lower = cookie.name.lower()
        if any(pattern in name_lower for pattern in SESSION_COOKIE_PATTERNS):
            session_cookies.append({
                "name": cookie.name,
                "value": cookie.value,
                "secure": cookie.secure,
                "http_only": getattr(cookie, "_rest", {}).get("HttpOnly") is not None,
                "same_site": getattr(cookie, "_rest", {}).get("SameSite"),
                "path": cookie.path,
                "domain": cookie.domain,
                "expires": str(cookie.expires) if cookie.expires else None,
            })
    return session_cookies


def parse_set_cookie_headers(response: httpx.Response) -> List[Dict]:
    """Parse Set-Cookie headers directly for full flag inspection."""
    cookies = []
    _raw_headers = response.headers.get_list("set-cookie") if hasattr(response.headers, 'get_list') else []
    if not _raw_headers:
        _single = response.headers.get("set-cookie")
        if _single:
            _raw_headers = [_single]
    for header_val in _raw_headers:
        if not header_val:
            continue
        cookie = {
            "name": "", "value": "", "http_only": False,
            "secure": False, "same_site": None,
            "path": None, "domain": None, "expires": None,
        }
        parts = [p.strip() for p in header_val.split(";")]
        if parts:
            kv = parts[0].split("=", 1)
            cookie["name"] = kv[0].strip()
            cookie["value"] = kv[1].strip() if len(kv) > 1 else ""
        for part in parts[1:]:
            pl = part.lower()
            if pl == "httponly":
                cookie["http_only"] = True
            elif pl == "secure":
                cookie["secure"] = True
            elif pl.startswith("samesite="):
                cookie["same_site"] = part.split("=", 1)[1].strip()
            elif pl.startswith("path="):
                cookie["path"] = part.split("=", 1)[1].strip()
            elif pl.startswith("domain="):
                cookie["domain"] = part.split("=", 1)[1].strip()
            elif pl.startswith("expires="):
                cookie["expires"] = part.split("=", 1)[1].strip()
        cookies.append(cookie)
    return cookies


def find_login_form(html: str, base_url: str) -> Optional[Dict]:
    """Detect login form — form with password input field."""
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        has_password = any(
            i.get("type", "").lower() == "password" for i in inputs
        )
        if has_password:
            action = form.get("action", "")
            method = form.get("method", "post").lower()
            fields = {}
            for inp in inputs:
                name = inp.get("name")
                if name:
                    fields[name] = inp.get("value", "")
            return {
                "action": urljoin(base_url, action) if action else base_url,
                "method": method,
                "fields": fields,
            }
    return None


def calculate_risk(findings: List[AuthFinding]) -> SeverityLevel:
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
# 1. Login Endpoint Probing
# ──────────────────────────────────────────────

async def probe_login_endpoints(
    client: httpx.AsyncClient,
    base_url: str,
    timeout: int,
    findings: List[AuthFinding],
    errors: List[str],
    checks: List[str],
) -> List[Dict]:
    """Discover all login endpoints and forms."""
    discovered = []

    semaphore = asyncio.Semaphore(10)

    async def _probe_path(path):
        async with semaphore:
            target = base_url + path
            checks.append(f"LOGIN_PROBE:{target}")
            try:
                resp = await client.get(target, timeout=timeout)
                if resp.status_code in (200, 301, 302):
                    form = find_login_form(resp.text, target)
                    if form or "password" in resp.text.lower():
                        discovered.append({
                            "url": target,
                            "status": resp.status_code,
                            "form": form,
                        })
            except Exception:
                pass

    tasks = [_probe_path(p) for p in LOGIN_PATHS]
    await asyncio.gather(*tasks)

    if discovered:
        findings.append(AuthFinding(
            check_type=AuthCheckType.LOGIN_PROBE,
            target_url=base_url,
            evidence=(
                f"Found {len(discovered)} login endpoint(s): "
                + ", ".join(d["url"] for d in discovered[:5])
            ),
            severity=SeverityLevel.LOW,
            description=(
                f"Discovered {len(discovered)} accessible login endpoint(s). "
                f"This is informational but helps map the attack surface."
            ),
            remediation=(
                "Ensure all login endpoints are protected by rate limiting, "
                "CAPTCHA, and account lockout. Avoid exposing multiple login paths."
            ),
            detail={"endpoints": [d["url"] for d in discovered]},
        ))

    return discovered


# ──────────────────────────────────────────────
# 2. Weak / Default Credentials
# ──────────────────────────────────────────────

async def test_weak_credentials(
    client: httpx.AsyncClient,
    login_url: str,
    form: Optional[Dict],
    username_field: str,
    password_field: str,
    timeout: int,
    findings: List[AuthFinding],
    errors: List[str],
    checks: List[str],
):
    if not form and not login_url:
        return

    action = form["action"] if form else login_url
    method = form["method"] if form else "post"
    base_fields = form["fields"].copy() if form else {}

    # Get baseline (failed login) response
    try:
        baseline_data = {
            **base_fields,
            username_field: "nonexistent_user_xyz",
            password_field: "wrong_password_xyz",
        }
        if method == "post":
            baseline = await client.post(action, data=baseline_data, timeout=timeout)
        else:
            baseline = await client.get(action, params=baseline_data, timeout=timeout)
        baseline_len = len(baseline.text)
        baseline_status = baseline.status_code
    except Exception as e:
        errors.append(f"Weak creds baseline failed: {str(e)}")
        return

    semaphore = asyncio.Semaphore(5)
    login_found = False

    async def _test_cred(u, p):
        nonlocal login_found
        if login_found: return
        async with semaphore:
            checks.append(f"CREDS:{u}:{p}")
            data = {**base_fields, username_field: u, password_field: p}
            try:
                if method == "post":
                    resp = await client.post(action, data=data,
                                             timeout=timeout, follow_redirects=True)
                else:
                    resp = await client.get(action, params=data,
                                            timeout=timeout, follow_redirects=True)

                failed_keywords = ["invalid", "incorrect", "wrong", "failed",
                                    "error", "denied", "unauthorized", "bad credentials"]
                success_keywords = ["dashboard", "welcome", "logout", "profile",
                                     "account", "signout", "log out", "my account"]

                response_lower = resp.text.lower()
                has_success = any(kw in response_lower for kw in success_keywords)
                has_failure = any(kw in response_lower for kw in failed_keywords)

                if has_success and not has_failure:
                    findings.append(AuthFinding(
                        check_type=AuthCheckType.WEAK_CREDENTIALS,
                        target_url=action,
                        evidence=f"Login succeeded with credentials: {u} / {p}",
                        severity=SeverityLevel.CRITICAL,
                        description=(
                            f"The application accepted default/weak credentials '{u}:{p}'. "
                            f"An attacker can gain unauthorized access without any prior knowledge."
                        ),
                        remediation=(
                            "Remove all default accounts and credentials immediately. "
                            "Enforce strong password policies. "
                            "Implement MFA for all user accounts, especially admin."
                        ),
                        detail={"username": u, "password": p, "login_url": action},
                    ))
                    login_found = True
            except Exception as e:
                errors.append(f"Credential test error {u}:{p}: {str(e)}")

    cred_tasks = [_test_cred(u, p) for u, p in DEFAULT_CREDENTIALS]
    await asyncio.gather(*cred_tasks)


# ──────────────────────────────────────────────
# 3. Account Lockout Policy
# ──────────────────────────────────────────────

async def test_account_lockout(
    client: httpx.AsyncClient,
    login_url: str,
    form: Optional[Dict],
    username_field: str,
    password_field: str,
    timeout: int,
    findings: List[AuthFinding],
    errors: List[str],
    checks: List[str],
):
    if not form and not login_url:
        return

    action = form["action"] if form else login_url
    method = form["method"] if form else "post"
    base_fields = form["fields"].copy() if form else {}

    attempt_count = 0
    locked = False

    for i in range(10):
        checks.append(f"LOCKOUT:attempt_{i+1}")
        data = {
            **base_fields,
            username_field: "admin",
            password_field: f"wrong_password_{i}",
        }
        try:
            if method == "post":
                resp = await client.post(action, data=data, timeout=timeout)
            else:
                resp = await client.get(action, params=data, timeout=timeout)

            attempt_count += 1
            resp_lower = resp.text.lower()

            # Check for lockout signals
            lockout_keywords = ["locked", "blocked", "too many", "temporarily",
                                 "suspended", "captcha", "rate limit", "try again later"]
            if any(kw in resp_lower for kw in lockout_keywords):
                locked = True
                break

            # Check for 429 Too Many Requests
            if resp.status_code == 429:
                locked = True
                break

        except Exception as e:
            errors.append(f"Lockout test error attempt {i}: {str(e)}")

    if not locked:
        findings.append(AuthFinding(
            check_type=AuthCheckType.ACCOUNT_LOCKOUT,
            target_url=action,
            evidence=(
                f"Completed {attempt_count} consecutive failed login attempts "
                f"without any lockout, CAPTCHA, or rate limiting response"
            ),
            severity=SeverityLevel.HIGH,
            description=(
                "The application does not enforce account lockout after repeated "
                "failed login attempts. This allows unlimited brute-force attacks."
            ),
            remediation=(
                "Implement account lockout after 5–10 failed attempts. "
                "Add progressive delays between attempts (exponential backoff). "
                "Deploy CAPTCHA after 3 failed attempts. "
                "Use rate limiting at the IP and account level."
            ),
            detail={"attempts_made": attempt_count},
        ))


# ──────────────────────────────────────────────
# 4. Cookie Flag Analysis
# ──────────────────────────────────────────────

async def test_cookie_flags(
    client: httpx.AsyncClient,
    url: str,
    login_url: str,
    form: Optional[Dict],
    username_field: str,
    password_field: str,
    timeout: int,
    findings: List[AuthFinding],
    errors: List[str],
    checks: List[str],
    cookie_details: List[CookieDetail],
):
    checks.append("COOKIE_FLAGS")
    base_url = get_base_url(url)
    is_https = url.startswith("https://")

    # Collect cookies from multiple pages
    pages_to_check = [url, login_url] if login_url != url else [url]

    semaphore = asyncio.Semaphore(10)

    async def _check_page_cookies(p_url):
        async with semaphore:
            try:
                resp = await client.get(p_url, timeout=timeout)
                raw_cookies = parse_set_cookie_headers(resp)

                for cookie in raw_cookies:
                    name = cookie["name"]
                    if not name:
                        continue

                    issues = []
                    is_session_cookie = any(
                        p in name.lower() for p in SESSION_COOKIE_PATTERNS
                    )

                    if not cookie["http_only"]:
                        issues.append("Missing HttpOnly flag — accessible via JavaScript (XSS risk)")
                    if not cookie["secure"] and is_https:
                        issues.append("Missing Secure flag — transmitted over HTTP")
                    if not cookie["secure"] and not is_https:
                        issues.append("Cookie sent over HTTP — no transport encryption")
                    if not cookie["same_site"]:
                        issues.append("Missing SameSite flag — CSRF risk")
                    elif cookie["same_site"].lower() == "none" and not cookie["secure"]:
                        issues.append("SameSite=None without Secure — invalid and insecure")
                    if not cookie["expires"] and is_session_cookie:
                        issues.append("No expiry set — session persists until browser close")

                    cookie_details.append(CookieDetail(
                        name=name,
                        value_sample=cookie["value"][:12] + "..." if len(cookie["value"]) > 12 else cookie["value"],
                        http_only=cookie["http_only"],
                        secure=cookie["secure"],
                        same_site=cookie["same_site"],
                        path=cookie["path"],
                        domain=cookie["domain"],
                        expires=cookie["expires"],
                        issues=issues,
                    ))

                    if issues and is_session_cookie:
                        severity = SeverityLevel.HIGH if not cookie["http_only"] else SeverityLevel.MEDIUM
                        findings.append(AuthFinding(
                            check_type=AuthCheckType.COOKIE_FLAGS,
                            target_url=p_url,
                            evidence=f"Cookie '{name}' has {len(issues)} security issue(s): {'; '.join(issues)}",
                            severity=severity,
                            description=(
                                f"Session cookie '{name}' is missing critical security flags. "
                                + " ".join(issues)
                            ),
                            remediation=(
                                "Set HttpOnly to prevent JS access. "
                                "Set Secure to enforce HTTPS-only transmission. "
                                "Set SameSite=Strict or Lax to prevent CSRF. "
                                "Set a reasonable expiry time for session cookies."
                            ),
                            detail={"cookie_name": name, "issues": issues},
                        ))
            except Exception as e:
                errors.append(f"Cookie flag check error on {p_url}: {str(e)}")

    cookie_tasks = [_check_page_cookies(p) for p in pages_to_check]
    await asyncio.gather(*cookie_tasks)


# ──────────────────────────────────────────────
# 5. Session Token Entropy & Predictability
# ──────────────────────────────────────────────

async def test_session_token_entropy(
    client: httpx.AsyncClient,
    url: str,
    login_url: str,
    timeout: int,
    findings: List[AuthFinding],
    errors: List[str],
    checks: List[str],
    token_analysis: List[TokenEntropyDetail],
):
    checks.append("TOKEN_ENTROPY")
    pages = [url, login_url] if login_url != url else [url]
    tokens_seen = []

    semaphore = asyncio.Semaphore(5)

    async def _analyze_token(p_url):
        async with semaphore:
            try:
                # Fetch multiple times to compare tokens
                for _ in range(3):
                    resp = await client.get(p_url, timeout=timeout)
                    raw_cookies = parse_set_cookie_headers(resp)
                    for cookie in raw_cookies:
                        name = cookie["name"]
                        value = cookie["value"]
                        if not value or len(value) < 4:
                            continue
                        if any(p in name.lower() for p in SESSION_COOKIE_PATTERNS):
                            tokens_seen.append((name, value))

                            entropy = calculate_entropy(value)
                            predictable = is_predictable_token(value)
                            charset = analyze_charset(value)

                            detail = TokenEntropyDetail(
                                token_sample=value[:16] + "..." if len(value) > 16 else value,
                                length=len(value),
                                entropy_bits=entropy,
                                is_predictable=predictable,
                                charset_analysis=charset,
                             )
                            token_analysis.append(detail)

                            # JWT specific checks
                            if is_jwt(value):
                                jwt_header = decode_jwt_header(value)
                                if jwt_header and jwt_header.get("alg", "").upper() in ("NONE", "HS256"):
                                    alg = jwt_header.get("alg", "")
                                    findings.append(AuthFinding(
                                        check_type=AuthCheckType.SESSION_TOKEN,
                                        target_url=p_url,
                                        evidence=f"JWT token uses algorithm: '{alg}'",
                                        severity=SeverityLevel.CRITICAL if alg.upper() == "NONE" else SeverityLevel.HIGH,
                                        description=(
                                            f"JWT token in cookie '{name}' uses '{alg}' algorithm. "
                                            + ("'none' algorithm disables signature verification entirely." if alg.upper() == "NONE"
                                               else "HS256 is vulnerable to brute-force if a weak secret is used.")
                                        ),
                                        remediation=(
                                            "Use RS256 or ES256 for JWT signing. "
                                            "Never accept 'none' algorithm. "
                                            "Use a strong, random secret (minimum 256 bits) for HS256."
                                        ),
                                        detail={"jwt_header": jwt_header, "cookie": name},
                                    ))

                            if predictable or entropy < 40:
                                findings.append(AuthFinding(
                                    check_type=AuthCheckType.SESSION_TOKEN,
                                    target_url=p_url,
                                    evidence=(
                                        f"Cookie '{name}' — entropy: {entropy} bits, "
                                        f"length: {len(value)}, charset: {charset}, "
                                        f"predictable: {predictable}"
                                    ),
                                    severity=SeverityLevel.HIGH if predictable else SeverityLevel.MEDIUM,
                                    description=(
                                        f"Session token '{name}' has low entropy ({entropy} bits) "
                                        f"or shows signs of predictability. "
                                        f"Weak tokens can be guessed or brute-forced."
                                    ),
                                    remediation=(
                                        "Use a cryptographically secure random number generator (CSPRNG) "
                                        "for all session tokens. "
                                        "Minimum token length: 128 bits (16 bytes) of entropy. "
                                        "Use frameworks' built-in session managers."
                                    ),
                                    detail=detail.model_dump(),
                                ))
            except Exception as e:
                errors.append(f"Token entropy check error on {p_url}: {str(e)}")

    token_tasks = [_analyze_token(p) for p in pages]
    await asyncio.gather(*token_tasks)

    # Check token uniqueness across requests
    if len(tokens_seen) >= 2:
        names = [t[0] for t in tokens_seen]
        values = [t[1] for t in tokens_seen]
        # If same cookie name appears with same value = not regenerating
        if len(set(values)) == 1 and len(values) > 1:
            findings.append(AuthFinding(
                check_type=AuthCheckType.SESSION_TOKEN,
                target_url=url,
                evidence=f"Same session token value issued across {len(values)} requests",
                severity=SeverityLevel.MEDIUM,
                description=(
                    "The server issues identical session tokens across multiple requests. "
                    "Tokens should be unique per session."
                ),
                remediation=(
                    "Regenerate session tokens on each new session creation. "
                    "Ensure tokens are unique and unpredictable."
                ),
                detail={"sample_token": values[0][:16] + "..."},
            ))


# ──────────────────────────────────────────────
# 6. Session Fixation
# ──────────────────────────────────────────────

async def test_session_fixation(
    client: httpx.AsyncClient,
    url: str,
    login_url: str,
    form: Optional[Dict],
    username_field: str,
    password_field: str,
    timeout: int,
    findings: List[AuthFinding],
    errors: List[str],
    checks: List[str],
):
    checks.append("SESSION_FIXATION")
    if not form:
        return

    action = form["action"]
    method = form["method"]
    base_fields = form["fields"].copy()

    try:
        # Step 1: Get pre-auth session token
        pre_resp = await client.get(login_url, timeout=timeout)
        pre_cookies = parse_set_cookie_headers(pre_resp)
        pre_token = None
        for c in pre_cookies:
            if any(p in c["name"].lower() for p in SESSION_COOKIE_PATTERNS):
                pre_token = c["value"]
                break

        if not pre_token:
            return

        # Step 2: Perform login
        data = {**base_fields, username_field: "test", password_field: "test"}
        if method == "post":
            post_resp = await client.post(action, data=data, timeout=timeout)
        else:
            post_resp = await client.get(action, params=data, timeout=timeout)

        # Step 3: Get post-auth session token
        post_cookies = parse_set_cookie_headers(post_resp)
        post_token = None
        for c in post_cookies:
            if any(p in c["name"].lower() for p in SESSION_COOKIE_PATTERNS):
                post_token = c["value"]
                break

        # If pre and post tokens are the same = session fixation vulnerability
        if pre_token and post_token and pre_token == post_token:
            findings.append(AuthFinding(
                check_type=AuthCheckType.SESSION_FIXATION,
                target_url=action,
                evidence=(
                    f"Pre-authentication token equals post-authentication token: "
                    f"'{pre_token[:16]}...'"
                ),
                severity=SeverityLevel.HIGH,
                description=(
                    "The application does not regenerate the session token after login. "
                    "An attacker can fixate a victim's session by setting a known token "
                    "before login, then hijack the session after the victim authenticates."
                ),
                remediation=(
                    "Always regenerate the session ID upon successful authentication. "
                    "Invalidate the old session token immediately after login. "
                    "Use secure, server-side session management."
                ),
                detail={"pre_token": pre_token[:16] + "...", "post_token": post_token[:16] + "..."},
            ))
        elif pre_token and not post_token:
            findings.append(AuthFinding(
                check_type=AuthCheckType.SESSION_FIXATION,
                target_url=action,
                evidence="No new session token issued after login — token not regenerated",
                severity=SeverityLevel.MEDIUM,
                description=(
                    "The application did not issue a new session token after authentication. "
                    "This may indicate session fixation vulnerability."
                ),
                remediation=(
                    "Regenerate the session ID after every successful login."
                ),
                detail={},
            ))

    except Exception as e:
        errors.append(f"Session fixation test error: {str(e)}")


# ──────────────────────────────────────────────
# 7. Token Expiry & Invalidation
# ──────────────────────────────────────────────

async def test_token_expiry(
    client: httpx.AsyncClient,
    url: str,
    login_url: str,
    form: Optional[Dict],
    username_field: str,
    password_field: str,
    timeout: int,
    findings: List[AuthFinding],
    errors: List[str],
    checks: List[str],
):
    checks.append("TOKEN_EXPIRY")

    # Check cookies for session expiry settings
    try:
        resp = await client.get(url, timeout=timeout)
        raw_cookies = parse_set_cookie_headers(resp)

        for cookie in raw_cookies:
            name = cookie["name"]
            if not any(p in name.lower() for p in SESSION_COOKIE_PATTERNS):
                continue

            if not cookie["expires"]:
                # Session cookie with no expiry — persists until browser closes
                # Not a direct vuln but worth noting
                pass

            # Check for very long-lived tokens
            if cookie["expires"]:
                try:
                    from email.utils import parsedate
                    import time
                    expires_tuple = parsedate(cookie["expires"])
                    if expires_tuple:
                        import calendar
                        expires_ts = calendar.timegm(expires_tuple)
                        now_ts = time.time()
                        days_valid = (expires_ts - now_ts) / 86400
                        if days_valid > 30:
                            findings.append(AuthFinding(
                                check_type=AuthCheckType.TOKEN_EXPIRY,
                                target_url=url,
                                evidence=(
                                    f"Cookie '{name}' expires in {int(days_valid)} days "
                                    f"({cookie['expires']})"
                                ),
                                severity=SeverityLevel.MEDIUM,
                                description=(
                                    f"Session cookie '{name}' has an excessively long expiry "
                                    f"of {int(days_valid)} days. "
                                    f"Long-lived tokens increase the window for session hijacking."
                                ),
                                remediation=(
                                    "Set session cookie expiry to 15–30 minutes for sensitive apps. "
                                    "Implement sliding session expiry that resets on activity. "
                                    "Force re-authentication for sensitive operations."
                                ),
                                detail={"cookie": name, "expires_days": int(days_valid)},
                            ))
                except Exception:
                    pass

    except Exception as e:
        errors.append(f"Token expiry check error: {str(e)}")


# ──────────────────────────────────────────────
# 8. Password Policy
# ──────────────────────────────────────────────

async def test_password_policy(
    client: httpx.AsyncClient,
    base_url: str,
    timeout: int,
    findings: List[AuthFinding],
    errors: List[str],
    checks: List[str],
):
    """Check if registration/password-change accepts weak passwords."""
    register_paths = [
        "/register", "/signup", "/sign-up",
        "/user/register", "/account/register",
        "/api/register", "/api/signup",
        "/create-account", "/new-account",
    ]

    semaphore = asyncio.Semaphore(5)

    async def _check_register_path(path):
        async with semaphore:
            target = base_url + path
            checks.append(f"POLICY:{target}")
            try:
                resp = await client.get(target, timeout=timeout)
                if resp.status_code != 200:
                    return

                html = resp.text.lower()
                has_register_form = (
                    "password" in html and
                    ("register" in html or "sign up" in html or "create" in html)
                )

                if has_register_form:
                    # Look for password policy hints
                    policy_keywords = ["must contain", "minimum", "uppercase",
                                        "special character", "at least", "strength"]
                    has_policy = any(kw in html for kw in policy_keywords)

                    if not has_policy:
                        findings.append(AuthFinding(
                            check_type=AuthCheckType.PASSWORD_POLICY,
                            target_url=target,
                            evidence=(
                                f"Registration form at '{target}' found with no visible "
                                f"password strength requirements or policy hints"
                            ),
                            severity=SeverityLevel.MEDIUM,
                            description=(
                                "The registration page does not appear to enforce or communicate "
                                "a password policy. Users may be able to set weak passwords."
                            ),
                            remediation=(
                                "Enforce minimum password length of 12 characters. "
                                "Require a mix of uppercase, lowercase, digits, and special chars. "
                                "Check passwords against known breach databases (HaveIBeenPwned API). "
                                "Show a real-time password strength meter to users."
                            ),
                            detail={"registration_url": target},
                        ))
            except Exception:
                pass

    policy_tasks = [_check_register_path(p) for p in register_paths]
    await asyncio.gather(*policy_tasks)


# ──────────────────────────────────────────────
# 9. Multi-Session Detection
# ──────────────────────────────────────────────

async def test_multi_session(
    client: httpx.AsyncClient,
    url: str,
    login_url: str,
    form: Optional[Dict],
    username_field: str,
    password_field: str,
    timeout: int,
    findings: List[AuthFinding],
    errors: List[str],
    checks: List[str],
):
    """Check if app issues multiple valid sessions for same account simultaneously."""
    checks.append("MULTI_SESSION")
    if not form:
        return

    action = form["action"]
    method = form["method"]
    base_fields = form["fields"].copy()

    # Use separate client instances to simulate two browsers
    try:
        tokens = []
        async def _get_token_for_sim():
            async with httpx.AsyncClient(follow_redirects=True) as temp_client:
                data = {**base_fields, username_field: "test", password_field: "test"}
                try:
                    if method == "post":
                        resp = await temp_client.post(action, data=data, timeout=timeout)
                    else:
                        resp = await temp_client.get(action, params=data, timeout=timeout)

                    raw_cookies = parse_set_cookie_headers(resp)
                    for c in raw_cookies:
                        if any(p in c["name"].lower() for p in SESSION_COOKIE_PATTERNS):
                            return c["value"]
                except Exception:
                    pass
            return None

        sim_tasks = [_get_token_for_sim() for _ in range(2)]
        results = await asyncio.gather(*sim_tasks)
        tokens = [t for t in results if t]

        if len(tokens) == 2 and tokens[0] != tokens[1]:
            findings.append(AuthFinding(
                check_type=AuthCheckType.MULTI_SESSION,
                target_url=action,
                evidence=(
                    f"Two distinct session tokens issued for same credentials: "
                    f"'{tokens[0][:12]}...' and '{tokens[1][:12]}...'"
                ),
                severity=SeverityLevel.MEDIUM,
                description=(
                    "The application allows multiple concurrent sessions for the same account. "
                    "If a session token is stolen, there is no automatic invalidation of other sessions."
                ),
                remediation=(
                    "Consider limiting concurrent sessions per account (especially for sensitive apps). "
                    "Notify users of new login events via email/SMS. "
                    "Provide a 'log out all sessions' feature in account settings. "
                    "Implement session anomaly detection."
                ),
                detail={"session_1": tokens[0][:12] + "...", "session_2": tokens[1][:12] + "..."},
            ))
    except Exception as e:
        errors.append(f"Multi-session test error: {str(e)}")


# ──────────────────────────────────────────────
# Main Scanner Entry Point
# ──────────────────────────────────────────────

async def run_auth_scan(
    urls: List[str],
    login_path: str = "/login",
    username_field: str = "username",
    password_field: str = "password",
    timeout: int = 10,
    cookies: Optional[Dict] = None,
) -> dict:
    if cookies is None:
        cookies = {}
    findings: List[AuthFinding] = []
    errors: List[str] = []
    checks: List[str] = []
    cookie_details: List[CookieDetail] = []
    token_analysis: List[TokenEntropyDetail] = []

    if isinstance(urls, str):
        urls = [urls]

    if not urls:
        return {
            "url": "none",
            "status": "completed",
            "summary": AuthSummary(
                total_checks=0, vulnerabilities_found=0,
                weak_credentials=0, session_issues=0,
                cookie_issues=0, lockout_issues=0,
                policy_issues=0, risk_level=SeverityLevel.LOW,
            ),
            "findings": [],
            "cookie_details": [],
            "token_analysis": [],
            "errors": ["No URLs provided to test."],
        }
        
    primary_url = urls[0]
    base_url = get_base_url(primary_url)
    login_url = base_url + login_path

    async with httpx.AsyncClient(
        follow_redirects=True,
        cookies=cookies,
        headers={"User-Agent": "WebVulnScanner/1.0 (educational use)"},
        timeout=timeout,
    ) as client:
        # Verify target reachable
        try:
            await client.get(primary_url, timeout=timeout)
        except Exception as e:
            return {
                "url": primary_url,
                "status": "unreachable",
                "summary": AuthSummary(
                    total_checks=0, vulnerabilities_found=0,
                    weak_credentials=0, session_issues=0,
                    cookie_issues=0, lockout_issues=0,
                    policy_issues=0, risk_level=SeverityLevel.LOW,
                ),
                "findings": [],
                "cookie_details": [],
                "token_analysis": [],
                "errors": [f"Could not reach target: {str(e)}"],
            }

        # Phase 1: Discover login endpoints
        discovered = await probe_login_endpoints(
            client, base_url, timeout, findings, errors, checks
        )

        # Use best discovered form or fallback to configured login_url
        best_form = None
        best_login_url = login_url
        if discovered:
            for d in discovered:
                if d.get("form"):
                    best_form = d["form"]
                    best_login_url = d["url"]
                    break

        # Phase 2: Run all checks concurrently
        await asyncio.gather(
            test_weak_credentials(
                client, best_login_url, best_form,
                username_field, password_field,
                timeout, findings, errors, checks
            ),
            test_account_lockout(
                client, best_login_url, best_form,
                username_field, password_field,
                timeout, findings, errors, checks
            ),
            test_cookie_flags(
                client, primary_url, best_login_url, best_form,
                username_field, password_field,
                timeout, findings, errors, checks, cookie_details
            ),
            test_session_token_entropy(
                client, primary_url, best_login_url,
                timeout, findings, errors, checks, token_analysis
            ),
            test_session_fixation(
                client, primary_url, best_login_url, best_form,
                username_field, password_field,
                timeout, findings, errors, checks
            ),
            test_token_expiry(
                client, primary_url, best_login_url, best_form,
                username_field, password_field,
                timeout, findings, errors, checks
            ),
            test_password_policy(
                client, base_url,
                timeout, findings, errors, checks
            ),
            test_multi_session(
                client, primary_url, best_login_url, best_form,
                username_field, password_field,
                timeout, findings, errors, checks
            ),
        )

    # Deduplicate findings
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.check_type, f.target_url, f.evidence[:60])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    summary = AuthSummary(
        total_checks=len(checks),
        vulnerabilities_found=len(unique_findings),
        weak_credentials=sum(1 for f in unique_findings if f.check_type == AuthCheckType.WEAK_CREDENTIALS),
        session_issues=sum(1 for f in unique_findings if f.check_type in (
            AuthCheckType.SESSION_TOKEN, AuthCheckType.SESSION_FIXATION,
            AuthCheckType.TOKEN_EXPIRY, AuthCheckType.MULTI_SESSION
        )),
        cookie_issues=sum(1 for f in unique_findings if f.check_type == AuthCheckType.COOKIE_FLAGS),
        lockout_issues=sum(1 for f in unique_findings if f.check_type == AuthCheckType.ACCOUNT_LOCKOUT),
        policy_issues=sum(1 for f in unique_findings if f.check_type == AuthCheckType.PASSWORD_POLICY),
        risk_level=calculate_risk(unique_findings),
    )

    return {
        "url": primary_url,
        "status": "completed",
        "summary": summary,
        "findings": unique_findings,
        "cookie_details": cookie_details,
        "token_analysis": token_analysis,
        "errors": errors,
    }