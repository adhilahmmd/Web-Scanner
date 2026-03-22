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
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
from typing import List, Dict, Tuple, Optional
from models.xss_models import (
    XSSFinding, XSSSummary, XSSResult,
    XSSType, InjectionPoint, SeverityLevel
)


# ──────────────────────────────────────────────
# Payload Sets
# ──────────────────────────────────────────────

# Each payload has a unique marker we can search for in the response
REFLECTED_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<body onload=alert(1)>',
    '<<script>alert(1)//<</script>',
    '<ScRiPt>alert(1)</ScRiPt>',          # case bypass
    '%3Cscript%3Ealert(1)%3C/script%3E',  # URL encoded
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',  # HTML entity
    '<details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
]

DOM_PAYLOADS = [
    '#<script>alert(1)</script>',
    '#"><script>alert(1)</script>',
    '#<img src=x onerror=alert(1)>',
    '?q=<script>alert(1)</script>',
    'javascript:alert(document.domain)',
    '#javascript:alert(1)',
]

STORED_XSS_MARKERS = [
    '<script>alert("STORED_XSS_TEST")</script>',
    '<img src=x onerror=alert("STORED_XSS_TEST")>',
    '<svg onload=alert("STORED_XSS_TEST")>',
    '"><script>alert("STORED_XSS_TEST")</script>',
]

HEADER_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
]

JSON_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
]

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


def payload_reflected(payload: str, response_text: str) -> bool:
    """Check if payload or its key identifiers appear in response."""
    checks = [
        payload.lower() in response_text.lower(),
        "<script>" in response_text.lower() and "alert" in response_text.lower(),
        "onerror=alert" in response_text.lower(),
        "onload=alert" in response_text.lower(),
        "onfocus=alert" in response_text.lower(),
        "ontoggle=alert" in response_text.lower(),
    ]
    return any(checks)


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

    for param in params:
        for payload in REFLECTED_PAYLOADS:
            payloads_tested.append(payload)
            injected_url = inject_url_param(url, param, payload)
            try:
                resp = await client.get(injected_url, timeout=timeout)
                if payload_reflected(payload, resp.text):
                    findings.append(XSSFinding(
                        xss_type=XSSType.REFLECTED,
                        injection_point=InjectionPoint.URL_PARAM,
                        parameter=param,
                        payload=payload,
                        evidence=f"Payload found unescaped in response body for parameter '{param}'",
                        severity=SeverityLevel.HIGH,
                        description=(
                            f"URL parameter '{param}' is vulnerable to Reflected XSS. "
                            f"The application echoes user input back into the HTML without sanitization."
                        ),
                        remediation=(
                            "Encode all user-supplied output using context-aware escaping "
                            "(HTML entity encoding). Implement a Content Security Policy (CSP) header. "
                            "Use a templating engine with auto-escaping enabled."
                        ),
                    ))
                    break  # One finding per param is enough
            except httpx.TimeoutException:
                errors.append(f"Timeout on URL param '{param}'")
            except Exception as e:
                errors.append(f"Error on URL param '{param}': {str(e)}")


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

        for field_name in base_inputs:
            for payload in REFLECTED_PAYLOADS[:6]:  # limit payloads per field
                payloads_tested.append(payload)
                data = {**base_inputs, field_name: payload}

                try:
                    if method == "post":
                        resp = await client.post(action, data=data, timeout=timeout)
                    else:
                        resp = await client.get(action, params=data, timeout=timeout)

                    # Check reflected XSS
                    if payload_reflected(payload, resp.text):
                        findings.append(XSSFinding(
                            xss_type=XSSType.REFLECTED,
                            injection_point=injection_point,
                            parameter=field_name,
                            payload=payload,
                            evidence=(
                                f"Payload reflected in form response via {method.upper()} "
                                f"to '{action}' for field '{field_name}'"
                            ),
                            severity=SeverityLevel.HIGH,
                            description=(
                                f"Form field '{field_name}' at '{action}' is vulnerable to "
                                f"Reflected XSS via {method.upper()} submission."
                            ),
                            remediation=(
                                "Sanitize and encode all form input before rendering. "
                                "Use CSRF tokens on all forms. "
                                "Implement strict CSP headers."
                            ),
                        ))
                        break

                except httpx.TimeoutException:
                    errors.append(f"Timeout on form field '{field_name}'")
                except Exception as e:
                    errors.append(f"Error on form '{action}': {str(e)}")

        # Stored XSS: submit payload then re-fetch page and check persistence
        for payload in STORED_XSS_MARKERS[:2]:
            payloads_tested.append(payload)
            data = {k: payload for k in base_inputs}
            try:
                if method == "post":
                    await client.post(action, data=data, timeout=timeout)
                else:
                    await client.get(action, params=data, timeout=timeout)

                # Re-fetch the page to check if payload persists
                check_resp = await client.get(url, timeout=timeout)
                if "STORED_XSS_TEST" in check_resp.text:
                    findings.append(XSSFinding(
                        xss_type=XSSType.STORED,
                        injection_point=injection_point,
                        parameter=", ".join(base_inputs.keys()),
                        payload=payload,
                        evidence=f"Stored XSS payload 'STORED_XSS_TEST' found when re-visiting '{url}'",
                        severity=SeverityLevel.CRITICAL,
                        description=(
                            f"The form at '{action}' stores user input which is later rendered "
                            f"unescaped — confirming Stored (Persistent) XSS."
                        ),
                        remediation=(
                            "Sanitize data on both input AND output. "
                            "Use a allowlist-based HTML sanitizer (e.g. DOMPurify). "
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
                payload=", ".join(DOM_PAYLOADS[:3]),
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
            for payload in DOM_PAYLOADS[:3]:
                payloads_tested.append(payload)
                test_url = url + payload
                try:
                    dom_resp = await client.get(test_url, timeout=timeout)
                    if payload_reflected(payload, dom_resp.text):
                        findings.append(XSSFinding(
                            xss_type=XSSType.DOM,
                            injection_point=InjectionPoint.URL_PARAM,
                            parameter="URL fragment / hash",
                            payload=payload,
                            evidence=f"DOM payload reflected in server response for: {test_url}",
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

    for header_name in headers_to_test:
        for payload in HEADER_PAYLOADS:
            payloads_tested.append(payload)
            custom_headers = {**headers_to_test, header_name: payload}
            try:
                resp = await client.get(url, headers=custom_headers, timeout=timeout)
                if payload_reflected(payload, resp.text):
                    findings.append(XSSFinding(
                        xss_type=XSSType.REFLECTED,
                        injection_point=InjectionPoint.HEADER,
                        parameter=header_name,
                        payload=payload,
                        evidence=(
                            f"XSS payload injected via HTTP header '{header_name}' "
                            f"was reflected in the response body."
                        ),
                        severity=SeverityLevel.HIGH,
                        description=(
                            f"The application reflects the value of the '{header_name}' "
                            f"HTTP header into the HTML response without sanitization."
                        ),
                        remediation=(
                            "Never reflect raw HTTP header values into HTML responses. "
                            "Sanitize and encode any header-derived values before output. "
                            "Implement CSP headers to mitigate XSS impact."
                        ),
                    ))
                    break
            except httpx.TimeoutException:
                errors.append(f"Timeout on header XSS test for '{header_name}'")
            except Exception as e:
                errors.append(f"Header XSS error for '{header_name}': {str(e)}")


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

    for param in params:
        for payload in JSON_PAYLOADS[:4]:
            payloads_tested.append(payload)
            json_body = {param: payload}
            try:
                resp = await client.post(
                    url,
                    json=json_body,
                    headers=json_headers,
                    timeout=timeout,
                )
                content_type = resp.headers.get("content-type", "")

                # If JSON response reflects our payload unescaped
                if payload in resp.text and "application/json" not in content_type:
                    findings.append(XSSFinding(
                        xss_type=XSSType.REFLECTED,
                        injection_point=InjectionPoint.JSON,
                        parameter=param,
                        payload=payload,
                        evidence=(
                            f"XSS payload in JSON body for key '{param}' was reflected "
                            f"in a non-JSON response (content-type: {content_type})"
                        ),
                        severity=SeverityLevel.MEDIUM,
                        description=(
                            f"The endpoint accepted a JSON payload with XSS in field '{param}' "
                            f"and reflected it back in an HTML response — indicating improper "
                            f"output encoding for JSON-sourced data."
                        ),
                        remediation=(
                            "Ensure JSON API responses always return Content-Type: application/json. "
                            "Encode all JSON values before rendering in HTML context. "
                            "Use JSON.stringify() safely and avoid injecting JSON directly into HTML."
                        ),
                    ))
                    break
            except httpx.TimeoutException:
                errors.append(f"Timeout on JSON XSS test for '{param}'")
            except Exception as e:
                errors.append(f"JSON XSS error for '{param}': {str(e)}")


# ──────────────────────────────────────────────
# Main Scanner Entry Point
# ──────────────────────────────────────────────

async def run_xss_scan(
    url: str,
    timeout: int = 10,
    test_forms: bool = True,
    test_headers: bool = True,
    test_json: bool = True,
) -> dict:
    findings: List[XSSFinding] = []
    errors: List[str] = []
    payloads_tested: List[str] = []

    async with httpx.AsyncClient(
        follow_redirects=True,
        headers={"User-Agent": "WebVulnScanner/1.0 (educational use)"},
    ) as client:
        # Verify target is reachable
        try:
            await client.get(url, timeout=timeout)
        except Exception as e:
            return {
                "url": url,
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

        # Run all test types concurrently
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

    # Deduplicate by (xss_type, parameter)
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.xss_type, f.parameter)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    reflected_count = sum(1 for f in unique_findings if f.xss_type == XSSType.REFLECTED)
    stored_count = sum(1 for f in unique_findings if f.xss_type == XSSType.STORED)
    dom_count = sum(1 for f in unique_findings if f.xss_type == XSSType.DOM)

    params = extract_url_params(url)
    summary = XSSSummary(
        total_parameters_tested=len(params),
        total_payloads_tested=len(payloads_tested),
        vulnerabilities_found=len(unique_findings),
        reflected_xss=reflected_count,
        stored_xss=stored_count,
        dom_xss=dom_count,
        risk_level=calculate_risk(unique_findings),
    )

    return {
        "url": url,
        "status": "completed",
        "summary": summary,
        "findings": unique_findings,
        "errors": errors,
    }