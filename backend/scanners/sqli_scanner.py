"""
SQL Injection Scanner Module
Detects common SQL injection vulnerabilities by testing
URL parameters with a curated payload set.
"""

import httpx
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Tuple
from models.sqli_models import VulnerabilityFinding, ScanSummary, SeverityLevel


# ──────────────────────────────────────────────
# Payload sets grouped by technique
# ──────────────────────────────────────────────
PAYLOADS: Dict[str, List[str]] = {
    "error_based": [
        "'",
        "''",
        "`",
        "\"",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1 UNION SELECT NULL--",
        "1 UNION SELECT NULL,NULL--",
    ],
    "boolean_based": [
        "' AND '1'='1",
        "' AND '1'='2",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND 1=1--",
        "' AND 1=2--",
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5'--",       # MSSQL
        "' OR SLEEP(5)--",                   # MySQL
        "'; SELECT pg_sleep(5)--",           # PostgreSQL
        "' OR 1=1; SELECT pg_sleep(5)--",
    ],
}

# ──────────────────────────────────────────────
# Error signatures to look for in responses
# ──────────────────────────────────────────────
SQL_ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "supplied argument is not a valid mysql",
    # MSSQL
    "unclosed quotation mark",
    "incorrect syntax near",
    "microsoft sql native client error",
    "mssql_query()",
    "[sql server]",
    # PostgreSQL
    "pg_query():",
    "pg::syntaxerror",
    "unterminated quoted string at or near",
    "postgresql",
    # Oracle
    "ora-00933",
    "ora-00907",
    "oracle error",
    "ora-01756",
    # SQLite
    "sqlite3::query",
    "sqlite_error",
    "sql error",
    # Generic
    "syntax error",
    "jdbc sqlexception",
    "odbc microsoft access driver",
    "index was outside the bounds of the array",
]

TIME_DELAY_THRESHOLD = 4.0  # seconds


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def extract_parameters(url: str) -> Dict[str, str]:
    """Extract query parameters from a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] for k, v in params.items()}


def inject_payload(url: str, param: str, payload: str) -> str:
    """Replace a single parameter value with a payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def detect_sql_error(response_text: str) -> Tuple[bool, str]:
    """Check if the response contains SQL error signatures."""
    lower = response_text.lower()
    for sig in SQL_ERROR_SIGNATURES:
        if sig in lower:
            return True, sig
    return False, ""


def calculate_risk(findings: list) -> SeverityLevel:
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
# Core Scanner
# ──────────────────────────────────────────────

async def test_error_based(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    timeout: int,
    findings: list,
    errors: list,
    payloads_tested: list,
):
    """Test for error-based SQL injection."""
    for payload in PAYLOADS["error_based"]:
        payloads_tested.append(payload)
        injected_url = inject_payload(url, param, payload)
        try:
            resp = await client.get(injected_url, timeout=timeout)
            found, evidence = detect_sql_error(resp.text)
            if found:
                findings.append(VulnerabilityFinding(
                    parameter=param,
                    payload=payload,
                    evidence=f"SQL error signature detected: '{evidence}'",
                    severity=SeverityLevel.HIGH,
                    description=(
                        f"Parameter '{param}' is vulnerable to error-based SQL injection. "
                        f"The application exposed a database error when the payload was injected."
                    ),
                    remediation=(
                        "Use parameterized queries / prepared statements. "
                        "Never concatenate user input directly into SQL queries. "
                        "Implement input validation and suppress detailed error messages in production."
                    ),
                ))
                return  # One confirmed finding per param is enough
        except httpx.TimeoutException:
            errors.append(f"Timeout on param '{param}' with payload: {payload}")
        except Exception as e:
            errors.append(f"Error on param '{param}': {str(e)}")


async def test_boolean_based(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    timeout: int,
    findings: list,
    errors: list,
    payloads_tested: list,
    baseline_length: int,
):
    """Test for boolean-based blind SQL injection by comparing response lengths."""
    true_payloads = ["' AND '1'='1", "1 AND 1=1", "' AND 1=1--"]
    false_payloads = ["' AND '1'='2", "1 AND 1=2", "' AND 1=2--"]

    for true_p, false_p in zip(true_payloads, false_payloads):
        payloads_tested.extend([true_p, false_p])
        try:
            true_url = inject_payload(url, param, true_p)
            false_url = inject_payload(url, param, false_p)

            true_resp = await client.get(true_url, timeout=timeout)
            false_resp = await client.get(false_url, timeout=timeout)

            true_len = len(true_resp.text)
            false_len = len(false_resp.text)
            diff = abs(true_len - false_len)

            # Significant difference AND true response ≈ baseline = likely boolean SQLi
            baseline_diff = abs(true_len - baseline_length)
            if diff > 50 and baseline_diff < 100:
                findings.append(VulnerabilityFinding(
                    parameter=param,
                    payload=f"TRUE: {true_p} | FALSE: {false_p}",
                    evidence=(
                        f"Response length difference: TRUE payload={true_len} chars, "
                        f"FALSE payload={false_len} chars (diff={diff})"
                    ),
                    severity=SeverityLevel.HIGH,
                    description=(
                        f"Parameter '{param}' appears vulnerable to boolean-based blind SQL injection. "
                        f"The application returns different content based on true/false conditions."
                    ),
                    remediation=(
                        "Use parameterized queries / prepared statements. "
                        "Validate and sanitize all user-supplied input. "
                        "Implement a Web Application Firewall (WAF) as an additional layer."
                    ),
                ))
                return
        except httpx.TimeoutException:
            errors.append(f"Timeout on boolean test for param '{param}'")
        except Exception as e:
            errors.append(f"Error on boolean test for param '{param}': {str(e)}")


async def test_time_based(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    timeout: int,
    findings: list,
    errors: list,
    payloads_tested: list,
):
    """Test for time-based blind SQL injection by measuring response delay."""
    for payload in PAYLOADS["time_based"]:
        payloads_tested.append(payload)
        injected_url = inject_payload(url, param, payload)
        try:
            import time
            start = time.monotonic()
            await client.get(injected_url, timeout=max(timeout, 10))
            elapsed = time.monotonic() - start

            if elapsed >= TIME_DELAY_THRESHOLD:
                findings.append(VulnerabilityFinding(
                    parameter=param,
                    payload=payload,
                    evidence=f"Response delayed by {elapsed:.2f}s (threshold: {TIME_DELAY_THRESHOLD}s)",
                    severity=SeverityLevel.CRITICAL,
                    description=(
                        f"Parameter '{param}' is vulnerable to time-based blind SQL injection. "
                        f"The database executed a sleep/delay function, confirming injection."
                    ),
                    remediation=(
                        "Immediately switch to parameterized queries / prepared statements. "
                        "Audit all database queries in the codebase. "
                        "Restrict database user permissions to minimum required. "
                        "Consider using an ORM with built-in SQL injection protection."
                    ),
                ))
                return
        except httpx.TimeoutException:
            # A timeout itself can indicate time-based SQLi
            findings.append(VulnerabilityFinding(
                parameter=param,
                payload=payload,
                evidence=f"Request timed out — possible time-based injection triggered",
                severity=SeverityLevel.MEDIUM,
                description=(
                    f"Parameter '{param}' caused a request timeout with a time-delay payload. "
                    f"This may indicate time-based blind SQL injection."
                ),
                remediation=(
                    "Use parameterized queries. Investigate application logs for unusual query times."
                ),
            ))
            return
        except Exception as e:
            errors.append(f"Error on time-based test for param '{param}': {str(e)}")


# ──────────────────────────────────────────────
# Main Scanner Entry Point
# ──────────────────────────────────────────────

async def run_sqli_scan(urls: List[str], timeout: int = 10) -> dict:
    """
    Run a full SQL injection scan against all parameters in the given URLs.
    Returns a dict compatible with ScanResult model.
    """
    findings: List[VulnerabilityFinding] = []
    errors: List[str] = []
    payloads_tested: List[str] = []

    if isinstance(urls, str):
        urls = [urls]
        
    if not urls:
        return {
            "url": "none",
            "status": "completed",
            "summary": ScanSummary(
                total_parameters=0,
                total_payloads_tested=0,
                vulnerabilities_found=0,
                risk_level=SeverityLevel.LOW,
            ),
            "findings": [],
            "errors": ["No URLs provided to test."],
        }
        
    primary_url = urls[0]
    total_params = 0

    async with httpx.AsyncClient(follow_redirects=True) as client:
        for url in urls:
            params = extract_parameters(url)
            if not params:
                continue
            
            total_params += len(params)

            # Get baseline response
            try:
                baseline = await client.get(url, timeout=timeout)
                baseline_length = len(baseline.text)
            except Exception as e:
                errors.append(f"Could not reach target URL {url}: {str(e)}")
                continue

            # Test each parameter concurrently with a limit
            semaphore = asyncio.Semaphore(5)  # max 5 concurrent tests for this site

            async def _test_param(p):
                async with semaphore:
                    tasks = [
                        test_error_based(client, url, p, timeout, findings, errors, payloads_tested),
                        test_boolean_based(client, url, p, timeout, findings, errors, payloads_tested, baseline_length),
                        test_time_based(client, url, p, timeout, findings, errors, payloads_tested),
                    ]
                    await asyncio.gather(*tasks)

            param_tasks = [_test_param(param) for param in params]
            await asyncio.gather(*param_tasks)

    # Deduplicate findings by parameter and url
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.parameter, f.payload)
        if key not in seen:
            unique_findings.append(f)
            seen.add(key)

    summary = ScanSummary(
        total_parameters=total_params,
        total_payloads_tested=len(payloads_tested),
        vulnerabilities_found=len(unique_findings),
        risk_level=calculate_risk(unique_findings),
    )

    return {
        "url": primary_url,
        "status": "completed",
        "summary": summary,
        "findings": unique_findings,
        "errors": errors,
    }