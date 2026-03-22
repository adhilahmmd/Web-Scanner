"""
Unified Scan Orchestrator Router
Runs multiple scanner modules concurrently for a single target URL.
If a valid JWT is provided, scan results are saved to the database.
"""

import json
import time
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
import uuid

from sqlalchemy.orm import Session

from scanners.crawler_scanner import run_crawler
from scanners.sqli_scanner import run_sqli_scan
from scanners.xss_scanner import run_xss_scan
from scanners.bac_scanner import run_bac_scan
from scanners.auth_scanner import run_auth_scan
from scanners.ssl_scanner import run_ssl_scan
from scanners.http_scanner import run_headers_scan

from core.dependencies import get_optional_user, get_db
from database.models import User, ScanResult

router = APIRouter()

# In-memory job store
unified_jobs: Dict[str, dict] = {}

AVAILABLE_MODULES = ["crawler", "sqli", "xss", "bac", "auth", "ssl", "headers"]


class UnifiedScanRequest(BaseModel):
    url: str
    modules: Optional[List[str]] = AVAILABLE_MODULES
    timeout: Optional[int] = 10

    class Config:
        json_schema_extra = {
            "example": {
                "url": "http://testphp.vulnweb.com",
                "modules": ["sqli", "xss", "headers", "ssl"],
                "timeout": 10
            }
        }


class UnifiedScanResult(BaseModel):
    url: str
    modules_requested: List[str]
    modules_completed: List[str]
    modules_failed: List[str]
    results: Dict[str, Any]
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    overall_risk: str
    saved_to_history: bool = False
    history_id: Optional[int] = None


async def _run_module(module: str, url: str, timeout: int) -> tuple[str, Any]:
    """Run a single scanner module and return (module_name, result)."""
    try:
        if module == "crawler":
            result = await run_crawler(url=url, max_depth=2, max_pages=20, timeout=timeout)
        elif module == "sqli":
            result = await run_sqli_scan(url=url, timeout=timeout)
        elif module == "xss":
            result = await run_xss_scan(url=url, timeout=timeout, test_forms=True, test_headers=True, test_json=True)
        elif module == "bac":
            result = await run_bac_scan(url=url, timeout=timeout, cookies={}, extra_headers={})
        elif module == "auth":
            result = await run_auth_scan(url=url, login_path=None, username_field="username",
                                          password_field="password", timeout=timeout, cookies={})
        elif module == "ssl":
            result = await run_ssl_scan(url=url, timeout=timeout)
        elif module == "headers":
            result = await run_headers_scan(url=url, timeout=timeout, follow_redirects=True)
        else:
            return module, {"error": f"Unknown module: {module}"}
        return module, result
    except Exception as e:
        return module, {"error": str(e)}


def _count_vulns(results: Dict[str, Any]) -> Dict[str, int]:
    """Count vulnerabilities across all module results."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}

    for module, data in results.items():
        if not data or "error" in data:
            continue
        findings = data.get("findings", [])
        for finding in findings:
            sev = (finding.get("severity") or "").lower()
            if sev in counts:
                counts[sev] += 1
            counts["total"] += 1

    return counts


def _compute_risk(counts: Dict[str, int]) -> str:
    if counts.get("critical", 0) > 0:
        return "critical"
    elif counts.get("high", 0) > 0:
        return "high"
    elif counts.get("medium", 0) > 0:
        return "medium"
    elif counts.get("low", 0) > 0:
        return "low"
    return "info"


def _save_scan_to_db(
    db: Session,
    user: User,
    result: UnifiedScanResult,
    duration_seconds: int,
) -> int:
    """Persist a completed scan to the database. Returns the new scan ID."""
    scan = ScanResult(
        user_id=user.id,
        target_url=result.url,
        modules_run=json.dumps(result.modules_requested),
        result_json=json.dumps(result.results),
        risk_level=result.overall_risk,
        critical_count=result.critical_count,
        high_count=result.high_count,
        medium_count=result.medium_count,
        low_count=result.low_count,
        total_findings=result.total_vulnerabilities,
        scan_duration=duration_seconds,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan.id


async def _run_all_modules(
    url: str,
    modules: List[str],
    timeout: int,
) -> tuple[UnifiedScanResult, int]:
    """Run all requested modules concurrently. Returns (result, duration_seconds)."""
    valid_modules = [m for m in modules if m in AVAILABLE_MODULES]
    tasks = [_run_module(m, url, timeout) for m in valid_modules]

    start = time.monotonic()
    raw_results = await asyncio.gather(*tasks, return_exceptions=False)
    duration = int(time.monotonic() - start)

    results = {}
    completed = []
    failed = []

    for module_name, data in raw_results:
        results[module_name] = data
        if isinstance(data, dict) and "error" in data:
            failed.append(module_name)
        else:
            completed.append(module_name)

    counts = _count_vulns(results)
    risk = _compute_risk(counts)

    scan_result = UnifiedScanResult(
        url=url,
        modules_requested=valid_modules,
        modules_completed=completed,
        modules_failed=failed,
        results=results,
        total_vulnerabilities=counts["total"],
        critical_count=counts.get("critical", 0),
        high_count=counts.get("high", 0),
        medium_count=counts.get("medium", 0),
        low_count=counts.get("low", 0),
        overall_risk=risk,
    )
    return scan_result, duration


# ──────────────────────────────────────────────
# POST /api/scan  — synchronous unified scan
# ──────────────────────────────────────────────
@router.post("/", response_model=UnifiedScanResult, summary="Run Unified Vulnerability Scan")
async def unified_scan(
    request: UnifiedScanRequest,
    current_user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """
    Run multiple vulnerability scanners concurrently against a target URL.
    If authenticated, results are automatically saved to your scan history.
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    result, duration = await _run_all_modules(request.url, request.modules, request.timeout)

    if current_user:
        scan_id = _save_scan_to_db(db, current_user, result, duration)
        result.saved_to_history = True
        result.history_id = scan_id

    return result


# ──────────────────────────────────────────────
# POST /api/scan/async  — background unified scan
# ──────────────────────────────────────────────
@router.post("/async", summary="Run Unified Scan (Async Job)")
async def unified_scan_async(
    request: UnifiedScanRequest,
    background_tasks: BackgroundTasks,
    current_user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """
    Kick off a unified scan in the background.
    Returns a `job_id` to poll with GET /api/scan/{job_id}.
    If authenticated, results are saved to history when complete.
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    job_id = str(uuid.uuid4())
    unified_jobs[job_id] = {"status": "running", "progress": 0, "result": None, "url": request.url}

    # Capture user_id before the background task runs (session may close)
    user_id = current_user.id if current_user else None

    async def _run():
        from database.db import SessionLocal as _SL
        try:
            result, duration = await _run_all_modules(request.url, request.modules, request.timeout)

            history_id = None
            if user_id:
                _db = _SL()
                try:
                    from database.models import User as _User
                    user = _db.query(_User).filter(_User.id == user_id).first()
                    if user:
                        history_id = _save_scan_to_db(_db, user, result, duration)
                        result.saved_to_history = True
                        result.history_id = history_id
                finally:
                    _db.close()

            unified_jobs[job_id] = {
                "status": "completed",
                "progress": 100,
                "result": result.model_dump(),
                "url": request.url,
            }
        except Exception as e:
            unified_jobs[job_id] = {
                "status": "failed",
                "progress": 0,
                "result": None,
                "error": str(e),
                "url": request.url,
            }

    background_tasks.add_task(_run)
    return {
        "job_id": job_id,
        "status": "running",
        "url": request.url,
        "poll_url": f"/api/scan/{job_id}"
    }


# ──────────────────────────────────────────────
# GET /api/scan/{job_id}  — poll job status
# ──────────────────────────────────────────────
@router.get("/{job_id}", summary="Get Async Unified Scan Result")
async def get_unified_result(job_id: str):
    """Poll the result of a previously submitted async unified scan."""
    job = unified_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")

    if job["status"] == "running":
        return {"job_id": job_id, "status": "running", "progress": job.get("progress", 0), "result": None}

    return {"job_id": job_id, "status": job["status"], "progress": 100, "result": job.get("result")}


# ──────────────────────────────────────────────
# GET /api/scan/modules/list  — list available modules
# ──────────────────────────────────────────────
@router.get("/modules/list", summary="List Available Scan Modules")
async def list_modules():
    """Returns all available scanner modules."""
    return {
        "modules": [
            {"id": "crawler", "name": "Web Crawler", "description": "Discovers pages, links, forms, and hidden paths"},
            {"id": "sqli", "name": "SQL Injection", "description": "Detects error-based, blind, and time-based SQLi"},
            {"id": "xss", "name": "XSS Scanner", "description": "Detects reflected, stored, and DOM-based XSS"},
            {"id": "bac", "name": "Broken Access Control", "description": "Tests IDOR, forced browsing, privilege escalation"},
            {"id": "auth", "name": "Auth & Session", "description": "Tests weak creds, session fixation, cookie flags"},
            {"id": "ssl", "name": "SSL/TLS Analysis", "description": "Checks certs, ciphers, HSTS, CVE vulnerabilities"},
            {"id": "headers", "name": "HTTP Security Headers", "description": "Analyzes CSP, HSTS, X-Frame-Options and more"},
        ]
    }
