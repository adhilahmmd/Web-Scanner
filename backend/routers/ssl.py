"""
SSL/TLS Scanner Router
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from models.ssl_models import SSLRequest, SSLResult
from scanners.ssl_scanner import (
    run_ssl_scan, WEAK_CIPHERS, WEAK_SIGNATURE_ALGORITHMS
)
import uuid
from typing import Dict

router = APIRouter()

ssl_jobs: Dict[str, dict] = {}


# ──────────────────────────────────────────────
# POST /api/ssl/scan  — synchronous scan
# ──────────────────────────────────────────────
@router.post("/scan", response_model=SSLResult, summary="Run SSL/TLS Scan")
async def scan_ssl(request: SSLRequest):
    """
    Run a full SSL/TLS analysis. Checks:

    - **Certificate** — expiry, self-signed, validity, chain trust, signature algorithm
    - **Protocol Versions** — TLS 1.0, 1.1, 1.2, 1.3 support detection
    - **Cipher Suites** — NULL, RC4, DES, EXPORT, 3DES, anonymous ciphers
    - **HSTS** — header presence, max-age value, includeSubDomains directive
    - **Mixed Content** — HTTP resources on HTTPS pages
    - **BEAST** — TLS 1.0 + CBC cipher combination
    - **POODLE** — SSLv3 support detection (CVE-2014-3566)
    - **Heartbleed** — TLS heartbeat extension probe (CVE-2014-0160)
    - **CRIME/BREACH** — TLS compression detection (CVE-2012-4929)

    Returns a letter grade (A+ to F) based on findings.
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    result = await run_ssl_scan(url=request.url, timeout=request.timeout)
    return SSLResult(**result)


# ──────────────────────────────────────────────
# POST /api/ssl/scan/async  — background scan
# ──────────────────────────────────────────────
@router.post("/scan/async", summary="Run SSL/TLS Scan (Async Job)")
async def scan_ssl_async(request: SSLRequest, background_tasks: BackgroundTasks):
    """
    Kick off an SSL/TLS scan in the background.
    Returns a `job_id` to poll with GET /api/ssl/scan/{job_id}.
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    job_id = str(uuid.uuid4())
    ssl_jobs[job_id] = {"status": "running", "result": None}

    async def _run():
        result = await run_ssl_scan(url=request.url, timeout=request.timeout)
        ssl_jobs[job_id] = {"status": "completed", "result": result}

    background_tasks.add_task(_run)
    return {
        "job_id": job_id,
        "status": "running",
        "poll_url": f"/api/ssl/scan/{job_id}"
    }


# ──────────────────────────────────────────────
# GET /api/ssl/scan/{job_id}  — poll result
# ──────────────────────────────────────────────
@router.get("/scan/{job_id}", summary="Get Async SSL Scan Result")
async def get_ssl_result(job_id: str):
    """Poll result of a previously submitted async SSL scan."""
    job = ssl_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    if job["status"] == "running":
        return {"job_id": job_id, "status": "running", "result": None}
    return {"job_id": job_id, "status": "completed", "result": job["result"]}


# ──────────────────────────────────────────────
# GET /api/ssl/weak-ciphers  — inspect cipher list
# ──────────────────────────────────────────────
@router.get("/weak-ciphers", summary="List Weak Cipher Patterns")
async def list_weak_ciphers():
    """Returns all weak cipher patterns detected by this scanner."""
    return {
        "total": len(WEAK_CIPHERS),
        "ciphers": [
            {"pattern": k, "reason": v} for k, v in WEAK_CIPHERS.items()
        ],
    }


# ──────────────────────────────────────────────
# GET /api/ssl/grading  — explain grading
# ──────────────────────────────────────────────
@router.get("/grading", summary="SSL Grading Criteria")
async def grading_criteria():
    """Explains the SSL letter grading system used by this scanner."""
    return {
        "grades": {
            "A+": "No issues found — perfect configuration",
            "A":  "Informational findings only",
            "B+": "Low severity issues (e.g. short HSTS max-age)",
            "B":  "Medium severity issues (e.g. missing HSTS, mixed content)",
            "C":  "High severity issues (e.g. weak ciphers, TLS 1.0)",
            "F":  "Critical issues (e.g. expired cert, POODLE, Heartbleed)",
        },
        "cves_checked": [
            {"id": "CVE-2014-3566", "name": "POODLE", "condition": "SSLv3 supported"},
            {"id": "CVE-2011-3389", "name": "BEAST",  "condition": "TLS 1.0 + CBC cipher"},
            {"id": "CVE-2014-0160", "name": "Heartbleed", "condition": "TLS heartbeat extension response"},
            {"id": "CVE-2012-4929", "name": "CRIME",  "condition": "TLS compression enabled"},
            {"id": "CVE-2013-3587", "name": "BREACH", "condition": "HTTP compression on sensitive endpoints"},
        ],
    }