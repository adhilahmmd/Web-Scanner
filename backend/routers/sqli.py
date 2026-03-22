"""
SQL Injection Router
Exposes endpoints for triggering and retrieving SQLi scan results.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from models.sqli_models import ScanRequest, ScanResult
from scanners.sqli_scanner import run_sqli_scan
import asyncio
import uuid
from typing import Dict

router = APIRouter()

# In-memory job store (replace with Redis/DB in production)
scan_jobs: Dict[str, dict] = {}


# ──────────────────────────────────────────────
# POST /api/sqli/scan  — run scan synchronously
# ──────────────────────────────────────────────
@router.post("/scan", response_model=ScanResult, summary="Run SQL Injection Scan")
async def scan(request: ScanRequest):
    """
    Run a synchronous SQL injection scan against the provided URL.

    Tests all query parameters using:
    - **Error-based** detection (database error messages)
    - **Boolean-based blind** detection (response length differences)
    - **Time-based blind** detection (response delay analysis)

    Returns detailed findings with severity, evidence, and remediation advice.
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    result = await run_sqli_scan(url=request.url, timeout=request.timeout)
    return ScanResult(**result)


# ──────────────────────────────────────────────
# POST /api/sqli/scan/async  — run scan as background job
# ──────────────────────────────────────────────
@router.post("/scan/async", summary="Run SQL Injection Scan (Async Job)")
async def scan_async(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Kick off a SQL injection scan in the background.
    Returns a `job_id` you can poll with GET /api/sqli/scan/{job_id}.
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    job_id = str(uuid.uuid4())
    scan_jobs[job_id] = {"status": "running", "result": None}

    async def _run():
        result = await run_sqli_scan(url=request.url, timeout=request.timeout)
        scan_jobs[job_id] = {"status": "completed", "result": result}

    background_tasks.add_task(_run)

    return {
        "job_id": job_id,
        "status": "running",
        "poll_url": f"/api/sqli/scan/{job_id}"
    }


# ──────────────────────────────────────────────
# GET /api/sqli/scan/{job_id}  — poll job status
# ──────────────────────────────────────────────
@router.get("/scan/{job_id}", summary="Get Async Scan Result")
async def get_scan_result(job_id: str):
    """
    Poll the result of a previously submitted async scan job.
    Returns status `running` until the scan completes.
    """
    job = scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")

    if job["status"] == "running":
        return {"job_id": job_id, "status": "running", "result": None}

    return {
        "job_id": job_id,
        "status": "completed",
        "result": job["result"]
    }


# ──────────────────────────────────────────────
# GET /api/sqli/payloads  — inspect payload list
# ──────────────────────────────────────────────
@router.get("/payloads", summary="List SQL Injection Payloads")
async def list_payloads():
    """Returns all payloads used by this scanner, grouped by technique."""
    from scanners.sqli_scanner import PAYLOADS
    return {
        "total": sum(len(v) for v in PAYLOADS.values()),
        "payloads": PAYLOADS
    }