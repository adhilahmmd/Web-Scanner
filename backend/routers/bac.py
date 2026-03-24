"""
Broken Access Control Router
Exposes endpoints for detecting access control vulnerabilities.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from models.bac_models import BACRequest, BACResult
from scanners.bac_scanner import (
    run_bac_scan, RESTRICTED_PATHS, ROLE_PARAMS, BYPASS_HEADERS
)
import uuid
from typing import Dict

router = APIRouter()

# In-memory job store
bac_jobs: Dict[str, dict] = {}


# ──────────────────────────────────────────────
# POST /api/bac/scan  — synchronous scan
# ──────────────────────────────────────────────
@router.post("/scan", response_model=BACResult, summary="Run Broken Access Control Scan")
async def scan_bac(request: BACRequest):
    """
    Run a full Broken Access Control scan. Checks for:

    - **IDOR** — increments/decrements ID parameters to access other objects
    - **Forced Browsing** — directly accesses 40+ restricted/admin paths
    - **Privilege Escalation** — injects role/admin params & manipulates cookies
    - **Missing Authentication** — probes sensitive API endpoints without credentials
    - **HTTP Method Tampering** — tests DELETE/PUT/PATCH and X-HTTP-Method-Override

    Bypass techniques tested:
    - Parameter tampering (IDs, roles)
    - URL path manipulation (trailing slash, encoding, extension tricks)
    - Header bypass (X-Original-URL, X-Rewrite-URL, X-Forwarded-For)
    - Cookie/token role manipulation
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    result = await run_bac_scan(
        urls=[request.url],
        timeout=request.timeout,
        cookies=request.cookies or {},
        extra_headers=request.headers or {},
    )
    return BACResult.model_validate(result)


# ──────────────────────────────────────────────
# POST /api/bac/scan/async  — background scan
# ──────────────────────────────────────────────
@router.post("/scan/async", summary="Run BAC Scan (Async Job)")
async def scan_bac_async(request: BACRequest, background_tasks: BackgroundTasks):
    """
    Kick off a Broken Access Control scan in the background.
    Returns a `job_id` to poll with GET /api/bac/scan/{job_id}.
    Recommended — BAC scans probe many paths and can take 30–60 seconds.
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    job_id = str(uuid.uuid4())
    bac_jobs[job_id] = {"status": "running", "result": None}

    async def _run():
        result = await run_bac_scan(
            urls=[request.url],
            timeout=request.timeout,
            cookies=request.cookies or {},
            extra_headers=request.headers or {},
        )
        bac_jobs[job_id] = {"status": "completed", "result": result}

    background_tasks.add_task(_run)
    return {
        "job_id": job_id,
        "status": "running",
        "poll_url": f"/api/bac/scan/{job_id}"
    }


# ──────────────────────────────────────────────
# GET /api/bac/scan/{job_id}  — poll result
# ──────────────────────────────────────────────
@router.get("/scan/{job_id}", summary="Get Async BAC Scan Result")
async def get_bac_result(job_id: str):
    """Poll the result of a previously submitted async BAC scan."""
    job = bac_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    if job["status"] == "running":
        return {"job_id": job_id, "status": "running", "result": None}
    return {"job_id": job_id, "status": "completed", "result": job["result"]}


# ──────────────────────────────────────────────
# GET /api/bac/restricted-paths  — inspect path list
# ──────────────────────────────────────────────
@router.get("/restricted-paths", summary="List Restricted Paths Probed")
async def list_restricted_paths():
    """Returns all restricted/admin paths probed during forced browsing."""
    return {
        "total": len(RESTRICTED_PATHS),
        "paths": RESTRICTED_PATHS
    }


# ──────────────────────────────────────────────
# GET /api/bac/bypass-techniques  — inspect techniques
# ──────────────────────────────────────────────
@router.get("/bypass-techniques", summary="List Bypass Techniques")
async def list_bypass_techniques():
    """Returns all bypass techniques and headers used in the scan."""
    return {
        "role_params_tested": ROLE_PARAMS,
        "header_bypasses": BYPASS_HEADERS,
        "http_methods_tested": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    }