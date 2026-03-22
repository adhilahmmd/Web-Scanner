"""
XSS Scanner Router
Exposes endpoints for detecting Cross-Site Scripting vulnerabilities.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from models.xss_models import XSSRequest, XSSResult
from scanners.xss_scanner import run_xss_scan, REFLECTED_PAYLOADS, DOM_PAYLOADS, STORED_XSS_MARKERS
import uuid
from typing import Dict

router = APIRouter()

# In-memory job store
xss_jobs: Dict[str, dict] = {}


# ──────────────────────────────────────────────
# POST /api/xss/scan  — synchronous scan
# ──────────────────────────────────────────────
@router.post("/scan", response_model=XSSResult, summary="Run XSS Scan")
async def scan_xss(request: XSSRequest):
    """
    Run a full XSS scan against the target URL. Detects:

    - **Reflected XSS** — payload echoed back in HTML response (URL params, forms, headers)
    - **Stored XSS** — payload persists and appears on re-fetch (forms)
    - **DOM-based XSS** — dangerous sink/source combinations detected in page source

    Injection points tested:
    - URL query parameters
    - HTML forms (GET & POST)
    - HTTP headers (User-Agent, Referer, X-Forwarded-For)
    - JSON API endpoints (POST with application/json)
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    result = await run_xss_scan(
        url=request.url,
        timeout=request.timeout,
        test_forms=request.test_forms,
        test_headers=request.test_headers,
        test_json=request.test_json,
    )
    return XSSResult(**result)


# ──────────────────────────────────────────────
# POST /api/xss/scan/async  — background scan
# ──────────────────────────────────────────────
@router.post("/scan/async", summary="Run XSS Scan (Async Job)")
async def scan_xss_async(request: XSSRequest, background_tasks: BackgroundTasks):
    """
    Kick off an XSS scan in the background.
    Returns a `job_id` to poll with GET /api/xss/scan/{job_id}.
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    job_id = str(uuid.uuid4())
    xss_jobs[job_id] = {"status": "running", "result": None}

    async def _run():
        result = await run_xss_scan(
            url=request.url,
            timeout=request.timeout,
            test_forms=request.test_forms,
            test_headers=request.test_headers,
            test_json=request.test_json,
        )
        xss_jobs[job_id] = {"status": "completed", "result": result}

    background_tasks.add_task(_run)
    return {
        "job_id": job_id,
        "status": "running",
        "poll_url": f"/api/xss/scan/{job_id}"
    }


# ──────────────────────────────────────────────
# GET /api/xss/scan/{job_id}  — poll result
# ──────────────────────────────────────────────
@router.get("/scan/{job_id}", summary="Get Async XSS Scan Result")
async def get_xss_result(job_id: str):
    """Poll the result of a previously submitted async XSS scan."""
    job = xss_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    if job["status"] == "running":
        return {"job_id": job_id, "status": "running", "result": None}
    return {"job_id": job_id, "status": "completed", "result": job["result"]}


# ──────────────────────────────────────────────
# GET /api/xss/payloads  — list all payloads
# ──────────────────────────────────────────────
@router.get("/payloads", summary="List XSS Payloads")
async def list_payloads():
    """Returns all XSS payloads used, grouped by technique."""
    return {
        "reflected_payloads": {
            "count": len(REFLECTED_PAYLOADS),
            "payloads": REFLECTED_PAYLOADS,
        },
        "dom_payloads": {
            "count": len(DOM_PAYLOADS),
            "payloads": DOM_PAYLOADS,
        },
        "stored_markers": {
            "count": len(STORED_XSS_MARKERS),
            "payloads": STORED_XSS_MARKERS,
        },
    }