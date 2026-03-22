"""
HTTP Security Headers Router
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from models.http_models import HeaderRequest, HeaderResult
from scanners.http_scanner import (
    run_headers_scan, SECURITY_HEADERS,
    INFO_LEAK_HEADERS, DANGEROUS_PERMISSIONS,
    WEAK_REFERRER_VALUES, STRONG_REFERRER_VALUES
)
import uuid
from typing import Dict

router = APIRouter()

headers_jobs: Dict[str, dict] = {}


# ──────────────────────────────────────────────
# POST /api/headers/scan  — synchronous scan
# ──────────────────────────────────────────────
@router.post("/scan", response_model=HeaderResult, summary="Run HTTP Security Headers Scan")
async def scan_headers(request: HeaderRequest):
    """
    Run a full HTTP Security Headers analysis. Checks:

    - **CSP** — presence + deep directive analysis (unsafe-inline, unsafe-eval, wildcards,
      missing directives, HTTP sources, nonce/hash usage)
    - **X-Frame-Options** — presence, valid values (DENY/SAMEORIGIN), deprecated ALLOW-FROM
    - **X-Content-Type-Options** — nosniff value validation
    - **Referrer-Policy** — privacy level grading (strong vs weak values)
    - **Permissions-Policy** — dangerous feature exposure (camera, mic, geolocation)
    - **X-XSS-Protection** — presence, mode=block, deprecation guidance
    - **Information Leaking Headers** — Server, X-Powered-By, X-AspNet-Version, etc.
    - **Misconfigurations** — CORS wildcard, HPKP, missing Cache-Control

    Returns a security score (0–100) and letter grade (A+ to F).
    Returns raw headers, per-header details, and full CSP directive breakdown.
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    result = await run_headers_scan(
        url=request.url,
        timeout=request.timeout,
        follow_redirects=request.follow_redirects,
    )
    return HeaderResult(**result)


# ──────────────────────────────────────────────
# POST /api/headers/scan/async  — background scan
# ──────────────────────────────────────────────
@router.post("/scan/async", summary="Run Headers Scan (Async Job)")
async def scan_headers_async(request: HeaderRequest, background_tasks: BackgroundTasks):
    """
    Kick off a headers scan in the background.
    Returns a `job_id` to poll with GET /api/headers/scan/{job_id}.
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    job_id = str(uuid.uuid4())
    headers_jobs[job_id] = {"status": "running", "result": None}

    async def _run():
        result = await run_headers_scan(
            url=request.url,
            timeout=request.timeout,
            follow_redirects=request.follow_redirects,
        )
        headers_jobs[job_id] = {"status": "completed", "result": result}

    background_tasks.add_task(_run)
    return {
        "job_id": job_id,
        "status": "running",
        "poll_url": f"/api/headers/scan/{job_id}"
    }


# ──────────────────────────────────────────────
# GET /api/headers/scan/{job_id}  — poll result
# ──────────────────────────────────────────────
@router.get("/scan/{job_id}", summary="Get Async Headers Scan Result")
async def get_headers_result(job_id: str):
    """Poll result of a previously submitted async headers scan."""
    job = headers_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    if job["status"] == "running":
        return {"job_id": job_id, "status": "running", "result": None}
    return {"job_id": job_id, "status": "completed", "result": job["result"]}


# ──────────────────────────────────────────────
# GET /api/headers/checklist  — full header checklist
# ──────────────────────────────────────────────
@router.get("/checklist", summary="Security Header Checklist")
async def get_checklist():
    """Returns all security headers checked, with descriptions and ideal values."""
    return {
        "security_headers": [
            {
                "name": meta["display"],
                "check_type": meta["check_type"],
                "missing_severity": meta["missing_severity"],
                "description": meta["description"],
            }
            for meta in SECURITY_HEADERS.values()
        ],
        "info_leak_headers": [
            {"header": k, "reveals": v}
            for k, v in INFO_LEAK_HEADERS.items()
        ],
        "dangerous_permissions": DANGEROUS_PERMISSIONS,
    }


# ──────────────────────────────────────────────
# GET /api/headers/grading  — grading explanation
# ──────────────────────────────────────────────
@router.get("/grading", summary="Security Score & Grading Criteria")
async def get_grading():
    """Explains the scoring system and what each grade means."""
    return {
        "scoring": {
            "max_score": 100,
            "penalties": {
                "critical": -25,
                "high": -15,
                "medium": -8,
                "low": -3,
                "info": -1,
            },
        },
        "grades": {
            "A+": "Score ≥ 95 — Excellent security posture",
            "A":  "Score ≥ 85 — Strong, minor improvements possible",
            "B+": "Score ≥ 75 — Good but some headers need attention",
            "B":  "Score ≥ 65 — Several medium-severity issues",
            "C":  "Score ≥ 50 — High severity issues present",
            "D":  "Score ≥ 35 — Multiple critical gaps",
            "F":  "Score < 35 — Critical misconfigurations or absent headers",
        },
        "referrer_policy": {
            "strong_values": STRONG_REFERRER_VALUES,
            "weak_values": WEAK_REFERRER_VALUES,
        },
    }