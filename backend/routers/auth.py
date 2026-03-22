"""
Broken Authentication & Session Management Router
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from models.auth_models import AuthRequest, AuthResult
from scanners.auth_scanner import (
    run_auth_scan, DEFAULT_CREDENTIALS, LOGIN_PATHS,
    SESSION_COOKIE_PATTERNS
)
import uuid
from typing import Dict

router = APIRouter()

# In-memory job store
auth_jobs: Dict[str, dict] = {}


# ──────────────────────────────────────────────
# POST /api/auth/scan  — synchronous scan
# ──────────────────────────────────────────────
@router.post("/scan", response_model=AuthResult, summary="Run Auth & Session Scan")
async def scan_auth(request: AuthRequest):
    """
    Run a full Broken Authentication & Session Management scan. Checks:

    - **Weak/Default Credentials** — tests 25+ common username/password combos
    - **Account Lockout** — 10 repeated failed logins, checks for rate limiting
    - **Cookie Flags** — HttpOnly, Secure, SameSite, expiry analysis
    - **Session Token Entropy** — length, Shannon entropy, charset, JWT algorithm
    - **Session Fixation** — pre vs post-login token comparison
    - **Token Expiry** — long-lived or non-expiring tokens
    - **Password Policy** — registration form policy enforcement check
    - **Multi-Session** — concurrent session acceptance detection
    - **Login Endpoint Discovery** — finds all login forms/paths automatically
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    result = await run_auth_scan(
        url=request.url,
        login_path=request.login_path,
        username_field=request.username_field,
        password_field=request.password_field,
        timeout=request.timeout,
        cookies=request.cookies or {},
    )
    return AuthResult(**result)


# ──────────────────────────────────────────────
# POST /api/auth/scan/async  — background scan
# ──────────────────────────────────────────────
@router.post("/scan/async", summary="Run Auth Scan (Async Job)")
async def scan_auth_async(request: AuthRequest, background_tasks: BackgroundTasks):
    """
    Run authentication scan in background.
    Returns a `job_id` to poll with GET /api/auth/scan/{job_id}.
    Recommended — brute force and lockout tests can take 30–60s.
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    job_id = str(uuid.uuid4())
    auth_jobs[job_id] = {"status": "running", "result": None}

    async def _run():
        result = await run_auth_scan(
            url=request.url,
            login_path=request.login_path,
            username_field=request.username_field,
            password_field=request.password_field,
            timeout=request.timeout,
            cookies=request.cookies or {},
        )
        auth_jobs[job_id] = {"status": "completed", "result": result}

    background_tasks.add_task(_run)
    return {
        "job_id": job_id,
        "status": "running",
        "poll_url": f"/api/auth/scan/{job_id}"
    }


# ──────────────────────────────────────────────
# GET /api/auth/scan/{job_id}  — poll result
# ──────────────────────────────────────────────
@router.get("/scan/{job_id}", summary="Get Async Auth Scan Result")
async def get_auth_result(job_id: str):
    """Poll result of a previously submitted async auth scan."""
    job = auth_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    if job["status"] == "running":
        return {"job_id": job_id, "status": "running", "result": None}
    return {"job_id": job_id, "status": "completed", "result": job["result"]}


# ──────────────────────────────────────────────
# GET /api/auth/wordlist  — inspect credential list
# ──────────────────────────────────────────────
@router.get("/wordlist", summary="List Default Credentials Tested")
async def list_wordlist():
    """Returns the default credentials used in brute force testing."""
    return {
        "total_pairs": len(DEFAULT_CREDENTIALS),
        "credentials": [
            {"username": u, "password": p} for u, p in DEFAULT_CREDENTIALS
        ],
    }


# ──────────────────────────────────────────────
# GET /api/auth/login-paths  — inspect login paths
# ──────────────────────────────────────────────
@router.get("/login-paths", summary="List Login Paths Probed")
async def list_login_paths():
    """Returns all login paths probed during endpoint discovery."""
    return {
        "total": len(LOGIN_PATHS),
        "paths": LOGIN_PATHS,
    }


# ──────────────────────────────────────────────
# GET /api/auth/cookie-patterns  — session cookie names
# ──────────────────────────────────────────────
@router.get("/cookie-patterns", summary="List Session Cookie Name Patterns")
async def list_cookie_patterns():
    """Returns patterns used to identify session cookies."""
    return {
        "total": len(SESSION_COOKIE_PATTERNS),
        "patterns": SESSION_COOKIE_PATTERNS,
    }