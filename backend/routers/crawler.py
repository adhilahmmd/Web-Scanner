"""
Crawler Router
Exposes endpoints for crawling websites and discovering
links, forms, JS files, API endpoints, and hidden paths.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from models.crawler_models import CrawlRequest, CrawlResult
from scanners.crawler_scanner import run_crawler
import uuid
from typing import Dict

router = APIRouter()

# In-memory job store (replace with Redis/DB in production)
crawl_jobs: Dict[str, dict] = {}


# ──────────────────────────────────────────────
# POST /api/crawler/scan  — synchronous crawl
# ──────────────────────────────────────────────
@router.post("/scan", response_model=CrawlResult, summary="Run Web Crawler Scan")
async def crawl(request: CrawlRequest):
    """
    Crawl a target website and discover:

    - **All pages & links** reachable from the start URL (same domain + subdomains)
    - **Forms & inputs** — action, method, and all input fields
    - **JS files** — all script sources loaded on crawled pages
    - **API endpoints** — extracted from JS file content using regex patterns
    - **Hidden paths** — probes 40+ common sensitive directories (admin, .env, /api, etc.)

    Respects `max_depth` and `max_pages` to control crawl scope.
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    result = await run_crawler(
        url=request.url,
        max_depth=request.max_depth,
        max_pages=request.max_pages,
        timeout=request.timeout,
    )
    return CrawlResult(**result)


# ──────────────────────────────────────────────
# POST /api/crawler/scan/async  — background crawl
# ──────────────────────────────────────────────
@router.post("/scan/async", summary="Run Web Crawler (Async Job)")
async def crawl_async(request: CrawlRequest, background_tasks: BackgroundTasks):
    """
    Kick off a crawl in the background.
    Returns a `job_id` to poll with GET /api/crawler/scan/{job_id}.
    Recommended for large sites where crawling may take 30–60 seconds.
    """
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://"
        )

    job_id = str(uuid.uuid4())
    crawl_jobs[job_id] = {"status": "running", "result": None}

    async def _run():
        result = await run_crawler(
            url=request.url,
            max_depth=request.max_depth,
            max_pages=request.max_pages,
            timeout=request.timeout,
        )
        crawl_jobs[job_id] = {"status": "completed", "result": result}

    background_tasks.add_task(_run)

    return {
        "job_id": job_id,
        "status": "running",
        "poll_url": f"/api/crawler/scan/{job_id}"
    }


# ──────────────────────────────────────────────
# GET /api/crawler/scan/{job_id}  — poll job
# ──────────────────────────────────────────────
@router.get("/scan/{job_id}", summary="Get Async Crawl Result")
async def get_crawl_result(job_id: str):
    """Poll the result of a previously submitted async crawl job."""
    job = crawl_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")

    if job["status"] == "running":
        return {"job_id": job_id, "status": "running", "result": None}

    return {"job_id": job_id, "status": "completed", "result": job["result"]}


# ──────────────────────────────────────────────
# GET /api/crawler/hidden-paths  — list probed paths
# ──────────────────────────────────────────────
@router.get("/hidden-paths", summary="List Hidden Paths Probed")
async def list_hidden_paths():
    """Returns the full list of hidden/sensitive paths this crawler probes."""
    from scanners.crawler_scanner import HIDDEN_PATHS
    return {
        "total": len(HIDDEN_PATHS),
        "paths": HIDDEN_PATHS
    }