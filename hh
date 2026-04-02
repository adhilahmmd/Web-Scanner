Crawler.models
from pydantic import BaseModel
from typing import Optional, List, Dict
from enum import Enum


class CrawlRequest(BaseModel):
    url: str
    max_depth: Optional[int] = 3
    max_pages: Optional[int] = 50
    timeout: Optional[int] = 10

    class Config:
        json_schema_extra = {
            "example": {
                "url": "http://testphp.vulnweb.com",
                "max_depth": 3,
                "max_pages": 50,
                "timeout": 10
            }
        }


class FormInput(BaseModel):
    name: Optional[str]
    input_type: Optional[str]
    value: Optional[str]


class FormDetail(BaseModel):
    action: str
    method: str
    inputs: List[FormInput]
    found_on: str


class JSEndpoint(BaseModel):
    endpoint: str
    found_in: str


class CrawlSummary(BaseModel):
    total_pages_crawled: int
    total_links_found: int
    total_forms_found: int
    total_js_files: int
    total_api_endpoints: int
    total_hidden_paths: int
    subdomains_found: List[str]


class CrawlResult(BaseModel):
    url: str
    scan_type: str = "Web Crawler"
    status: str
    summary: CrawlSummary
    pages_crawled: List[str]
    all_links: List[str]
    forms: List[FormDetail]
    js_files: List[str]
    api_endpoints: List[JSEndpoint]
    hidden_paths: List[str]
    errors: Optional[List[str]] = []

crawler.router

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





Sqli.model

from pydantic import BaseModel, HttpUrl
from typing import Optional, List
from enum import Enum


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanRequest(BaseModel):
    url: str
    timeout: Optional[int] = 10
    crawl_forms: Optional[bool] = False

    class Config:
        json_schema_extra = {
            "example": {
                "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
                "timeout": 10,
                "crawl_forms": False
            }
        }


class VulnerabilityFinding(BaseModel):
    parameter: str
    payload: str
    evidence: str
    severity: SeverityLevel
    description: str
    remediation: str


class ScanSummary(BaseModel):
    total_parameters: int
    total_payloads_tested: int
    vulnerabilities_found: int
    risk_level: SeverityLevel


class ScanResult(BaseModel):
    url: str
    scan_type: str = "SQL Injection"
    status: str
    summary: ScanSummary
    findings: List[VulnerabilityFinding]
    errors: Optional[List[str]] = []

sqli.router

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
