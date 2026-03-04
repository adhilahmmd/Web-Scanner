"""
Web Crawler Module
Crawls same domain + subdomains to:
- Discover all reachable pages/links
- Extract forms and their inputs
- Find hidden directories/endpoints
- Extract JS files and API endpoints from source
"""

import httpx
import asyncio
import re
from urllib.parse import urlparse, urljoin, urlunparse
from bs4 import BeautifulSoup
from typing import Set, List, Dict, Tuple
from models.crawler_models import (
    FormDetail, FormInput, JSEndpoint, CrawlSummary
)


# ──────────────────────────────────────────────
# Common hidden paths to probe
# ──────────────────────────────────────────────
HIDDEN_PATHS = [
    "/admin", "/admin/login", "/administrator",
    "/login", "/signin", "/dashboard",
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/docs", "/redoc", "/openapi.json",
    "/.env", "/.git", "/.git/config",
    "/config", "/config.php", "/config.yml", "/config.json",
    "/backup", "/backup.zip", "/backup.sql",
    "/wp-admin", "/wp-login.php", "/wp-config.php",
    "/phpmyadmin", "/phpinfo.php",
    "/robots.txt", "/sitemap.xml",
    "/server-status", "/server-info",
    "/debug", "/test", "/testing",
    "/upload", "/uploads", "/files",
    "/static", "/assets", "/public",
    "/.htaccess", "/.htpasswd",
    "/console", "/shell",
    "/graphql", "/graphiql",
]

# Regex patterns to find API endpoints in JS files
API_PATTERNS = [
    r'["\'](/api/[^\s"\'<>]+)["\']',
    r'["\'](\/(v\d+\/)[^\s"\'<>]+)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.\w+\(["\']([^"\']+)["\']',
    r'url:\s*["\']([^"\']+)["\']',
    r'endpoint:\s*["\']([^"\']+)["\']',
    r'baseURL:\s*["\']([^"\']+)["\']',
    r'href\s*=\s*["\']([^"\']+)["\']',
]


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def get_base_domain(url: str) -> str:
    """Extract base domain (e.g. vulnweb.com from testphp.vulnweb.com)."""
    parsed = urlparse(url)
    parts = parsed.netloc.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return parsed.netloc


def is_same_domain_or_subdomain(url: str, base_domain: str) -> bool:
    """Check if a URL belongs to same domain or its subdomains."""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.split(":")[0]  # strip port
        return netloc == base_domain or netloc.endswith(f".{base_domain}")
    except Exception:
        return False


def normalize_url(url: str) -> str:
    """Remove fragment and trailing slashes for deduplication."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment="")).rstrip("/")


def extract_links(html: str, base_url: str) -> List[str]:
    """Extract all href links from HTML."""
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        full_url = urljoin(base_url, href)
        links.append(normalize_url(full_url))
    return links


def extract_forms(html: str, page_url: str) -> List[FormDetail]:
    """Extract all forms and their input fields from HTML."""
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").upper()
        full_action = urljoin(page_url, action) if action else page_url

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append(FormInput(
                name=inp.get("name"),
                input_type=inp.get("type", "text"),
                value=inp.get("value", ""),
            ))

        forms.append(FormDetail(
            action=full_action,
            method=method,
            inputs=inputs,
            found_on=page_url,
        ))
    return forms


def extract_js_files(html: str, base_url: str) -> List[str]:
    """Extract all <script src="..."> JS file URLs."""
    soup = BeautifulSoup(html, "html.parser")
    js_files = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"].strip()
        full_url = urljoin(base_url, src)
        js_files.append(full_url)
    return js_files


def extract_api_endpoints_from_js(js_content: str, js_url: str) -> List[JSEndpoint]:
    """Scan JS file content for API endpoint patterns."""
    endpoints = []
    seen = set()
    for pattern in API_PATTERNS:
        matches = re.findall(pattern, js_content)
        for match in matches:
            m = match.strip()
            if m and m not in seen and len(m) > 2:
                seen.add(m)
                endpoints.append(JSEndpoint(endpoint=m, found_in=js_url))
    return endpoints


def extract_subdomains(links: List[str], base_domain: str) -> List[str]:
    """Extract unique subdomains from a list of links."""
    subdomains = set()
    for link in links:
        try:
            netloc = urlparse(link).netloc.split(":")[0]
            if netloc.endswith(f".{base_domain}") and netloc != base_domain:
                subdomains.add(netloc)
        except Exception:
            pass
    return list(subdomains)


# ──────────────────────────────────────────────
# Hidden Path Prober
# ──────────────────────────────────────────────

async def probe_hidden_paths(
    client: httpx.AsyncClient,
    base_url: str,
    timeout: int,
    errors: List[str],
) -> List[str]:
    """Probe common hidden paths and return those that return 200/301/302."""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    found = []

    tasks = []
    for path in HIDDEN_PATHS:
        tasks.append(_probe_single_path(client, base + path, timeout))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for path, result in zip(HIDDEN_PATHS, results):
        if isinstance(result, Exception):
            continue
        status, url = result
        if status in (200, 301, 302, 403):  # 403 = exists but forbidden
            found.append(f"{url} [{status}]")

    return found


async def _probe_single_path(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
) -> Tuple[int, str]:
    try:
        resp = await client.get(url, timeout=timeout, follow_redirects=False)
        return resp.status_code, url
    except Exception:
        return 0, url


# ──────────────────────────────────────────────
# Main Crawler
# ──────────────────────────────────────────────

async def run_crawler(
    url: str,
    max_depth: int = 3,
    max_pages: int = 50,
    timeout: int = 10,
) -> dict:
    """
    Crawl a website and collect links, forms, JS files,
    API endpoints, and hidden paths.
    """
    base_domain = get_base_domain(url)
    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = [(normalize_url(url), 0)]  # (url, depth)

    all_links: Set[str] = set()
    all_forms: List[FormDetail] = []
    all_js_files: Set[str] = set()
    all_api_endpoints: List[JSEndpoint] = []
    pages_crawled: List[str] = []
    errors: List[str] = []

    async with httpx.AsyncClient(
        follow_redirects=True,
        headers={"User-Agent": "WebVulnScanner/1.0 (educational use)"},
    ) as client:

        # ── Phase 1: Crawl pages ──
        while queue and len(pages_crawled) < max_pages:
            current_url, depth = queue.pop(0)

            if current_url in visited:
                continue
            if not is_same_domain_or_subdomain(current_url, base_domain):
                continue

            visited.add(current_url)

            try:
                resp = await client.get(current_url, timeout=timeout)

                # Only parse HTML pages
                content_type = resp.headers.get("content-type", "")
                if "text/html" not in content_type:
                    continue

                pages_crawled.append(current_url)
                html = resp.text

                # Extract links
                links = extract_links(html, current_url)
                for link in links:
                    all_links.add(link)
                    if (
                        link not in visited
                        and depth + 1 <= max_depth
                        and is_same_domain_or_subdomain(link, base_domain)
                    ):
                        queue.append((link, depth + 1))

                # Extract forms
                forms = extract_forms(html, current_url)
                all_forms.extend(forms)

                # Extract JS files
                js_files = extract_js_files(html, current_url)
                for js in js_files:
                    all_js_files.add(js)

            except httpx.TimeoutException:
                errors.append(f"Timeout: {current_url}")
            except Exception as e:
                errors.append(f"Error crawling {current_url}: {str(e)}")

        # ── Phase 2: Fetch & analyse JS files ──
        js_tasks = []
        for js_url in list(all_js_files)[:20]:  # cap at 20 JS files
            js_tasks.append(_fetch_and_parse_js(client, js_url, timeout))

        js_results = await asyncio.gather(*js_tasks, return_exceptions=True)
        for result in js_results:
            if isinstance(result, list):
                all_api_endpoints.extend(result)

        # ── Phase 3: Probe hidden paths ──
        hidden_paths = await probe_hidden_paths(client, url, timeout, errors)

    # Deduplicate API endpoints
    seen_endpoints = set()
    unique_api_endpoints = []
    for ep in all_api_endpoints:
        if ep.endpoint not in seen_endpoints:
            seen_endpoints.add(ep.endpoint)
            unique_api_endpoints.append(ep)

    subdomains = extract_subdomains(list(all_links), base_domain)

    summary = CrawlSummary(
        total_pages_crawled=len(pages_crawled),
        total_links_found=len(all_links),
        total_forms_found=len(all_forms),
        total_js_files=len(all_js_files),
        total_api_endpoints=len(unique_api_endpoints),
        total_hidden_paths=len(hidden_paths),
        subdomains_found=subdomains,
    )

    return {
        "url": url,
        "status": "completed",
        "summary": summary,
        "pages_crawled": pages_crawled,
        "all_links": sorted(all_links),
        "forms": all_forms,
        "js_files": sorted(all_js_files),
        "api_endpoints": unique_api_endpoints,
        "hidden_paths": hidden_paths,
        "errors": errors,
    }


async def _fetch_and_parse_js(
    client: httpx.AsyncClient,
    js_url: str,
    timeout: int,
) -> List[JSEndpoint]:
    try:
        resp = await client.get(js_url, timeout=timeout)
        return extract_api_endpoints_from_js(resp.text, js_url)
    except Exception:
        return []