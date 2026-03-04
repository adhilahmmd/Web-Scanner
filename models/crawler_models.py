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