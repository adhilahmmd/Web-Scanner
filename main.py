from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import sqli, crawler, xss

app = FastAPI(
    title="Web Vulnerability Scanner",
    description="Modular web application security scanner",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(sqli.router, prefix="/api/sqli", tags=["SQL Injection"])
app.include_router(crawler.router, prefix="/api/crawler", tags=["Web Crawler"])
app.include_router(xss.router, prefix="/api/xss", tags=["XSS Scanner"])


@app.get("/")
async def root():
    return {
        "name": "Web Vulnerability Scanner API",
        "version": "1.0.0",
        "modules": ["sqli", "crawler", "xss"],
        "docs": "/docs"
    }


@app.get("/health")
async def health():
    return {"status": "ok"}