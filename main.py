from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import sqli, crawler, xss, bac, auth, ssl

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
app.include_router(bac.router, prefix="/api/bac", tags=["Broken Access Control"])
app.include_router(auth.router, prefix="/api/auth", tags=["Broken Authentication & Session"])
app.include_router(ssl.router, prefix="/api/ssl", tags=["SSL/TLS Analysis"])


@app.get("/")
async def root():
    return {
        "name": "Web Vulnerability Scanner API",
        "version": "1.0.0",
        "modules": ["sqli", "crawler", "xss", "bac", "auth", "ssl"],
        "docs": "/docs"
    }


@app.get("/health")
async def health():
    return {"status": "ok"}