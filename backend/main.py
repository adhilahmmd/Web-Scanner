from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from routers import sqli, crawler, xss, bac, auth, ssl, http
from routers import scan
from routers import users, history
from database.db import init_db
from scanners.oob_server import oob_server
import os

app = FastAPI(
    title="Web Vulnerability Scanner",
    description="Modular web application security scanner with user authentication",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database and OOB callback server on startup
@app.on_event("startup")
async def on_startup():
    init_db()
    await oob_server.start()

@app.on_event("shutdown")
async def on_shutdown():
    await oob_server.stop()

# Register API routers
app.include_router(sqli.router, prefix="/api/sqli", tags=["SQL Injection"])
app.include_router(crawler.router, prefix="/api/crawler", tags=["Web Crawler"])
app.include_router(xss.router, prefix="/api/xss", tags=["XSS Scanner"])
app.include_router(bac.router, prefix="/api/bac", tags=["Broken Access Control"])
app.include_router(auth.router, prefix="/api/auth", tags=["Broken Authentication & Session"])
app.include_router(ssl.router, prefix="/api/ssl", tags=["SSL/TLS Analysis"])
app.include_router(http.router, prefix="/api/headers", tags=["HTTP Security Headers"])
app.include_router(scan.router, prefix="/api/scan", tags=["Unified Scanner"])

# User authentication & history
app.include_router(users.router, prefix="/api/users", tags=["User Auth"])
app.include_router(history.router, prefix="/api/history", tags=["Scan History"])


@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(content=b"", media_type="image/x-icon")


# Serve frontend static files (must be after API routes)
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=os.path.join(FRONTEND_DIR, "css")), name="css")
    app.mount("/js", StaticFiles(directory=os.path.join(FRONTEND_DIR, "js")), name="js")

    @app.get("/", response_class=FileResponse)
    async def serve_frontend():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
else:
    @app.get("/")
    async def root():
        return {
            "name": "Web Vulnerability Scanner API",
            "version": "2.0.0",
            "modules": ["sqli", "crawler", "xss", "bac", "auth", "ssl", "headers", "scan"],
            "auth_modules": ["users", "history"],
            "docs": "/docs",
            "note": "Frontend not found — run from project root or build frontend first"
        }