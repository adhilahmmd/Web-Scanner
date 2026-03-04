from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import sqli

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


@app.get("/")
async def root():
    return {
        "name": "Web Vulnerability Scanner API",
        "version": "1.0.0",
        "modules": ["sqli"],
        "docs": "/docs"
    }


@app.get("/health")
async def health():
    return {"status": "ok"}