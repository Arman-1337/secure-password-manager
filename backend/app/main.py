"""
Main FastAPI Application
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import time
import os

from backend.app.config import settings
from backend.app.database.connection import init_db
from backend.app.api import auth_routes, vault_routes, utils_routes

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Enterprise-grade password manager with AES-256 encryption"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests with timing."""
    start_time = time.time()
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    
    print(f"{request.method} {request.url.path} - {response.status_code} ({process_time:.3f}s)")
    
    return response

# Include routers
app.include_router(auth_routes.router)
app.include_router(vault_routes.router)
app.include_router(utils_routes.router)

# Mount static files
static_path = os.path.join(os.path.dirname(__file__), "../../frontend/static")
templates_path = os.path.join(os.path.dirname(__file__), "../../frontend/templates")

if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")

templates = Jinja2Templates(directory=templates_path)

# Root endpoint
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Serve main application page."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION
    }

# Startup event
@app.on_event("startup")
def startup_event():
    """Initialize database on startup."""
    print("\n" + "="*70)
    print(f"  {settings.APP_NAME} v{settings.APP_VERSION}")
    print("="*70)
    print("\n  🔐 Initializing database...")
    
    init_db()
    
    print(f"\n  ✅ Server ready!")
    print(f"  📊 API Docs: http://127.0.0.1:8000/docs")
    print(f"  🔒 Application: http://127.0.0.1:8000")
    print("\n" + "="*70 + "\n")

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Custom 404 handler."""
    return JSONResponse(
        status_code=404,
        content={"detail": "Resource not found"}
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    """Custom 500 handler."""
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )