"""
main.py - FastAPI application entry point for the Cloud Security Reporter GUI.

Start with:
    uv run python main.py

Do NOT use --reload in production — it restarts the server on file changes,
killing all active SSE streams and orphaning running pipeline subprocesses.
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from fastapi.responses import HTMLResponse

from db.database import init_db
from api.routes import router

_HERE = Path(__file__).parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise DB on startup."""
    await init_db()
    yield


app = FastAPI(
    title="Cloud Security Reporter",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
)

# Static files and templates
app.mount("/static", StaticFiles(directory=_HERE / "static"), name="static")
templates = Jinja2Templates(directory=_HERE / "templates")

# API routes
app.include_router(router, prefix="/api")


@app.get("/{full_path:path}", response_class=HTMLResponse, include_in_schema=False)
async def spa_shell(request: Request, full_path: str):
    return templates.TemplateResponse(request=request, name="index.html")


if __name__ == "__main__":
    port = 8000
    print(f"\n  Cloud Security Reporter GUI")
    print(f"  http://localhost:{port}")
    print(f"  Press Ctrl+C to stop\n")

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=port,
        # NO reload=True — file watching kills active pipeline runs
        # To apply code changes, stop and restart the server manually
        reload=False,
        log_level="warning",  # suppress INFO noise in production
    )