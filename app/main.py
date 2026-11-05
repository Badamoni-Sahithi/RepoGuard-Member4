from pathlib import Path
import re

from fastapi import FastAPI, HTTPException

from app.security_service import run_security_analysis

app = FastAPI(
    title="RepoGuard AI",
    description="Repository security analysis API",
    version="1.0.0"
)

# Only scan repositories placed in this controlled workspace.
WORKSPACE = Path(__file__).resolve().parent.parent / "workspaces"
WORKSPACE.mkdir(parents=True, exist_ok=True)


@app.get("/")
def home():
    return {
        "message": "RepoGuard AI Backend is running!"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/scan/{repo_id}")
def scan_repository(repo_id: str):

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", repo_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid repository ID"
        )

    repo_path = (WORKSPACE / repo_id).resolve()

    if repo_path.parent != WORKSPACE.resolve():
        raise HTTPException(
            status_code=400,
            detail="Invalid repository location"
        )

    if not repo_path.is_dir():
        raise HTTPException(
            status_code=404,
            detail="Repository not found in workspace"
        )

    try:
        results = run_security_analysis(str(repo_path))

        return {
            "status": "success",
            "repository_id": repo_id,
            "security_analysis": results
        }

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Security analysis failed"
        )