import os
import json
import subprocess
import asyncio
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import docker
import sys

app = FastAPI(title="HTTP Request Smuggling Lab Control Panel")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Docker client
docker_client = docker.from_env()

# ===== Data Models =====
class ModeConfig(BaseModel):
    mode: str  # "vulnerable" or "defended"

class ScenarioRequest(BaseModel):
    scenario: str  # "cl_te", "te_cl", "cache_poison"
    action: str  # "run", "verify", "cleanup"

class StatusResponse(BaseModel):
    status: str
    mode: str
    backend_healthy: bool
    cache_healthy: bool
    frontend_healthy: bool
    message: str

# ===== Utility Functions =====
def get_container_status(container_name: str) -> bool:
    try:
        container = docker_client.containers.get(container_name)
        return container.status == "running"
    except:
        return False

def get_current_mode() -> str:
    try:
        backend = docker_client.containers.get("smuggling-backend")
        env_vars = backend.attrs['Config']['Env']
        for var in env_vars:
            if var.startswith("MODE="):
                return var.split("=")[1]
        return "vulnerable"
    except:
        return "unknown"

def update_backend_mode(mode: str):
    """Change backend mode by recreating container with new environment"""
    compose_dir = "/Users/admin/final-project-raghad-bayan/smuggling-lab"
    env = os.environ.copy()
    env["MODE"] = mode

    try:
        # Stop and remove old container
        subprocess.run(
            ["docker-compose", "-f", "docker-compose.yml", "down", "backend"],
            cwd=compose_dir,
            capture_output=True
        )
        # Rebuild and start with new mode
        subprocess.run(
            ["docker-compose", "-f", "docker-compose.yml", "up", "-d", "backend"],
            cwd=compose_dir,
            env=env,
            capture_output=True
        )
        return True
    except Exception as e:
        print(f"Error updating mode: {e}", file=sys.stderr)
        return False

# ===== API Endpoints =====
@app.get("/api/status")
async def get_status() -> StatusResponse:
    """Get overall lab status"""
    return StatusResponse(
        status="ready",
        mode=get_current_mode(),
        backend_healthy=get_container_status("smuggling-backend"),
        cache_healthy=get_container_status("smuggling-cache"),
        frontend_healthy=get_container_status("smuggling-frontend"),
        message="Lab is running"
    )

@app.post("/api/mode")
async def set_mode(config: ModeConfig):
    """Switch lab mode between vulnerable and defended"""
    if config.mode not in ["vulnerable", "defended"]:
        raise HTTPException(status_code=400, detail="Invalid mode")

    if update_backend_mode(config.mode):
        return {"status": "success", "mode": config.mode, "message": f"Switched to {config.mode}"}
    else:
        raise HTTPException(status_code=500, detail="Failed to switch mode")

@app.get("/api/mode")
async def get_mode():
    """Get current mode"""
    return {"mode": get_current_mode()}

@app.post("/api/scenario/run")
async def run_scenario(req: ScenarioRequest, background_tasks: BackgroundTasks):
    """Run attack scenario"""
    scenario_map = {
        "cl_te": "/Users/admin/final-project-raghad-bayan/smuggling-lab/attacker/smuggle_clte.py",
        "te_cl": "/Users/admin/final-project-raghad-bayan/smuggling-lab/attacker/smuggle_tecl.py",
        "cache_poison": "/Users/admin/final-project-raghad-bayan/smuggling-lab/attacker/cache_poison.py",
    }

    if req.scenario not in scenario_map:
        raise HTTPException(status_code=400, detail="Invalid scenario")

    script = scenario_map[req.scenario]

    try:
        result = subprocess.run(
            ["python", script],
            capture_output=True,
            text=True,
            timeout=30
        )
        return {
            "status": "completed",
            "scenario": req.scenario,
            "output": result.stdout,
            "error": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Scenario execution timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/cache/purge")
async def purge_cache():
    """Purge Varnish cache"""
    try:
        script = "/Users/admin/final-project-raghad-bayan/smuggling-lab/attacker/purge_cache.py"
        result = subprocess.run(
            ["python", script],
            capture_output=True,
            text=True,
            timeout=10
        )
        return {
            "status": "success" if result.returncode == 0 else "failed",
            "output": result.stdout,
            "error": result.stderr
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/cache/verify")
async def verify_poison():
    """Verify cache poisoning"""
    try:
        script = "/Users/admin/final-project-raghad-bayan/smuggling-lab/attacker/verify_poison.py"
        result = subprocess.run(
            ["python", script],
            capture_output=True,
            text=True,
            timeout=10
        )
        return {
            "status": "verified" if "poisoned" in result.stdout.lower() else "clean",
            "output": result.stdout,
            "error": result.stderr
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs/{service}")
async def get_logs(service: str, lines: int = 50):
    """Get container logs"""
    container_map = {
        "backend": "smuggling-backend",
        "cache": "smuggling-cache",
        "frontend": "smuggling-frontend"
    }

    if service not in container_map:
        raise HTTPException(status_code=400, detail="Invalid service")

    try:
        container = docker_client.containers.get(container_map[service])
        logs = container.logs(tail=lines).decode()
        return {"service": service, "logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ===== Static Files =====
@app.get("/")
async def root():
    """Serve dashboard"""
    with open("/Users/admin/final-project-raghad-bayan/smuggling-lab/dashboard/index.html") as f:
        return f.read()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
