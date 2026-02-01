"""FastAPI application for Mailwarden web interface."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Store for log messages (ring buffer)
log_buffer: deque[dict[str, Any]] = deque(maxlen=1000)

# Connected WebSocket clients
websocket_clients: set[WebSocket] = set()

# Config file path (set via environment or default)
CONFIG_PATH: Path | None = None


class LogHandler(logging.Handler):
    """Custom log handler that broadcasts to WebSocket clients."""

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record to all connected clients."""
        try:
            log_entry = {
                "timestamp": record.created,
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
            log_buffer.append(log_entry)
            
            # Broadcast to all connected clients
            asyncio.create_task(broadcast_log(log_entry))
        except Exception:
            pass


async def broadcast_log(log_entry: dict[str, Any]) -> None:
    """Broadcast log entry to all connected WebSocket clients."""
    if not websocket_clients:
        return
    
    message = json.dumps({"type": "log", "data": log_entry})
    disconnected = set()
    
    for client in websocket_clients:
        try:
            await client.send_text(message)
        except Exception:
            disconnected.add(client)
    
    websocket_clients.difference_update(disconnected)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown."""
    # Setup custom log handler
    handler = LogHandler()
    handler.setLevel(logging.DEBUG)
    
    # Add handler to root logger and mailwarden loggers
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    
    mailwarden_logger = logging.getLogger("mailwarden")
    mailwarden_logger.addHandler(handler)
    
    yield
    
    # Cleanup
    root_logger.removeHandler(handler)
    mailwarden_logger.removeHandler(handler)


def create_app(config_path: str | Path | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    global CONFIG_PATH
    
    if config_path:
        CONFIG_PATH = Path(config_path)
    elif os.environ.get("MAILWARDEN_CONFIG"):
        CONFIG_PATH = Path(os.environ["MAILWARDEN_CONFIG"])
    
    app = FastAPI(
        title="Mailwarden",
        description="Email organization with AI classification",
        version="1.0.0",
        lifespan=lifespan,
    )
    
    # CORS for development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Mount static files
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
    
    # Register routes
    register_routes(app)
    
    return app


def register_routes(app: FastAPI) -> None:
    """Register all API routes."""
    
    @app.get("/", response_class=HTMLResponse)
    async def index():
        """Serve the main HTML page."""
        html_path = Path(__file__).parent / "static" / "index.html"
        if html_path.exists():
            return FileResponse(html_path, media_type="text/html")
        return HTMLResponse("<h1>Mailwarden</h1><p>Static files not found.</p>")
    
    @app.get("/api/health")
    async def health():
        """Health check endpoint."""
        return {"status": "ok", "version": "1.0.0"}
    
    @app.get("/api/config")
    async def get_config():
        """Get current configuration."""
        if not CONFIG_PATH or not CONFIG_PATH.exists():
            raise HTTPException(status_code=404, detail="Configuration file not found")
        
        try:
            with open(CONFIG_PATH) as f:
                config = yaml.safe_load(f)
            
            # Mask sensitive data
            if config.get("imap", {}).get("password"):
                config["imap"]["password"] = "********"
            
            return {"config": config, "path": str(CONFIG_PATH)}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/config/raw")
    async def get_config_raw():
        """Get raw configuration file content."""
        if not CONFIG_PATH or not CONFIG_PATH.exists():
            raise HTTPException(status_code=404, detail="Configuration file not found")
        
        try:
            with open(CONFIG_PATH) as f:
                content = f.read()
            return {"content": content, "path": str(CONFIG_PATH)}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    class ConfigUpdate(BaseModel):
        content: str
    
    @app.put("/api/config")
    async def update_config(update: ConfigUpdate):
        """Update configuration file."""
        if not CONFIG_PATH:
            raise HTTPException(status_code=404, detail="Configuration file path not set")
        
        try:
            # Validate YAML
            yaml.safe_load(update.content)
            
            # Backup existing config
            if CONFIG_PATH.exists():
                backup_path = CONFIG_PATH.with_suffix(".yml.bak")
                backup_path.write_text(CONFIG_PATH.read_text())
            
            # Write new config
            CONFIG_PATH.write_text(update.content)
            
            return {"status": "ok", "message": "Configuration updated successfully"}
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/logs")
    async def get_logs(limit: int = 100):
        """Get recent log entries."""
        logs = list(log_buffer)[-limit:]
        return {"logs": logs, "total": len(log_buffer)}
    
    @app.websocket("/ws/logs")
    async def websocket_logs(websocket: WebSocket):
        """WebSocket endpoint for realtime logs."""
        await websocket.accept()
        websocket_clients.add(websocket)
        
        try:
            # Send recent logs on connect
            recent_logs = list(log_buffer)[-50:]
            await websocket.send_text(json.dumps({
                "type": "history",
                "data": recent_logs
            }))
            
            # Keep connection alive
            while True:
                try:
                    # Wait for ping/pong or disconnect
                    data = await asyncio.wait_for(
                        websocket.receive_text(),
                        timeout=30.0
                    )
                    if data == "ping":
                        await websocket.send_text("pong")
                except asyncio.TimeoutError:
                    # Send keepalive
                    await websocket.send_text(json.dumps({"type": "keepalive"}))
        except WebSocketDisconnect:
            pass
        finally:
            websocket_clients.discard(websocket)
    
    @app.get("/api/status")
    async def get_status():
        """Get current application status."""
        return {
            "status": "running",
            "config_loaded": CONFIG_PATH is not None and CONFIG_PATH.exists(),
            "config_path": str(CONFIG_PATH) if CONFIG_PATH else None,
            "connected_clients": len(websocket_clients),
            "log_buffer_size": len(log_buffer),
        }


# Default app instance
app = create_app()
