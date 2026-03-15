import asyncio
import json
import threading
import os
import sys
from datetime import datetime
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.db import init_db, create_session_tables, get_recent_attempts, \
                       get_stats, get_attempts_by_ip, get_recent_sessions, \
                       get_session_commands
from server.honeypot import start_honeypot, set_broadcast_callback

load_dotenv()

API_PORT = int(os.getenv("API_PORT", 8080))

app = FastAPI(title="PiTrap Dashboard API")

connected_websockets: List[WebSocket] = []
main_loop = None

async def broadcast(data: dict):
    dead = []
    for ws in connected_websockets:
        try:
            await ws.send_json(data)
        except:
            dead.append(ws)
    for ws in dead:
        connected_websockets.remove(ws)

def honeypot_broadcast(data: dict):
    if main_loop and main_loop.is_running():
        main_loop.call_soon_threadsafe(
            asyncio.ensure_future,
            broadcast(data)
        )

@app.on_event("startup")
async def startup():
    global main_loop
    main_loop = asyncio.get_running_loop()

    init_db()
    create_session_tables()

    set_broadcast_callback(honeypot_broadcast)

    thread = threading.Thread(
        target=start_honeypot,
        name="honeypot-thread",
        daemon=True
    )
    thread.start()
    print("[API] Honeypot thread started")

@app.get("/")
async def get_dashboard():
    dashboard_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "dashboard", "index.html"
    )
    with open(dashboard_path, "r") as f:
        content = f.read()
    return HTMLResponse(content)

@app.get("/api/attempts")
async def get_attempts(limit: int = 50):
    return get_recent_attempts(limit)

@app.get("/api/stats")
async def get_statistics():
    return get_stats()

@app.get("/api/attacker/{ip}")
async def get_attacker(ip: str):
    attempts = get_attempts_by_ip(ip)
    return {
        "ip": ip,
        "total_attempts": len(attempts),
        "attempts": attempts
    }

@app.get("/api/sessions")
async def get_sessions(limit: int = 20):
    return get_recent_sessions(limit)

@app.get("/api/sessions/{session_id}")
async def get_session_detail(session_id: int):
    commands = get_session_commands(session_id)
    return {
        "session_id": session_id,
        "commands": commands,
        "total": len(commands)
    }

@app.get("/api/tunnel")
async def get_tunnel():
    try:
        import requests
        r = requests.get("http://localhost:4040/api/tunnels", timeout=2)
        data = r.json()
        url = data["tunnels"][0]["public_url"]
        return {"tunnel_url": url, "status": "active"}
    except:
        return {"tunnel_url": None, "status": "inactive"}

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "timestamp": datetime.now().isoformat()
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)

    try:
        recent = get_recent_attempts(20)
        for attempt in reversed(recent):
            await websocket.send_json(attempt)

        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=API_PORT)
