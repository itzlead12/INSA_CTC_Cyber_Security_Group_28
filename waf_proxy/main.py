from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse
import httpx, re

from reverse_proxy import router as proxy_router
from websocket_manager import manager as ws_manager

# Replace with your Django backend URL
DJANGO_URL = "http://localhost:8001"

app = FastAPI(title="FastAPI WAF Proxy")

# ----------------- WAF Logic -----------------

async def fetch_rules(client_id: str):
    """
    Fetch client-specific rules from Django backend.
    Example response format:
    {"sqli": ["SELECT", "' OR '1'='1"], "xss": ["<script>"]}
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{DJANGO_URL}/api/rules/{client_id}")
        return response.json() if response.status_code == 200 else {}

def is_malicious(body: str, rules: dict):
    """
    Detects SQLi and XSS based on simple patterns.
    """
    for pattern in rules.get("sqli", []):
        if re.search(pattern, body, re.IGNORECASE):
            return True
    for pattern in rules.get("xss", []):
        if re.search(pattern, body, re.IGNORECASE):
            return True
    return False

async def log_blocked_request(request, reason=""):
    """
    Sends logs to Django backend and broadcasts via WebSocket.
    """
    await ws_manager.broadcast(f"Blocked: {request.url} | Reason: {reason}")
    async with httpx.AsyncClient() as client:
        await client.post(f"{DJANGO_URL}/api/logs/", json={
            "url": str(request.url),
            "method": request.method,
            "blocked": True,
            "reason": reason
        })

# ----------------- Middleware -----------------

@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    """
    Core WAF middleware.
    """
    api_key = request.headers.get("x-api-key")
    if not api_key:
        return JSONResponse({"detail": "Missing API key"}, status_code=401)

    client_id = request.headers.get("x-client-id")  # identify client
    rules = await fetch_rules(client_id)

    body = (await request.body()).decode()
    if is_malicious(body, rules):
        await log_blocked_request(request, reason="SQLi/XSS detected")
        return JSONResponse({"detail": "Blocked by WAF"}, status_code=403)

    return await call_next(request)
RATE_LIMIT: Dict[str, Dict[str, Any]] = {}

# ----------------- WebSocket -----------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint to broadcast logs in real-time.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep connection alive
    except Exception:
        await ws_manager.disconnect(websocket)

# ----------------- Include Proxy -----------------

app.include_router(proxy_router)

# ----------------- Run -----------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
