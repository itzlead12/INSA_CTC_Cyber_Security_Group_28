<<<<<<< HEAD
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
=======
# main.py
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from middleware import WAFMiddleware, PureWebSocketManager
import logging
import asyncio,json,httpx
from datetime import datetime, date, time
import uvicorn


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

websocket_manager = PureWebSocketManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("WAF Service starting...")
    yield
    logger.info("WAF Service shutting down...")

app = FastAPI(
    title="WAF Proxy Service",
    description="Professional Web Application Firewall as a Service",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://django:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

waf_middleware = WAFMiddleware(websocket_manager)

@app.middleware("http")
async def waf_middleware_handler(request: Request, call_next):
    return await waf_middleware.process_request(request, call_next)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    
    client_id = websocket.query_params.get("client_id")
    connection_type = websocket.query_params.get("type", "admin")
    
    
    await websocket_manager.connect(websocket, connection_type=connection_type, client_id=client_id)
    
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
            elif data == "status":
                status_msg = {
                    "type": "status",
                    "connections": len(websocket_manager.active_connections),
                    "timestamp": datetime.now().isoformat()
                }
                await websocket.send_text(json.dumps(status_msg))
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        websocket_manager.disconnect(websocket)


@app.post("/verify-recaptcha")
async def verify_recaptcha(request: Request):
    try:
        data = await request.json()
        token = data.get("token")
        client_ip = data.get("ip")
        
        logger.info(f"reCAPTCHA verification request from {client_ip}, token: {token[:20] if token else 'none'}...")
        
        if not token or not client_ip:
            return JSONResponse(status_code=400, content={"error": "Missing data"})
        

        if token == "TEST_TOKEN":
            logger.info(f"TEST MODE: Accepting test token for IP {client_ip}")
            if waf_middleware.api_client.redis_client:
                waf_middleware.api_client.redis_client.setex(f"recaptcha:{client_ip}", 300, "1")
            return {"status": "success", "test_mode": True}
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={
                    "secret": "6LeLFNwrAAAAANUxkjqp8r7FDG_3SVaJzk0StMqA",
                    "response": token,
                    "remoteip": client_ip
                }
            )
        
        result = response.json()
        if result.get("success"):
            if waf_middleware.api_client.redis_client:
                waf_middleware.api_client.redis_client.setex(f"recaptcha:{client_ip}", 300, "1")
            return {"status": "success"}
        else:
            return JSONResponse(status_code=403, content={"error": "Verification failed"})
            
    except Exception as e:
        logger.error(f"reCAPTCHA verification error: {e}")
        # Fail open in development
        if waf_middleware.api_client.redis_client:
            waf_middleware.api_client.redis_client.setex(f"recaptcha:{client_ip}", 300, "1")
        return {"status": "success", "development_mode": True}
    
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "WAF Proxy"}

@app.get("/stats")
async def get_stats():
    return {
        "total_requests": websocket_manager.stats["total_requests"],
        "total_blocked": websocket_manager.stats["total_blocked"],
        "total_allowed": websocket_manager.stats["total_allowed"],
        "requests_per_second": websocket_manager.stats["requests_per_second"],
        "active_connections": len(websocket_manager.active_connections)
    }




@app.get("/")
async def root():
    return {
        "message": "WAF Proxy Service", 
        "version": "1.0.0",
        "documentation": "/docs"
    }


if __name__ == "__main__":
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8080, 
        log_level="info"
    )
>>>>>>> 3f30b45 (WAF updated version upload)
