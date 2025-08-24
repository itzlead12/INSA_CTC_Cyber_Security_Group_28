import uvicorn
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse

# Import your own modules
from reverse_proxy import router as proxy_router
from websocket_manager import manager as ws_manager

app = FastAPI(title="FastAPI Core Request Handler")

# WebSocket endpoint (monitoring)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keeps connection alive
    except Exception:
        await ws_manager.disconnect(websocket)

# Core request handler middleware

@app.middleware("http")
async def core_request_handler(request: Request, call_next):
    """
    1. Every incoming request passes here first.
    2. Normally, you'd run WAF checks (handled by teammates).
    3. If blocked → return 403.
    4. If allowed → forward to proxy.
    """
    api_key = request.headers.get("x-api-key")
    if not api_key:
        return JSONResponse({"detail": "Missing API key"}, status_code=401)

    response = await call_next(request)
    return response

# Include reverse proxy routes

app.include_router(proxy_router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
