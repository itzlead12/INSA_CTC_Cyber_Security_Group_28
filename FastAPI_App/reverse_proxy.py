import httpx
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from typing import Dict

router = APIRouter()

# Example backend (replace with actual client app)
BACKEND_URL = "http://localhost:9000"


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(path: str, request: Request):
    """
    Reverse proxy that forwards safe requests to the client backend.
    Preserves query params, headers, and streaming responses.
    """
    target_url = f"{BACKEND_URL}/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    # Clean headers: don't forward host/content-length (httpx sets them)
    headers: Dict[str, str] = {
        k.decode(): v.decode()
        for k, v in request.headers.raw
        if k.decode().lower() not in {"host", "content-length", "accept-encoding", "connection"}
    }

    # Add real client IP
    client_host = request.client.host if request.client else "unknown"
    headers["x-forwarded-for"] = client_host

    async with httpx.AsyncClient(follow_redirects=True) as client:
        try:
            upstream = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=await request.body(),
                timeout=30.0
            )
        except httpx.RequestError as exc:
            return StreamingResponse(
                iter([f"Upstream request failed: {str(exc)}".encode()]),
                status_code=502
            )

    # Stream response back to client
    excluded_headers = {"content-encoding", "transfer-encoding", "connection"}
    response_headers = {
        k: v for k, v in upstream.headers.items() if k.lower() not in excluded_headers
    }

    return StreamingResponse(
        upstream.aiter_bytes(),
        status_code=upstream.status_code,
        headers=response_headers
    )
