import httpx
from fastapi import APIRouter, Request
from fastapi.responses import Response

router = APIRouter()

# Target backend
BACKEND_URL = "http://localhost:9000"

@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(path: str, request: Request):
    """
    Forwards requests to the backend.
    """
    target_url = f"{BACKEND_URL}/{path}"

    async with httpx.AsyncClient() as client:
        response = await client.request(
            method=request.method,
            url=target_url,
            headers=request.headers.raw,
            content=await request.body()
        )

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers),
    )
