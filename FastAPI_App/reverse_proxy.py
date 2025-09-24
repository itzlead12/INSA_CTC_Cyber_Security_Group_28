import httpx
from fastapi import APIRouter, Request
from fastapi.responses import Response

router = APIRouter()

# Example backend (replace with actual client app)
BACKEND_URL = "http://localhost:9000"

@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(path: str, request: Request):
    """
    Forwards safe requests to the client backend.
    """
    target_url = f"{BACKEND_URL}/{path}"

    # Forward request
    async with httpx.AsyncClient() as client:
        response = await client.request(
            method=request.method,
            url=target_url,
            headers=request.headers.raw,
            content=await request.body()
        )

    # Return backend response
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers)
    )
