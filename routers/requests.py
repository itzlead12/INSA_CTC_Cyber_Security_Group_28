from fastapi import APIRouter, HTTPException
from models.request_model import ClientRequest
from services.handler import validate_client, process_request, clients_db
from utils.logger import log_request

router = APIRouter(tags=["Requests"])

@router.post("/process")
async def handle_request(request: ClientRequest):
    log_request(request.client_name, "/api/process")

    # Validate client API key
    client = validate_client(request.api_key)

    # Example: Only admin can send requests to this endpoint
    if client.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied: admin only")

    result = process_request(request)
    return result