from models.request_model import ClientRequest, Client
from fastapi import HTTPException

# In-memory client store
clients_db = {
    "client1": Client(username="client1", api_key="123", role="admin"),
    "client2": Client(username="client2", api_key="456", role="user")
}

def validate_client(api_key: str) -> Client:
    # Find client by API key
    for client in clients_db.values():
        if client.api_key == api_key:
            return client
    raise HTTPException(status_code=401, detail="Invalid API key")

def process_request(request: ClientRequest) -> dict:
    # Example processing
    return {
        "status": "success",
        "client": request.client_name,
        "data": request.payload
    }
