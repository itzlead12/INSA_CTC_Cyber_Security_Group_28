from pydantic import BaseModel

class ClientRequest(BaseModel):
    client_name: str
    api_key: str
    target_url: str
    payload: dict

class Client(BaseModel):
    username: str
    api_key: str
    role: str  # 'admin' or 'user'
