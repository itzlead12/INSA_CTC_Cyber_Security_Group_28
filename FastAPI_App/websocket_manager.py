from typing import List, Dict
from fastapi import WebSocket

class WebSocketManager:
    """
    Manages active WebSocket connections and broadcasts messages.
    """
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.connection_ids: Dict[str, WebSocket] = {}  # optional map for private messaging

    async def connect(self, websocket: WebSocket, client_id: str = None):
        """
        Accepts a new WebSocket connection.
        Optionally stores it under a client_id for private messaging.
        """
        await websocket.accept()
        self.active_connections.append(websocket)
        if client_id:
            self.connection_ids[client_id] = websocket
        print(f"[WS] New connection. Total: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        """
        Removes a WebSocket connection.
        """
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        # also remove from client_id map if it exists
        for cid, ws in list(self.connection_ids.items()):
            if ws == websocket:
                del self.connection_ids[cid]
        print(f"[WS] Disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: str):
        """
        Sends a message to all active connections.
        """
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.append(connection)

        # cleanup broken connections
        for conn in disconnected:
            await self.disconnect(conn)

    async def send_to(self, client_id: str, message: str):
        """
        Sends a message to a specific client if connected.
        """
        websocket = self.connection_ids.get(client_id)
        if websocket:
            try:
                await websocket.send_text(message)
            except Exception:
                await self.disconnect(websocket)

    def count(self) -> int:
        """
        Returns the number of active connections.
        """
        return len(self.active_connections)

    async def heartbeat(self):
        """
        Pings all active connections to ensure they're alive.
        """
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text("ping")
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            await self.disconnect(conn)

# Global manager instance
manager = WebSocketManager()
