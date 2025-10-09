# middleware.py
from fastapi import Request, WebSocket
from fastapi.responses import JSONResponse, Response
import httpx
from typing import Dict, Optional, List
from rules import RuleEngine, WAFResult
from services import DjangoAPIClient
import asyncio
import logging
import json
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class WAFMiddleware:
    """
    Professional WAF Middleware with real-time WebSocket updates to both admin and client dashboards
    """
    
    def __init__(self, websocket_manager):
        self.rule_engine = RuleEngine()
        self.api_client = DjangoAPIClient()
        self.websocket_manager = websocket_manager
        self.logger = logging.getLogger(__name__)
    
    async def process_request(self, request: Request, call_next):
        """
        Process incoming request through WAF pipeline with real-time updates to both dashboards
        """
        client_host = request.headers.get("host", "").split(':')[0]
        client_ip = self._get_client_ip(request)
        
        self.logger.info(f"Processing request: {request.method} {request.url.path} from {client_ip} to {client_host}")
        
        # Skip WAF for health checks and internal endpoints
        if self._should_skip_waf(request):
            response = await call_next(request)
            return response
        
        # Get client configuration
        client_config = await self.api_client.get_client_configuration(client_host)
        
        if not client_config or client_config.get('error') == 'not_found':
            self.logger.warning(f"No WAF configuration found for host: {client_host}")
            return JSONResponse(
                status_code=404,
                content={
                    'error': 'Service not configured',
                    'detail': f'No WAF configuration found for {client_host}'
                }
            )