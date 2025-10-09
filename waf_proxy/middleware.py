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
        
        # Perform WAF analysis
        waf_result = await self._analyze_request(request, client_config, client_ip)
        
        # Send real-time update via WebSocket to both dashboards (non-blocking)
        asyncio.create_task(
            self._send_real_time_update(request, client_config, client_ip, waf_result)
        )
        
        if waf_result.blocked:
            return await self._handle_blocked_request(request, waf_result, client_config, client_ip)
        else:
            return await self._handle_allowed_request(request, client_config, client_ip, call_next)

    def _get_client_ip(self, request: Request) -> str:
        """
        Extract real client IP address from headers.
        This gets the actual request sender's IP address, not Docker internal IPs.
        """
        # Common headers that contain real client IP in proxy environments
        ip_headers = [
            'x-real-ip',           # Nginx
            'x-forwarded-for',     # Most proxies (including Docker)
            'x-forwarded',
            'forwarded-for', 
            'forwarded',
            'x-cluster-client-ip',
            'proxy-client-ip',
            'true-client-ip',
            'cf-connecting-ip',    # Cloudflare
        ]
        
        # Check each header in order
        for header in ip_headers:
            ip = request.headers.get(header)
            if ip:
                # x-forwarded-for can contain multiple IPs (client, proxy1, proxy2)
                if ',' in ip:
                    ip = ip.split(',')[0].strip()
                
                # Validate IP format
                if self._is_valid_ip(ip):
                    self.logger.info(f"Found real client IP {ip} in header {header}")
                    return ip
        
        # Fallback to direct connection IP
        direct_ip = request.client.host if request.client else "0.0.0.0"
        self.logger.info(f"Using direct connection IP: {direct_ip}")
        return direct_ip

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    def _is_ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Check if IP is in CIDR range"""
        import ipaddress
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj in network
        except ValueError:
            return False