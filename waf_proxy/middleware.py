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

    def _should_skip_waf(self, request: Request) -> bool:
        skip_paths = ['/health', '/metrics', '/docs', '/redoc', '/ws', '/static/','/verify-recaptcha', '/favicon.ico' ]
        return any(request.url.path.startswith(path) for path in skip_paths)
    
    async def _analyze_request(self, request: Request, client_config: dict, client_ip: str) -> WAFResult:
        """Analyze request against WAF rules including country and IP blocking"""
        try:
            # NEW: Check IP blacklist first
            ip_block_result = self._check_ip_blacklist(client_ip, client_config)
            if ip_block_result.blocked:
                return ip_block_result
            
            # NEW: Check country blocking
            country_block_result = await self._check_country_blocking(client_ip, client_config)
            if country_block_result.blocked:
                return country_block_result
            
            # Existing WAF rules check
            request_context = await self._extract_request_context(request, client_ip)
            return self.rule_engine.check_request(
                request_context, 
                client_config.get("rules", [])
            )
        except Exception as e:
            self.logger.error(f"Error during WAF analysis: {e}")
            return WAFResult(blocked=False, reason="Analysis error")

    def _check_ip_blacklist(self, client_ip: str, client_config: dict) -> WAFResult:
        """NEW: Check if IP is in blacklist"""
        if not client_config.get('enable_ip_blacklist', False):
            return WAFResult(blocked=False)
        
        blacklisted_ips = client_config.get('ip_blacklist', [])
        
        # Check exact IP match
        if client_ip in blacklisted_ips:
            return WAFResult(blocked=True, reason=f"IP {client_ip} is blacklisted")
        
        # Check IP range (CIDR) - e.g., "192.168.1.0/24"
        for ip_range in blacklisted_ips:
            if '/' in ip_range and self._is_ip_in_range(client_ip, ip_range):
                return WAFResult(blocked=True, reason=f"IP {client_ip} is in blacklisted range {ip_range}")
        
        return WAFResult(blocked=False)

    async def _check_country_blocking(self, client_ip: str, client_config: dict) -> WAFResult:
        """NEW: Check if country is blocked"""
        if not client_config.get('enable_country_blocking', False):
            return WAFResult(blocked=False)
        
        # Skip private IPs
        if self._is_private_ip(client_ip):
            return WAFResult(blocked=False)
        
        # Get geolocation data via API call to Django
        try:
            country_data = await self.api_client.get_ip_geolocation(client_ip)
            
            if not country_data or 'country_code' not in country_data:
                return WAFResult(blocked=False)
            
            country_code = country_data['country_code']
            
            blocked_countries = client_config.get('blocked_countries', [])
            allowed_countries = client_config.get('allowed_countries', [])
            
            # Allow list mode (only allowed countries can access)
            if allowed_countries:
                if country_code not in allowed_countries:
                    return WAFResult(blocked=True, reason=f"Country {country_code} not in allowed list")
            
            # Block list mode (block specific countries)
            elif blocked_countries:
                if country_code in blocked_countries:
                    return WAFResult(blocked=True, reason=f"Country {country_code} is blocked")
            
            return WAFResult(blocked=False)
            
        except Exception as e:
            self.logger.error(f"Error checking country blocking: {e}")
            return WAFResult(blocked=False)
    
    async def _extract_request_context(self, request: Request, client_ip: str) -> dict:
        """Extract request context for WAF analysis"""
        body = ""
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body_bytes = await request.body()
                body = body_bytes.decode('utf-8', errors='ignore')
            except Exception as e:
                self.logger.warning(f"Error reading request body: {e}")
        
        return {
            "method": request.method,
            "path": str(request.url.path),
            "query_string": str(request.query_params),
            "headers": dict(request.headers),
            "body": body,
            "client_ip": client_ip,  
            "user_agent": request.headers.get("user-agent", ""),
        }

    async def _handle_blocked_request(self, request: Request, waf_result: WAFResult, 
                                client_config: dict, client_ip: str) -> Response:
        self.logger.warning(f"Request blocked: {waf_result.reason} for {client_ip}")
    
        # Log the event
        country_code = ""
        try:
            country_data = await self.api_client.get_ip_geolocation(client_ip)
            country_code = country_data.get('country_code', '') if country_data else ""
        except Exception as e:
            self.logger.error(f"Error getting geolocation for logging: {e}")
    
        await self.api_client.log_security_event({
            "client_host": request.headers.get("host", ""),
            "ip_address": client_ip,
            "country_code": country_code,
            "request_path": request.url.path,
            "user_agent": request.headers.get("user-agent", ""),
            "reason": waf_result.reason,
            "method": request.method,
            "blocked": True,
        })

    async def _handle_allowed_request(self, request: Request, client_config: dict, 
                                    client_ip: str, call_next) -> Response:
        """Handle allowed request"""
        self.logger.debug(f"Request allowed from {client_ip} to {client_config.get('client_name')}")
        
        target_url = client_config.get('target_url')
        if not target_url:
            return JSONResponse(
                status_code=500,
                content={'error': 'Target URL not configured'}
            )
        
        return await self._forward_to_backend(request, target_url)