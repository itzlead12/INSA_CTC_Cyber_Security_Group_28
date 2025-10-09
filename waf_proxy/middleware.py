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

class PureWebSocketManager:
    """
    Pure WebSocket manager - broadcasts real-time data to both admin and client dashboards
    """
    
    def __init__(self):
        self.active_connections = []
        self.api_base_url = "http://django:8000"
        self.stats_cache = {}
        self.last_api_fetch = None
        self.request_timestamps = []

    async def connect(self, websocket: WebSocket, connection_type: str = "admin", client_id: str = None):
        """Accept and track new WebSocket connection for both admin and client dashboards"""
        await websocket.accept()
        
        connection_info = {
            'websocket': websocket,
            'type': connection_type,  # 'admin' or 'client'
            'client_id': client_id,   # Only for client connections
            'connected_at': datetime.now()
        }
        self.active_connections.append(connection_info)
        
        logger.info(f"New {connection_type} WebSocket connection. Total: {len(self.active_connections)}")
        
        # Send appropriate dashboard data
        if connection_type == "admin":
            await self.send_admin_dashboard_data(websocket)
        else:
            await self.send_client_dashboard_data(websocket, client_id)

    def disconnect(self, websocket: WebSocket):
        """Remove disconnected WebSocket"""
        for connection_info in self.active_connections:
            if connection_info['websocket'] == websocket:
                self.active_connections.remove(connection_info)
                logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")
                break

    async def send_admin_dashboard_data(self, websocket: WebSocket):
        """Send admin dashboard data"""
        try:
            dashboard_data = await self.fetch_admin_dashboard_data()
            
            full_data = {
                "type": "dashboard_data",
                "dashboard_type": "admin",
                "global_stats": dashboard_data.get("global_stats", {}),
                "charts_data": dashboard_data.get("charts_data", {}),
                "recent_activity": dashboard_data.get("recent_activity", []),
                "timestamp": datetime.now().isoformat()
            }
            
            await websocket.send_text(json.dumps(full_data))
            logger.info("📊 Sent admin dashboard data to WebSocket client")
        except Exception as e:
            logger.error(f"Error sending admin dashboard data: {e}")

    async def send_client_dashboard_data(self, websocket: WebSocket, client_id: str):
        """Send client dashboard data"""
        try:
            client_data = await self.fetch_client_dashboard_data(client_id)
            
            client_dashboard_data = {
                "type": "client_dashboard_data",
                "dashboard_type": "client",
                "global_stats": client_data.get("global_stats", {}),
                "charts_data": client_data.get("charts_data", {}),
                "recent_activity": client_data.get("recent_activity", []),
                "client_info": client_data.get("client_info", {}),
                "timestamp": datetime.now().isoformat()
            }
            
            await websocket.send_text(json.dumps(client_dashboard_data))
            logger.info(f"📊 Sent client dashboard data for client {client_id}")
        except Exception as e:
            logger.error(f"Error sending client dashboard data: {e}")

    async def fetch_admin_dashboard_data(self) -> Dict:
        """Fetch admin dashboard data from Django API"""
        try:
            stats_url = f"{self.api_base_url}/api/stats/"
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(stats_url)
                response.raise_for_status()
                api_data = response.json()
            
            dashboard_data = self.process_admin_api_data(api_data)
            self.stats_cache = dashboard_data
            self.last_api_fetch = datetime.now()
            
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Error fetching admin dashboard data: {e}")
            return self.stats_cache or self.get_admin_fallback_data()

    async def fetch_client_dashboard_data(self, client_id: str) -> Dict:
        """Fetch client dashboard data from Django API"""
        try:
            stats_url = f"{self.api_base_url}/clients/api/{client_id}/stats/"
            async with httpx.AsyncClient(timeout=10.0) as client:
                headers = {"X-Internal-Secret": "your-secret-key-123"}
                response = await client.get(stats_url, headers=headers)
                response.raise_for_status()
                api_data = response.json()
            
            return self.process_client_api_data(api_data)
            
        except Exception as e:
            logger.error(f"Error fetching client dashboard data for {client_id}: {e}")
            return self.get_client_fallback_data()

    def process_admin_api_data(self, api_data: Dict) -> Dict:
        """Process admin API data into dashboard format"""
        global_stats = api_data.get("global_stats", {})
        charts_data = api_data.get("charts_data", {})
        recent_activity = api_data.get("recent_activity", [])

        # FIX: Use prepare_traffic_chart_data to ensure 24 hours of data
        requests_by_hour = charts_data.get("requests_by_hour", [])
        traffic_chart_data = self.prepare_traffic_chart_data(requests_by_hour)
    
        # Admin threat data uses "threat_types" format
        threat_types = charts_data.get("threat_types", [])
        threat_chart_data = {
            "labels": [t.get('reason', 'Unknown') for t in threat_types],
            "series": [t.get('count', 0) for t in threat_types]
        }

        logger.info(f"📊 Admin API - Traffic: {len(traffic_chart_data)} hours, Threats: {len(threat_types)} types")

        return {
            "global_stats": {
                "total_requests": global_stats.get("total_requests", 0),
                "total_blocked": global_stats.get("total_blocked", 0),
                "total_allowed": global_stats.get("total_allowed", 0),
                "requests_per_second": self.calculate_current_rps(),
                "total_clients": global_stats.get("total_clients", 0),
                "total_rules": global_stats.get("total_rules", 0),
                "recent_threats": global_stats.get("recent_threats", 0)
            },
            "charts_data": {
                "traffic_data": traffic_chart_data,
                "threat_data": threat_chart_data,
                "top_ips": charts_data.get("top_blocked_ips", [])
            },
            "recent_activity": recent_activity
        }

    def process_client_api_data(self, api_data: Dict) -> Dict:
        """Process client API data into dashboard format"""
        global_stats = api_data.get("global_stats", {})
        charts_data = api_data.get("charts_data", {})
        recent_activity = api_data.get("recent_activity", [])

        # FIX: Use prepare_traffic_chart_data for client data too
        traffic_data = charts_data.get("traffic_data", [])
        traffic_chart_data = self.prepare_traffic_chart_data(traffic_data)
    
        # Client threat data is already in the right format
        threat_chart_data = charts_data.get("threat_data", {"labels": [], "series": []})

        logger.info(f"📊 Client API - Traffic: {len(traffic_chart_data)} hours, Threats: {len(threat_chart_data.get('labels', []))} types")

        return {
            "global_stats": {
                "total_requests": global_stats.get("total_requests", 0),
                "total_blocked": global_stats.get("total_blocked", 0),
                "total_allowed": global_stats.get("total_allowed", 0),
                "requests_per_second": self.calculate_current_rps(),
                "total_clients": 1,
                "total_rules": global_stats.get("total_rules", 0),
                "recent_threats": global_stats.get("recent_threats", 0)
            },
            "charts_data": {
                "traffic_data": traffic_chart_data,
                "threat_data": threat_chart_data,
                "top_ips": charts_data.get("top_ips", [])
            },
            "recent_activity": recent_activity,
            "client_info": {
                "name": api_data.get("client_name", "Unknown Client")
            }
        }

    def prepare_traffic_chart_data(self, requests_by_hour: List[Dict]) -> List[Dict]:
        """Prepare traffic chart data with 24 hours"""
        logger.info(f"📊 Preparing traffic chart data: {len(requests_by_hour)} hours")
    
        # Ensure we have data for all 24 hours (fill missing hours with zeros)
        chart_data = []
        for hour in range(24):
            # Find data for this hour, or create empty data
            hour_data = next((item for item in requests_by_hour if item.get('hour') == hour), None)
            if hour_data:
                chart_data.append(hour_data)
            else:
                chart_data.append({
                    "hour": hour,
                    "blocked": 0,
                    "allowed": 0,
                    "total": 0
                })
        return chart_data

    def prepare_threat_chart_data(self, threat_types: List[Dict]) -> Dict:
        """Prepare threat distribution chart data"""
        labels = []
        series = []
        
        for threat in threat_types:
            reason = threat.get("reason", "Unknown")
            if not reason or reason == "None":
                reason = "Other"
            labels.append(reason)
            series.append(threat.get("count", 0))
        
        return {
            "labels": labels,
            "series": series
        }

    def get_admin_fallback_data(self) -> Dict:
        """Return fallback data for admin dashboard"""
        return {
            "global_stats": {
                "total_requests": 0,
                "total_blocked": 0,
                "total_allowed": 0,
                "requests_per_second": 0,
                "total_clients": 1,
                "total_rules": 3,
                "recent_threats": 0
            },
            "charts_data": {
                "traffic_data": [],
                "threat_data": {"labels": [], "series": []},
                "top_ips": []
            },
            "recent_activity": []
        }

    def get_client_fallback_data(self) -> Dict:
        """Return fallback data for client dashboard"""
        return {
            "global_stats": {
                "total_requests": 0,
                "total_blocked": 0,
                "total_allowed": 0,
                "requests_per_second": 0,
                "total_clients": 1,
                "total_rules": 0,
                "recent_threats": 0
            },
            "charts_data": {
                "traffic_data": [],
                "threat_data": {"labels": [], "series": []},
                "top_ips": []
            },
            "recent_activity": [],
            "client_info": {
                "name": "Unknown Client"
            }
        }

    def update_request_timestamps(self):
        """Update request timestamps for RPS calculation"""
        now = datetime.now()
        self.request_timestamps.append(now)
        
        self.request_timestamps = [
            ts for ts in self.request_timestamps 
            if (now - ts).total_seconds() < 10
        ]

    def calculate_current_rps(self) -> float:
        """Calculate current requests per second based on recent requests"""
        if not self.request_timestamps:
            return 0.0
        
        now = datetime.now()
        recent_requests = [
            ts for ts in self.request_timestamps 
            if (now - ts).total_seconds() <= 5
        ]
        
        return len(recent_requests) / 5.0
    
    async def broadcast_to_all(self, message: dict):
        """Broadcast message to all connected WebSockets (both admin and client)"""
        if not self.active_connections:
            return
            
        disconnected = []
        
        for connection_info in self.active_connections:
            try:
                await connection_info['websocket'].send_text(json.dumps(message))
                logger.debug(f"📢 Broadcasted {message.get('type')} to {connection_info['type']} dashboard")
            except Exception as e:
                logger.error(f"Error broadcasting to WebSocket: {e}")
                disconnected.append(connection_info)
        
        # Clean up disconnected clients
        for connection_info in disconnected:
            self.disconnect(connection_info['websocket'])

    async def broadcast_to_admins(self, message: dict):
        """Broadcast message only to admin dashboards"""
        admin_connections = [
            conn for conn in self.active_connections 
            if conn.get('type') == 'admin'
        ]
        
        if not admin_connections:
            return
            
        disconnected = []
        
        for connection_info in admin_connections:
            try:
                await connection_info['websocket'].send_text(json.dumps(message))
                logger.debug(f"📢 Broadcasted to admin dashboard")
            except Exception as e:
                logger.error(f"Error broadcasting to admin WebSocket: {e}")
                disconnected.append(connection_info)
        
        for connection_info in disconnected:
            self.disconnect(connection_info['websocket'])

    async def broadcast_to_client(self, client_id: str, message: dict):
        """Broadcast message only to specific client dashboard"""
        client_connections = [
            conn for conn in self.active_connections 
            if conn.get('type') == 'client' and conn.get('client_id') == client_id
        ]
        
        if not client_connections:
            return
            
        disconnected = []
        
        for connection_info in client_connections:
            try:
                await connection_info['websocket'].send_text(json.dumps(message))
                logger.debug(f"🔴 Broadcasted to client {client_id}")
            except Exception as e:
                logger.error(f"Error broadcasting to client WebSocket: {e}")
                disconnected.append(connection_info)
        
        for connection_info in disconnected:
            self.disconnect(connection_info['websocket'])


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
    
    async def _forward_to_backend(self, request: Request, target_url: str) -> Response:
        """Forward request to backend service"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                url = f"{target_url.rstrip('/')}{request.url.path}"
                if request.url.query:
                    url += f"?{request.url.query}"
                
                headers = dict(request.headers)
                headers.pop("host", None)
                headers.pop("content-length", None)
                
                if request.method in ["POST", "PUT", "PATCH"]:
                    body = await request.body()
                    response = await client.request(
                        request.method, url, headers=headers, content=body
                    )
                else:
                    response = await client.request(
                        request.method, url, headers=headers
                    )
                
                return Response(
                    content=response.content,
                    status_code=response.status_code,
                    headers=dict(response.headers)
                )
                
        except httpx.ConnectError:
            return Response(content=b"Backend service unavailable", status_code=503)
        except Exception as e:
            self.logger.error(f"Error forwarding request: {e}")
            return Response(content=b"Internal server error", status_code=500)

    async def _send_real_time_update(self, request: Request, client_config: dict, 
                                   client_ip: str, waf_result: WAFResult):
        """Send real-time update to WebSocket dashboards"""
        try:
            # Prepare request data with client ID for client dashboard targeting
            request_data = {
                "client_ip": client_ip,  # This now contains the REAL request sender IP
                "client_name": client_config.get('client_name', 'unknown'),
                "client_id": str(client_config.get('id')),  # Convert to string for consistency
                "client_host": client_config.get('host'),
                "path": request.url.path,
                "method": request.method,
                "user_agent": request.headers.get("user-agent", ""),
                "waf_blocked": waf_result.blocked,
                "threat_type": waf_result.reason if waf_result.blocked else "allowed",
                "timestamp": datetime.now().isoformat(),
                "rule_id": waf_result.rule_id
            }
            
            self.logger.info(f"📡 Broadcasting real-time update to both dashboards for {request_data['client_name']} from IP {client_ip}")
            
            # Broadcast to both admin and relevant client dashboard
            await self.websocket_manager.broadcast_request_event(request_data)
            
        except Exception as e:
            self.logger.error(f"Error sending real-time update: {e}")

    async def _handle_recaptcha(self, config_value: str, data: str, client_ip: str, user_agent: str) -> WAFResult:
        """Handle reCAPTCHA challenge for suspicious traffic"""
        if self._is_recaptcha_solved(client_ip):
            return WAFResult(blocked=False)
        return WAFResult(blocked=True, reason="reCAPTCHA required", confidence=0.5)

    def _is_recaptcha_solved(self, client_ip: str) -> bool:
        """Check if reCAPTCHA was solved recently (TTL: 5 minutes)"""
        # This would typically check Redis or another cache
        # For now, return False to always require reCAPTCHA
        return False