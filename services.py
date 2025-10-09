import httpx
import redis
import json
from typing import Dict, Optional
from config import settings
import logging

logger = logging.getLogger(__name__)


class DjangoAPIClient:
<<<<<<< HEAD
    """
    Professional HTTP client for Django API communication.
    Handles retries, timeouts, and proper error handling.
    """

=======
   
>>>>>>> 3f30b45 (WAF updated version upload)
    def __init__(self):
        self.base_url = settings.DJANGO_API_URL.rstrip('/')
        self.redis_client = redis.from_url(settings.REDIS_URL)
        self.timeout = httpx.Timeout(10.0, connect=5.0)  # Proper timeouts

<<<<<<< HEAD
    # ---- KEEP THIS FUNCTION AS-IS ----
=======
    
>>>>>>> 3f30b45 (WAF updated version upload)
    async def get_client_configuration(self, host: str) -> Optional[Dict]:
        host = host.split(':')[0].lower().strip()
        
        logger.info(f"Fetching WAF configuration for host: {host}")
        
<<<<<<< HEAD
        # Cache key with versioning
        cache_key = f"waf:v1:config:{host}"
        
        # Check cache first
=======
        
        cache_key = f"waf:v1:config:{host}"
        
        
>>>>>>> 3f30b45 (WAF updated version upload)
        cached = self.redis_client.get(cache_key)
        if cached:
            try:
                return json.loads(cached)
            except json.JSONDecodeError:
                logger.warning(f"Corrupted cache entry for {cache_key}")
                self.redis_client.delete(cache_key)
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                url = f"{self.base_url}/clients/api/v1/clients/{host}/waf-config/"
                
                logger.debug(f"API Request: GET {url}")
                
                response = await client.get(url)
                
                logger.debug(f"API Response: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"Successfully retrieved WAF config for {data.get('client_name', 'unknown')}")
                    self.redis_client.setex(cache_key, 300, json.dumps(data))
                    return data
                    
                elif response.status_code == 404:
                    logger.warning(f"Client configuration not found for host: {host}")
                    self.redis_client.setex(cache_key, 60, json.dumps({'error': 'not_found'}))
                    
                else:
                    logger.error(f"API returned unexpected status: {response.status_code}")
                    
        except httpx.ConnectError as e:
            logger.error(f"Connection error to Django API: {e}")
        except httpx.TimeoutException as e:
            logger.error(f"Timeout contacting Django API: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching WAF config: {e}")
        
        return None
    
    async def get_ip_geolocation(self, ip_address: str) -> Optional[Dict]:
        try:
            url = f"{self.base_url}/api/v1/ip-geolocation/{ip_address}/"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warning(f"Geolocation API returned {response.status_code} for IP {ip_address}")
                    return None
        except Exception as e:
            logger.error(f"Error fetching geolocation for {ip_address}: {e}")
            return None
    
 
    async def log_security_event(self, event_data: dict) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                url = f"{self.base_url}/logs/api/v1/security-events/"
                
<<<<<<< HEAD
                # Fire-and-forget with proper error handling
=======
                
>>>>>>> 3f30b45 (WAF updated version upload)
                response = await client.post(url, json=event_data)
                
                if response.status_code in {200, 201}:
                    logger.info("Security event logged successfully.")
                    return True
                else:
                    logger.warning(f"Failed to log security event. Status: {response.status_code}")
                    return False

        except httpx.RequestError as e:
            logger.error(f"HTTP request error while logging security event: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error logging security event: {e}")
            return False
        
   


api_client = DjangoAPIClient()
