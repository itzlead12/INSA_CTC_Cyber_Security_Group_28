import httpx
import redis
import json
import logging
from typing import Dict, Optional
from config import settings

logger = logging.getLogger(__name__)


class DjangoAPIClient:
    """Full-featured HTTP client for Django API."""

    def __init__(self):
        self.base_url = settings.DJANGO_API_URL.rstrip('/')
        self.redis_client = redis.from_url(settings.REDIS_URL)
        self.timeout = httpx.Timeout(10.0, connect=5.0)

    async def get_client_configuration(self, host: str) -> Optional[Dict]:
        # (same as before)
        ...

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
