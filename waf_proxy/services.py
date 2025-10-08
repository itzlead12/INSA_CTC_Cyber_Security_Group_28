import httpx
import redis
import json
import logging
from typing import Dict, Optional
from config import settings

logger = logging.getLogger(__name__)


class DjangoAPIClient:
    """HTTP client with Redis caching and robust logging."""

    def __init__(self):
        self.base_url = settings.DJANGO_API_URL.rstrip('/')
        self.redis_client = redis.from_url(settings.REDIS_URL)
        self.timeout = httpx.Timeout(10.0, connect=5.0)

    async def get_client_configuration(self, host: str) -> Optional[Dict]:
        host = host.split(':')[0].lower().strip()
        logger.info(f"Fetching WAF configuration for host: {host}")
        cache_key = f"waf:v1:config:{host}"
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
