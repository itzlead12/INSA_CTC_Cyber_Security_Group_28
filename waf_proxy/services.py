import httpx
import redis
import json
import logging
from typing import Dict, Optional
from config import settings

logger = logging.getLogger(__name__)


class DjangoAPIClient:
    """HTTP client with Redis caching support."""

    def __init__(self):
        self.base_url = settings.DJANGO_API_URL.rstrip('/')
        self.redis_client = redis.from_url(settings.REDIS_URL)
        self.timeout = httpx.Timeout(10.0, connect=5.0)

    async def get_client_configuration(self, host: str) -> Optional[Dict]:
        """Retrieve WAF client configuration and cache results."""
        host = host.split(':')[0].lower().strip()
        cache_key = f"waf:v1:config:{host}"
        cached = self.redis_client.get(cache_key)
        if cached:
            try:
                return json.loads(cached)
            except json.JSONDecodeError:
                logger.warning(f"Corrupted cache entry for {cache_key}")
                self.redis_client.delete(cache_key)
