import httpx
from config import settings


class DjangoAPIClient:
    """HTTP client for Django API communication."""

    def __init__(self):
        self.base_url = settings.DJANGO_API_URL.rstrip('/')
        self.timeout = httpx.Timeout(10.0, connect=5.0)
