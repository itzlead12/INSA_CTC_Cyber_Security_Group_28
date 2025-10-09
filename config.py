import os

class Settings:
    DJANGO_API_URL: str = os.getenv("DJANGO_API_URL", "http://django:8000")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    WAF_TIMEOUT: int = int(os.getenv("WAF_TIMEOUT", "30"))
    WAF_CACHE_TTL: int = int(os.getenv("WAF_CACHE_TTL", "300"))  
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    RECAPTCHA_SITE_KEY = "6LeLFNwrAAAAAF16FkDFMk0EcLreFSOFFRVbitIb"
    RECAPTCHA_SECRET_KEY = "6LeLFNwrAAAAANUxkjqp8r7FDG_3SVaJzk0StMqA" 
settings = Settings()