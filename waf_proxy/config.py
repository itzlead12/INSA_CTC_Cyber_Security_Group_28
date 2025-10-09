import os

class Settings:
    # Django API Configuration
    DJANGO_API_URL: str = os.getenv("DJANGO_API_URL", "http://django:8000")
    
    # Redis Configuration
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    
    # WAF Configuration
    WAF_TIMEOUT: int = int(os.getenv("WAF_TIMEOUT", "30"))
    WAF_CACHE_TTL: int = int(os.getenv("WAF_CACHE_TTL", "300"))  # 5 minutes
    
    # Logging Configuration
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    # config.py or add to your existing settings
    
    RECAPTCHA_SITE_KEY = "6LeLFNwrAAAAAF16FkDFMk0EcLreFSOFFRVbitIb"
    RECAPTCHA_SECRET_KEY = "6LeLFNwrAAAAANUxkjqp8r7FDG_3SVaJzk0StMqA" 

settings = Settings()