import redis
import logging, re
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import unquote_plus
from config import settings

logger = logging.getLogger(__name__)

@dataclass
class WAFResult:
    """WAF Analysis Result"""
    blocked: bool
    reason: str = ""
    rule_id: Optional[int] = None
    severity: str = "medium"
    confidence: float = 0.0

class RuleEngine:
    
    
    def __init__(self):
        self.redis_client = self._initialize_redis()
        self.compiled_patterns = {}
        self.rule_cache = {}