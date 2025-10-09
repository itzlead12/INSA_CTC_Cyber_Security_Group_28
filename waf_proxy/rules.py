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