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
        
    def _initialize_redis(self) -> Optional[redis.Redis]:
        """Initialize Redis connection with proper error handling"""
        try:
            client = redis.from_url(settings.REDIS_URL)
            client.ping()
            logger.info(" Redis connected successfully")
            return client
        except Exception as e:
            logger.error(f" Redis connection failed: {e}")
            return None
    
    def check_request(self, request: Dict, rules: List[Dict]) -> WAFResult:
        """
        Analyze request against WAF rules with professional error handling
        """
        try:
            # Validate input parameters
            if not self._validate_request_context(request):
                return WAFResult(blocked=False, reason="Invalid request context")
            
            if not rules:
                logger.debug("No rules to check against")
                return WAFResult(blocked=False)
            
            # Prepare data for scanning
            scan_data = self._prepare_scan_data(request)
            client_ip = request.get("client_ip", "0.0.0.0")
            user_agent = request.get("user_agent", "")
            
            logger.debug(f"Scanning request from {client_ip} against {len(rules)} rules")
            
            # Check each rule with priority based on severity
            prioritized_rules = self._prioritize_rules(rules)
            
            for rule in prioritized_rules:
                result = self._apply_single_rule(rule, scan_data, client_ip, user_agent)
                if result.blocked:
                    logger.warning(f"Request blocked by rule {rule.get('id')}: {result.reason}")
                    return result
            
            logger.debug("Request passed all security checks")
            return WAFResult(blocked=False)
            
        except Exception as e:
            logger.error(f"Error during WAF analysis: {e}")
            # Fail open - allow request on engine error
            return WAFResult(blocked=False, reason="Engine error")