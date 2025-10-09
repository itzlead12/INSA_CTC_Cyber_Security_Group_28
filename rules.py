import redis
import logging, re
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import unquote_plus
from config import settings

logger = logging.getLogger(__name__)

@dataclass
class WAFResult:
<<<<<<< HEAD
    """WAF Analysis Result"""
=======
    
>>>>>>> 3f30b45 (WAF updated version upload)
    blocked: bool
    reason: str = ""
    rule_id: Optional[int] = None
    severity: str = "medium"
<<<<<<< HEAD
    confidence: float = 0.0
=======
    confidence: float = 0.0

class RuleEngine:
    
    
    def __init__(self):
        self.redis_client = self._initialize_redis()
        self.compiled_patterns = {}
        self.rule_cache = {}
        
    def _initialize_redis(self) -> Optional[redis.Redis]:
        
        try:
            client = redis.from_url(settings.REDIS_URL)
            client.ping()
            logger.info(" Redis connected successfully")
            return client
        except Exception as e:
            logger.error(f" Redis connection failed: {e}")
            return None
    
    def check_request(self, request: Dict, rules: List[Dict]) -> WAFResult:
        
       
        try:
            
            if not self._validate_request_context(request):
                return WAFResult(blocked=False, reason="Invalid request context")
            
            if not rules:
                logger.debug("No rules to check against")
                return WAFResult(blocked=False)
            
           
            scan_data = self._prepare_scan_data(request)
            client_ip = request.get("client_ip", "0.0.0.0")
            user_agent = request.get("user_agent", "")
            
            logger.debug(f"Scanning request from {client_ip} against {len(rules)} rules")
            
            
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
            
            return WAFResult(blocked=False, reason="Engine error")
    
    def _validate_request_context(self, request: Dict) -> bool:
        
        required_fields = ['method', 'path', 'client_ip']
        for field in required_fields:
            if field not in request or not request[field]:
                logger.warning(f"Missing required field in request context: {field}")
                return False
        return True
    
    def _prepare_scan_data(self, request: Dict) -> str:
        
        try:
            path = request.get("path", "")
            query = unquote_plus(request.get("query_string", ""))
            body = unquote_plus(request.get("body", ""))
            
            
            headers_str = ""
            headers = request.get("headers", {})
            for hdr in ["cookie", "referer", "x-forwarded-for", "x-forwarded-host", "origin", "host"]:
                val = headers.get(hdr, "")
                if val:
                    headers_str += " " + unquote_plus(str(val))

            
            scan_data = f"{path} {query} {body} {headers_str}".lower()
            
            
            max_scan_size = 10000  
            if len(scan_data) > max_scan_size:
                scan_data = scan_data[:max_scan_size]
                logger.warning("Scan data truncated due to size limits")
            
            return scan_data
            
        except Exception as e:
            logger.error(f"Error preparing scan data: {e}")
            return ""
    
    def _prioritize_rules(self, rules: List[Dict]) -> List[Dict]:
        
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        
        return sorted(rules, key=lambda x: severity_order.get(x.get('severity', 'medium'), 2))
    
    def _apply_single_rule(self, rule: Dict, scan_data: str, client_ip: str, user_agent: str) -> WAFResult:
        
        try:
            rule_type = rule.get("rule_type", "")
            rule_value = rule.get("value", "")
            rule_id = rule.get("id")
            severity = rule.get("severity", "medium")
            
            if not rule_type or not rule_value:
                return WAFResult(blocked=False)
            
            
            handler_method = getattr(self, f"_handle_{rule_type}", None)
            if handler_method and callable(handler_method):
                result = handler_method(rule_value, scan_data, client_ip, user_agent)
                if result.blocked:
                    result.rule_id = rule_id
                    result.severity = severity
                    return result
            
            return WAFResult(blocked=False)
            
        except Exception as e:
            logger.error(f"Error applying rule {rule.get('id')}: {e}")
            return WAFResult(blocked=False)
    
    def _handle_sql_injection(self, patterns_value: str, data: str, client_ip: str, user_agent: str) -> WAFResult:
        
        try:
            patterns = self._parse_patterns(patterns_value)
            
            for pattern in patterns:
                if not pattern:
                    continue
                
                
                test_patterns = self._generate_test_patterns(pattern)
                
                for test_pattern in test_patterns:
                    if self._safe_pattern_match(test_pattern, data):
                        return WAFResult(
                            blocked=True, 
                            reason=f"SQL Injection pattern detected: {pattern}",
                            confidence=0.9
                        )
            
            return WAFResult(blocked=False)
            
        except Exception as e:
            logger.error(f"Error in SQL injection detection: {e}")
            return WAFResult(blocked=False)
    
    def _handle_xss(self, patterns_value: str, data: str, client_ip: str, user_agent: str) -> WAFResult:
        
        try:
            patterns = self._parse_patterns(patterns_value)
            
            for pattern in patterns:
                if self._safe_pattern_match(pattern, data):
                    return WAFResult(
                        blocked=True,
                        reason=f"XSS pattern detected: {pattern}",
                        confidence=0.8
                    )
            
            return WAFResult(blocked=False)
            
        except Exception as e:
            logger.error(f"Error in XSS detection: {e}")
            return WAFResult(blocked=False)
    
    def _handle_rate_limit(self, config_value: str, data: str, client_ip: str, user_agent: str) -> WAFResult:
        
        try:
            if not self.redis_client:
                return WAFResult(blocked=False) 
            
           
            config_parts = config_value.split(':')
            if len(config_parts) != 2:
                logger.warning(f"Invalid rate limit configuration: {config_value}")
                return WAFResult(blocked=False)
            
            try:
                requests_per_second = float(config_parts[0])
                max_burst = int(config_parts[1])
            except ValueError:
                logger.warning(f"Invalid rate limit values: {config_value}")
                return WAFResult(blocked=False)
            
            
            redis_key = f"rate_limit:{client_ip}"
            current_time = self.redis_client.time()[0]  
            
            
            token_data = self.redis_client.get(redis_key)
            if token_data:
                last_update, tokens = map(float, token_data.decode().split(':'))
            else:
                last_update, tokens = current_time, max_burst
            
            
            time_passed = current_time - last_update
            new_tokens = tokens + (time_passed * requests_per_second)
            tokens = min(new_tokens, max_burst)
            
            
            if tokens >= 1.0:
                tokens -= 1.0
                
                self.redis_client.setex(
                    redis_key, 
                    3600,  
                    f"{current_time}:{tokens}"
                )
                return WAFResult(blocked=False)
            else:
                return WAFResult(
                    blocked=True,
                    reason=f"Rate limit exceeded for {client_ip}",
                    confidence=1.0
                )
                
        except Exception as e:
            logger.error(f"Error in rate limiting: {e}")
            return WAFResult(blocked=False)  
    
    def _handle_path_traversal(self, patterns_value: str, data: str, client_ip: str, user_agent: str) -> WAFResult:
       
        try:
            patterns = self._parse_patterns(patterns_value)
            
            for pattern in patterns:
                if self._safe_pattern_match(pattern, data):
                    return WAFResult(
                        blocked=True,
                        reason=f"Path traversal pattern detected: {pattern}",
                        confidence=0.7
                    )
            
            return WAFResult(blocked=False)
            
        except Exception as e:
            logger.error(f"Error in path traversal detection: {e}")
            return WAFResult(blocked=False)
    
    def _handle_rce(self, patterns_value: str, data: str, client_ip: str, user_agent: str) -> WAFResult:
        
        try:
            patterns = self._parse_patterns(patterns_value)
            
            for pattern in patterns:
                if self._safe_pattern_match(pattern, data):
                    return WAFResult(
                        blocked=True,
                        reason=f"RCE pattern detected: {pattern}",
                        confidence=0.8
                    )
            
            return WAFResult(blocked=False)
            
        except Exception as e:
            logger.error(f"Error in RCE detection: {e}")
            return WAFResult(blocked=False)
    
    def _handle_ua_block(self, patterns_value: str, data: str, client_ip: str, user_agent: str) -> WAFResult:
        
        try:
            if not user_agent:
                return WAFResult(blocked=False)
            
            patterns = self._parse_patterns(patterns_value)
            user_agent_lower = user_agent.lower()
            
            for pattern in patterns:
                if pattern.lower() in user_agent_lower:
                    return WAFResult(
                        blocked=True,
                        reason=f"Blocked User Agent: {pattern}",
                        confidence=0.9
                    )
            
            return WAFResult(blocked=False)
            
        except Exception as e:
            logger.error(f"Error in User Agent blocking: {e}")
            return WAFResult(blocked=False)
    def _handle_lfi(self, patterns_value, data, client_ip, user_agent) -> WAFResult:
        return self._handle_path_traversal(patterns_value, data, client_ip, user_agent)

    def _handle_rfi(self, patterns_value, data, client_ip, user_agent) -> WAFResult:
        return self._handle_rce(patterns_value, data, client_ip, user_agent)
    
    def _handle_recaptcha(self, patterns_value: str, data: str, client_ip: str, user_agent: str) -> WAFResult:
        
        if self._is_recaptcha_solved(client_ip):
            return WAFResult(blocked=False)
        return WAFResult(blocked=True, reason="reCAPTCHA required", confidence=0.5)

    def _is_recaptcha_solved(self, client_ip: str) -> bool:
        
        if not self.redis_client:
            return True  # Fail open
        token = self.redis_client.get(f"recaptcha:{client_ip}")
        return token is not None


    def _parse_patterns(self, patterns_value: str) -> List[str]:
        
        try:
            patterns = [p.strip() for p in patterns_value.split('\n') if p.strip()]
            
            
            valid_patterns = []
            for pattern in patterns:
                if 1 <= len(pattern) <= 500: 
                    valid_patterns.append(pattern)
                else:
                    logger.warning(f"Invalid pattern length: {len(pattern)}")
            
            return valid_patterns
            
        except Exception as e:
            logger.error(f"Error parsing patterns: {e}")
            return []
    
    def _generate_test_patterns(self, pattern: str) -> List[str]:
        
        patterns = [pattern]
        
        # URL encoding variations
        url_encoded = pattern.replace("'", "%27").replace(" ", "%20").replace("=", "%3D")
        if url_encoded != pattern:
            patterns.append(url_encoded)
        
        # Double encoding
        double_encoded = url_encoded.replace("%", "%25")
        if double_encoded != url_encoded:
            patterns.append(double_encoded)
        
        
        html_encoded = pattern.replace("<", "<").replace(">", ">")
        if html_encoded != pattern:
            patterns.append(html_encoded)
        
        return patterns
    
    def _safe_pattern_match(self, pattern: str, data: str) -> bool:
        try:
            
            if len(pattern) < 50 and all(c.isalnum() or c in " ._-" for c in pattern):
                return pattern.lower() in data.lower()
            
            return bool(re.search(pattern, data, flags=re.IGNORECASE))
        except re.error:
            logger.warning(f"Invalid regex pattern: {pattern}")
            return False

    
    def cleanup(self):
        if self.redis_client and hasattr(self.redis_client, "close"):
            self.redis_client.close()
        
        self.compiled_patterns.clear()
        self.rule_cache.clear()


RULE_HANDLERS = {
    'sql_injection': 'SQL Injection',
    'xss': 'Cross-Site Scripting',
    'rate_limit': 'Rate Limiting',
    'path_traversal': 'Path Traversal',
    'rce': 'Remote Code Execution',
    'ua_block': 'User Agent Blocking',
    'lfi': 'Local File Inclusion',
    'rfi': 'Remote File Inclusion',
}

def create_rule_engine() -> RuleEngine:
    return RuleEngine()
>>>>>>> 3f30b45 (WAF updated version upload)
