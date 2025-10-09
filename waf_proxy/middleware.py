# middleware.py
from fastapi import Request, WebSocket
from fastapi.responses import JSONResponse, Response
import httpx
from typing import Dict, Optional, List
from rules import RuleEngine, WAFResult
from services import DjangoAPIClient
import asyncio
import logging
import json
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class WAFMiddleware:
    """
    Professional WAF Middleware with real-time WebSocket updates to both admin and client dashboards
    """
    
    def __init__(self, websocket_manager):
        self.rule_engine = RuleEngine()
        self.api_client = DjangoAPIClient()
        self.websocket_manager = websocket_manager
        self.logger = logging.getLogger(__name__)