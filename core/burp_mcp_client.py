"""
Freeboldsec AI VulnOps Framework - Burp Suite MCP Client
Advanced integration with Burp Suite Pro via Model Context Protocol

Author: Jason Haddix, Director of Technical Operations at BishopFox
Framework: The Bug Hunter's Methodology (TBHM) - AI Edition
Version: 2.5.0 (Aggressive Exploitation Mode)
"""

import asyncio
import json
import logging
import os
import time
import re
import sys
import hashlib
from typing import Dict, Any, List, Optional, Callable, Union, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, parse_qs

import aiohttp

# Import core framework components
if __name__ == "__main__" or not __package__:
    # Running as a script or directly imported - adjust path and use absolute imports
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.memory_manager import MemoryManager
    from core.model_dispatcher import ModelDispatcher
    from personas.persona_loader import load_persona
    from utils.logger import setup_logger
    from exploits.exploit_generator import ExploitGenerator
    from reporting.vuln_reporter import VulnReporter
else:
    # Running as a module - use relative imports
    from .memory_manager import MemoryManager
    from .model_dispatcher import ModelDispatcher
    from ..personas.persona_loader import load_persona
    from ..utils.logger import setup_logger
    from ..exploits.exploit_generator import ExploitGenerator
    from ..reporting.vuln_reporter import VulnReporter
    from reporting.vuln_reporter import VulnReporter

logger = setup_logger("freeboldsec.mcp.client", level=logging.INFO, 
                     file_path="logs/burp_mcp_client.log", 
                     console=True)


@dataclass
class BurpTool:
    """Represents a tool available in Burp Suite via MCP"""
    name: str
    tool_id: str
    description: str
    parameters: Dict[str, Any]
    requires_target: bool = True


@dataclass
class VulnerabilityIndicator:
    """Vulnerability indicator identified through traffic analysis"""
    vuln_type: str
    confidence: float
    evidence: str
    request_id: Optional[str] = None
    location: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        return {
            "type": self.vuln_type,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "request_id": self.request_id,
            "location": self.location,
            "timestamp": self.timestamp
        }


class BurpMCPClient:
    """Advanced client for interacting with Burp Suite Pro via MCP server
    
    Features:
    - Real-time vulnerability detection with AI-powered analysis
    - Persona-based prompting for specialized security tasks
    - Automated exploit generation and validation
    - Context memory for cross-request vulnerability correlation
    """
    
    def __init__(
        self, 
        mcp_url: str = "http://localhost:9876/sse",
        api_key: Optional[str] = None,
        memory_size: int = 100,
        enable_auto_exploit: bool = True,
        log_level: int = logging.INFO,
        reconnect_delay: int = 1000,
        max_reconnect_attempts: int = 0  # 0 = infinite
    ):
        self.mcp_url = mcp_url
        self.api_key = api_key or os.environ.get("BURP_MCP_KEY")
        self.session: Optional[aiohttp.ClientSession] = None
        self.connected = False
        self.available_tools: Dict[str, BurpTool] = {}
        self.memory = MemoryManager(max_size=memory_size)
        self.model_dispatcher = ModelDispatcher()
        self.enable_auto_exploit = enable_auto_exploit
        self.max_reconnect_attempts = max_reconnect_attempts
        self.reconnect_delay = reconnect_delay
        self.target_scope: Set[str] = set()
        
        # Load specialized security personas
        self.personas = {
            "recon": load_persona("recon_strategist"),
            "vuln_hunter": load_persona("vuln_hunter"),
            "exploit": load_persona("exploit_architect"),
            "report": load_persona("report_engineer")
        }
        
        # Statistics and metrics
        self.stats = {
            "messages_received": 0,
            "potential_vulns_found": 0,
            "confirmed_vulns": 0,
            "exploits_generated": 0,
            "reconnect_attempts": 0,
            "start_time": time.time()
        }
        
        # Event handlers
        self.event_handlers = {}
        
        # Register default event handlers
        self.register_event_handler("request", self._handle_request)
        self.register_event_handler("response", self._handle_response)
        self.register_event_handler("scan-issue", self._handle_scan_issue)
        self.register_event_handler("scan-start", self._handle_scan_start)
        
        # Initialize available Burp tools
        self._initialize_burp_tools()
        
        logger.info(f"Freeboldsec Burp MCP Client initialized - targeting {mcp_url}")
    
    def _initialize_burp_tools(self):
        """Initialize the available Burp Suite MCP tools"""
        tools = {
            "get_proxy_history": BurpTool(
                "Get Proxy History", "mcp_burpmcp_get_proxy_http_history", 
                "Retrieve HTTP requests and responses from Burp proxy history",
                {"count": 10, "offset": 0},
                requires_target=False
            ),
            "get_proxy_history_regex": BurpTool(
                "Get Proxy History (Regex)", "mcp_burpmcp_get_proxy_http_history_regex",
                "Search proxy history using regex patterns",
                {"count": 10, "offset": 0, "regex": ""},
                requires_target=False
            ),
            "get_scanner_issues": BurpTool(
                "Get Scanner Issues", "mcp_burpmcp_get_scanner_issues",
                "Retrieve vulnerability issues found by Burp Scanner",
                {"count": 10, "offset": 0},
                requires_target=False
            ),
            "get_active_editor": BurpTool(
                "Get Active Editor", "mcp_burpmcp_get_active_editor_contents",
                "Get contents of currently active editor in Burp",
                {},
                requires_target=False
            ),
            "set_active_editor": BurpTool(
                "Set Active Editor", "mcp_burpmcp_set_active_editor_contents",
                "Set contents of currently active editor in Burp",
                {"text": ""},
                requires_target=False
            ),
            "send_to_repeater": BurpTool(
                "Send to Repeater", "mcp_burpmcp_create_repeater_tab",
                "Create a new Repeater tab with the specified request",
                {
                    "content": "", 
                    "tabName": "", 
                    "targetHostname": "", 
                    "targetPort": 443, 
                    "usesHttps": True
                }
            ),
            "send_to_intruder": BurpTool(
                "Send to Intruder", "mcp_burpmcp_send_to_intruder",
                "Send an HTTP request to Intruder",
                {
                    "content": "", 
                    "tabName": "", 
                    "targetHostname": "", 
                    "targetPort": 443, 
                    "usesHttps": True
                }
            ),
            "send_http1_request": BurpTool(
                "Send HTTP/1.1 Request", "mcp_burpmcp_send_http1_request",
                "Issue an HTTP/1.1 request and return the response",
                {
                    "content": "", 
                    "targetHostname": "", 
                    "targetPort": 443, 
                    "usesHttps": True
                }
            ),
            "send_http2_request": BurpTool(
                "Send HTTP/2 Request", "mcp_burpmcp_send_http2_request",
                "Issue an HTTP/2 request and return the response",
                {
                    "headers": {}, 
                    "pseudoHeaders": {}, 
                    "requestBody": "", 
                    "targetHostname": "", 
                    "targetPort": 443, 
                    "usesHttps": True
                }
            ),
            "base64_encode": BurpTool(
                "Base64 Encode", "mcp_burpmcp_base64_encode",
                "Base64 encode the input string",
                {"content": ""},
                requires_target=False
            ),
            "base64_decode": BurpTool(
                "Base64 Decode", "mcp_burpmcp_base64_decode",
                "Base64 decode the input string",
                {"content": ""},
                requires_target=False
            ),
            "url_encode": BurpTool(
                "URL Encode", "mcp_burpmcp_url_encode",
                "URL encode the input string",
                {"content": ""},
                requires_target=False
            ),
            "url_decode": BurpTool(
                "URL Decode", "mcp_burpmcp_url_decode",
                "URL decode the input string",
                {"content": ""},
                requires_target=False
            ),
            "generate_random_string": BurpTool(
                "Generate Random String", "mcp_burpmcp_generate_random_string",
                "Generate a random string of specified length and character set",
                {"length": 10, "characterSet": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
                requires_target=False
            ),
            "set_proxy_intercept": BurpTool(
                "Set Proxy Intercept", "mcp_burpmcp_set_proxy_intercept_state",
                "Enable or disable Burp Proxy intercept",
                {"intercepting": True},
                requires_target=False
            ),
            "output_project_options": BurpTool(
                "Output Project Options", "mcp_burpmcp_output_project_options",
                "Output current project-level configuration in JSON format",
                {},
                requires_target=False
            ),
            "output_user_options": BurpTool(
                "Output User Options", "mcp_burpmcp_output_user_options",
                "Output current user-level configuration in JSON format",
                {},
                requires_target=False
            ),
            "set_project_options": BurpTool(
                "Set Project Options", "mcp_burpmcp_set_project_options",
                "Set project-level configuration in JSON format",
                {"json": ""},
                requires_target=False
            ),
            "set_user_options": BurpTool(
                "Set User Options", "mcp_burpmcp_set_user_options",
                "Set user-level configuration in JSON format",
                {"json": ""},
                requires_target=False
            ),
            "set_task_engine_state": BurpTool(
                "Set Task Engine State", "mcp_burpmcp_set_task_execution_engine_state",
                "Set the state of Burp's task execution engine (paused or unpaused)",
                {"running": True},
                requires_target=False
            )
        }
        
        self.available_tools = tools
        logger.info(f"Initialized {len(tools)} Burp Suite MCP tools")
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def test_connection(self) -> bool:
        """Test connection to Burp Suite MCP server"""
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            # Get session ID from SSE endpoint
            async with self.session.get(
                self.mcp_url,
                headers={
                    "Accept": "text/event-stream",
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive"
                },
                timeout=10
            ) as response:
                if response.status == 200:
                    # Read the SSE response to get the session endpoint
                    async for line in response.content:
                        line_str = line.decode('utf-8').strip()
                        if line_str.startswith('data: /message?sessionId='):
                            session_path = line_str[6:]  # Remove 'data: '
                            self.session_id = session_path.split('sessionId=')[1]
                            base_url = self.mcp_url.replace('/sse', '')
                            self.message_endpoint = f"{base_url}{session_path}"
                            self.connected = True
                            logger.info(f"Connected to Burp MCP with session: {self.session_id}")
                            return True
                    
                    logger.warning("No session ID found in SSE response")
                    return False
                else:
                    logger.warning(f"MCP server returned status {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to connect to Burp Suite MCP server: {e}")
            self.connected = False
            return False
    
    async def send_mcp_request(self, tool_name: str, parameters: Dict[str, Any], timeout: int = 30, max_retries: int = 3) -> Dict[str, Any]:
        """Send request to Burp Suite via MCP protocol with robust async handling"""
        
        if not self.connected:
            await self.test_connection()
        
        if not self.connected:
            raise ConnectionError("Not connected to Burp Suite MCP server")
        
        tool = self.available_tools.get(tool_name)
        if not tool:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        # Prepare MCP request
        mcp_request = {
            "jsonrpc": "2.0",
            "id": datetime.now().isoformat(),
            "method": "tools/call",
            "params": {
                "name": tool.tool_id,
                "arguments": {**tool.parameters, **parameters}
            }
        }
        
        # Retry logic with exponential backoff
        for attempt in range(max_retries):
            try:
                timeout_obj = aiohttp.ClientTimeout(total=timeout)
                async with self.session.post(
                    self.message_endpoint,
                    json=mcp_request,
                    headers={"Content-Type": "application/json"},
                    timeout=timeout_obj
                ) as response:
                    
                    if response.status == 200:
                        result = await response.json()
                        logger.info(f"Successfully executed {tool_name}")
                        return result
                        
                    elif response.status == 202:
                        # Accepted - async processing, poll for result
                        logger.info(f"Request accepted (202) for {tool_name}, polling for result...")
                        return await self._poll_for_mcp_result(tool_name, mcp_request["id"])
                        
                    else:
                        error_text = await response.text()
                        logger.error(f"MCP request failed: {response.status} - {error_text}")
                        if response.status >= 500 and attempt < max_retries - 1:
                            # Server error, retry
                            await asyncio.sleep(2 ** attempt)
                            continue
                        raise Exception(f"MCP request failed: {response.status}")
                        
            except asyncio.TimeoutError:
                logger.warning(f"MCP request timeout on attempt {attempt + 1}/{max_retries}")
                if attempt == max_retries - 1:
                    raise Exception(f"MCP request timed out after {max_retries} attempts")
                await asyncio.sleep(2 ** attempt)
                
            except Exception as e:
                logger.error(f"Error sending MCP request (attempt {attempt + 1}): {e}")
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(2 ** attempt)
                
    async def _poll_for_mcp_result(self, tool_name: str, request_id: str, max_polls: int = 15, poll_interval: float = 2.0) -> Dict[str, Any]:
        """Poll for async MCP result with timeout"""
        logger.info(f"Polling for result of {tool_name} (ID: {request_id})")
        
        for poll_count in range(max_polls):
            await asyncio.sleep(poll_interval)
            
            try:
                # Check if result is ready (implementation depends on MCP server behavior)
                status_request = {
                    "jsonrpc": "2.0",
                    "id": f"{request_id}_status_{poll_count}",
                    "method": "status/check",
                    "params": {"request_id": request_id}
                }
                
                async with self.session.post(
                    self.message_endpoint,
                    json=status_request,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    
                    if response.status == 200:
                        result = await response.json()
                        if result.get("result", {}).get("status") == "completed":
                            logger.info(f"Async result ready for {tool_name} after {poll_count + 1} polls")
                            return result
                        elif result.get("result", {}).get("status") == "failed":
                            error_msg = result.get("result", {}).get("error", "Unknown error")
                            raise Exception(f"Async MCP request failed: {error_msg}")
                        else:
                            logger.debug(f"Still processing {tool_name}... poll {poll_count + 1}/{max_polls}")
                            continue
                            
                    elif response.status == 404:
                        # Status endpoint not supported, try original request again
                        logger.debug(f"Status check not supported, retrying original request")
                        return await self._retry_original_request(tool_name, request_id)
                        
                    else:
                        logger.warning(f"Status check failed with HTTP {response.status}")
                        
            except Exception as e:
                logger.warning(f"Polling attempt {poll_count + 1} failed: {e}")
                
        # Timeout reached - return partial result
        logger.warning(f"Polling timeout for {tool_name} after {max_polls} attempts")
        return {
            "result": {
                "status": "timeout", 
                "message": f"Async operation timed out after {max_polls * poll_interval}s",
                "tool_name": tool_name,
                "request_id": request_id
            }
        }
        
    async def _retry_original_request(self, tool_name: str, request_id: str) -> Dict[str, Any]:
        """Retry the original request to see if it's ready"""
        tool = self.available_tools.get(tool_name)
        if not tool:
            raise ValueError(f"Unknown tool: {tool_name}")
            
        try:
            async with self.session.get(
                f"{self.message_endpoint}?request_id={request_id}",
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                
                if response.status == 200:
                    content_type = response.headers.get('content-type', '')
                    if 'json' in content_type:
                        return await response.json()
                    else:
                        text_result = await response.text()
                        return {"result": {"content": text_result, "status": "completed"}}
                        
                elif response.status == 202:
                    # Still processing
                    return {
                        "result": {
                            "status": "processing", 
                            "message": "Request still processing"
                        }
                    }
                else:
                    error_text = await response.text()
                    raise Exception(f"Retry failed: {response.status} - {error_text}")
                    
        except Exception as e:
            logger.error(f"Retry request failed: {e}")
            return {
                "result": {
                    "status": "error", 
                    "message": str(e)
                }
            }
    
    # New methods using actual MCP tools
    async def get_proxy_history(self, count: int = 10, offset: int = 0) -> Dict[str, Any]:
        """Get HTTP requests/responses from proxy history"""
        parameters = {"count": count, "offset": offset}
        return await self.send_mcp_request("get_proxy_history", parameters)
    
    async def search_proxy_history(self, regex: str, count: int = 10, offset: int = 0) -> Dict[str, Any]:
        """Search proxy history with regex pattern"""
        parameters = {"regex": regex, "count": count, "offset": offset}
        return await self.send_mcp_request("get_proxy_history_regex", parameters)
    
    async def send_http_request(self, target_hostname: str, target_port: int, content: str, 
                               uses_https: bool = False) -> Dict[str, Any]:
        """Send HTTP/1.1 request and get response"""
        parameters = {
            "targetHostname": target_hostname,
            "targetPort": target_port,
            "usesHttps": uses_https,
            "content": content
        }
        return await self.send_mcp_request("send_http1_request", parameters)
    
    async def get_scanner_issues(self, count: int = 10, offset: int = 0) -> Dict[str, Any]:
        """Get vulnerability findings from scanner"""
        parameters = {"count": count, "offset": offset}
        return await self.send_mcp_request("get_scanner_issues", parameters)
    
    def get_available_tools(self) -> List[str]:
        """Get list of available Burp tools"""
        return list(self.available_tools.keys())
    
    def get_tool_info(self, tool_name: str) -> Optional[BurpTool]:
        """Get information about a specific tool"""
        return self.available_tools.get(tool_name)


# CLI interface for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Burp MCP Client CLI")
    parser.add_argument("--test-connection", action="store_true", help="Test MCP connection")
    parser.add_argument("--scan", help="Scan target URL")
    parser.add_argument("--spider", help="Spider target URL")
    parser.add_argument("--discover", help="Discover endpoints for target URL")
    parser.add_argument("--list-tools", action="store_true", help="List available tools")
    
    args = parser.parse_args()
    
    async def cli_main():
        async with BurpMCPClient() as client:
            if args.test_connection:
                connected = await client.test_connection()
                print(f"Connection: {'✅ Success' if connected else '❌ Failed'}")
            
            elif args.scan:
                result = await client.scan_target(args.scan)
                print(json.dumps(result, indent=2))
            
            elif args.spider:
                result = await client.spider_target(args.spider)
                print(json.dumps(result, indent=2))
            
            elif args.discover:
                endpoints = await client.discover_endpoints(args.discover)
                print(f"Discovered {len(endpoints)} endpoints:")
                for endpoint in endpoints:
                    print(f"  • {endpoint}")
            
            elif args.list_tools:
                tools = client.get_available_tools()
                print(f"Available Burp Suite tools ({len(tools)}):")
                for tool_name in tools:
                    tool_info = client.get_tool_info(tool_name)
                    print(f"  • {tool_info.name}: {tool_info.description}")
    
    asyncio.run(cli_main())
