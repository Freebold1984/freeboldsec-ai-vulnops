"""
Burp Suite MCP Client - Interfaces with Burp Suite Pro via Model Context Protocol
"""

import asyncio
import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime

import aiohttp
from aiohttp_sse_client import client as sse_client

logger = logging.getLogger(__name__)


@dataclass
class BurpTool:
    name: str
    tool_id: str
    description: str
    parameters: Dict[str, Any]
    requires_target: bool = True


class BurpMCPClient:
    """Client for interacting with Burp Suite Pro via MCP server"""
    
    def __init__(self, mcp_url: str = "http://localhost:9876/sse"):
        self.mcp_url = mcp_url
        self.session: Optional[aiohttp.ClientSession] = None
        self.connected = False
        self.available_tools: Dict[str, BurpTool] = {}
        
        # Define the 22 Burp tools available via MCP
        self._initialize_burp_tools()
    
    def _initialize_burp_tools(self):
        """Initialize the 22 available Burp Suite tools"""
        tools = {
            "spider": BurpTool(
                "Spider", "spider", 
                "Crawl target to discover content and functionality",
                {"max_depth": 10, "forms": True, "query_strings": True}
            ),
            "scanner": BurpTool(
                "Scanner", "scanner",
                "Automated vulnerability scanner",
                {"scan_type": "active", "insertion_points": "all"}
            ),
            "intruder": BurpTool(
                "Intruder", "intruder",
                "Automated attack tool for fuzzing",
                {"attack_type": "sniper", "payload_type": "simple_list"}
            ),
            "repeater": BurpTool(
                "Repeater", "repeater",
                "Manual request manipulation and testing",
                {"follow_redirects": False}
            ),
            "sequencer": BurpTool(
                "Sequencer", "sequencer",
                "Analyze randomness of session tokens",
                {"sample_size": 1000}
            ),
            "decoder": BurpTool(
                "Decoder", "decoder",
                "Decode/encode data in various formats",
                {"operation": "auto_detect"},
                requires_target=False
            ),
            "comparer": BurpTool(
                "Comparer", "comparer",
                "Compare two pieces of data",
                {"comparison_type": "words"},
                requires_target=False
            ),
            "extender": BurpTool(
                "Extender", "extender",
                "Manage Burp extensions",
                {},
                requires_target=False
            ),
            "proxy": BurpTool(
                "Proxy", "proxy",
                "Intercept and modify HTTP traffic",
                {"intercept": False}
            ),
            "target": BurpTool(
                "Target", "target",
                "Manage target scope and site map",
                {}
            ),
            "engagement_tools": BurpTool(
                "Engagement Tools", "engagement",
                "Various engagement tools (find comments, scripts, etc.)",
                {"tool": "find_comments"}
            ),
            "content_discovery": BurpTool(
                "Content Discovery", "content_discovery",
                "Discover hidden content and functionality",
                {"wordlist": "common", "extensions": ["php", "asp", "jsp"]}
            ),
            "logger": BurpTool(
                "Logger", "logger",
                "Log HTTP requests and responses",
                {"log_all": True},
                requires_target=False
            ),
            "collaborator": BurpTool(
                "Collaborator", "collaborator",
                "Out-of-band interaction testing",
                {"polling_location": "default"}
            ),
            "clickbandit": BurpTool(
                "Clickbandit", "clickbandit",
                "Generate clickjacking attacks",
                {}
            ),
            "dom_invader": BurpTool(
                "DOM Invader", "dom_invader",
                "Client-side vulnerability detection",
                {}
            ),
            "infiltrator": BurpTool(
                "Infiltrator", "infiltrator",
                "Instrument target applications",
                {}
            ),
            "bambdas": BurpTool(
                "Bambdas", "bambdas",
                "Custom Java expressions for filtering",
                {"expression": ""},
                requires_target=False
            ),
            "hackvertor": BurpTool(
                "Hackvertor", "hackvertor",
                "Data conversion and encoding",
                {"tags": []},
                requires_target=False
            ),
            "turbo_intruder": BurpTool(
                "Turbo Intruder", "turbo_intruder",
                "High-speed content discovery and fuzzing",
                {"threads": 10, "request_engine": "http2"}
            ),
            "param_miner": BurpTool(
                "Param Miner", "param_miner",
                "Identify hidden parameters",
                {"wordlist": "default"}
            ),
            "auth_analyzer": BurpTool(
                "Auth Analyzer", "auth_analyzer",
                "Authentication and authorization testing",
                {"session_handling": "auto"}
            )
        }
        
        self.available_tools = tools
        logger.info(f"Initialized {len(tools)} Burp Suite tools")
    
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
            
            async with self.session.get(f"{self.mcp_url}/health") as response:
                if response.status == 200:
                    self.connected = True
                    logger.info("Successfully connected to Burp Suite MCP server")
                    return True
                else:
                    logger.warning(f"MCP server returned status {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to connect to Burp Suite MCP server: {e}")
            self.connected = False
            return False
    
    async def send_mcp_request(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Send request to Burp Suite via MCP protocol"""
        
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
        
        try:
            async with self.session.post(
                f"{self.mcp_url}/rpc",
                json=mcp_request,
                headers={"Content-Type": "application/json"}
            ) as response:
                
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"Successfully executed {tool_name}")
                    return result
                else:
                    error_text = await response.text()
                    logger.error(f"MCP request failed: {response.status} - {error_text}")
                    raise Exception(f"MCP request failed: {response.status}")
                    
        except Exception as e:
            logger.error(f"Error sending MCP request: {e}")
            raise
    
    async def scan_target(self, target_url: str, scan_type: str = "active") -> Dict[str, Any]:
        """Run Burp Scanner against target"""
        
        parameters = {
            "target_url": target_url,
            "scan_type": scan_type,
            "scope": "in_scope_only"
        }
        
        return await self.send_mcp_request("scanner", parameters)
    
    async def spider_target(self, target_url: str, max_depth: int = 10) -> Dict[str, Any]:
        """Run Burp Spider to crawl target"""
        
        parameters = {
            "target_url": target_url,
            "max_depth": max_depth,
            "forms": True,
            "query_strings": True
        }
        
        return await self.send_mcp_request("spider", parameters)
    
    async def discover_endpoints(self, target_url: str) -> List[str]:
        """Discover endpoints using multiple Burp tools"""
        
        discovered_endpoints = []
        
        try:
            # Use Spider for crawling
            spider_result = await self.spider_target(target_url)
            if spider_result.get("result", {}).get("endpoints"):
                discovered_endpoints.extend(spider_result["result"]["endpoints"])
            
            # Use Content Discovery
            content_discovery_result = await self.send_mcp_request("content_discovery", {
                "target_url": target_url,
                "wordlist": "common"
            })
            
            if content_discovery_result.get("result", {}).get("found_paths"):
                discovered_endpoints.extend(content_discovery_result["result"]["found_paths"])
            
            # Remove duplicates
            unique_endpoints = list(set(discovered_endpoints))
            logger.info(f"Discovered {len(unique_endpoints)} unique endpoints")
            
            return unique_endpoints
            
        except Exception as e:
            logger.error(f"Endpoint discovery failed: {e}")
            return []
    
    async def run_intruder_attack(
        self, 
        target_url: str, 
        payload_positions: List[str],
        payloads: List[str],
        attack_type: str = "sniper"
    ) -> Dict[str, Any]:
        """Run Burp Intruder attack"""
        
        parameters = {
            "target_url": target_url,
            "attack_type": attack_type,
            "payload_positions": payload_positions,
            "payloads": payloads
        }
        
        return await self.send_mcp_request("intruder", parameters)
    
    async def analyze_session_tokens(self, target_url: str, token_name: str) -> Dict[str, Any]:
        """Analyze session token randomness with Sequencer"""
        
        parameters = {
            "target_url": target_url,
            "token_name": token_name,
            "sample_size": 1000
        }
        
        return await self.send_mcp_request("sequencer", parameters)
    
    async def test_collaborator_interactions(self, target_url: str) -> Dict[str, Any]:
        """Test for out-of-band interactions using Collaborator"""
        
        parameters = {
            "target_url": target_url,
            "interaction_types": ["dns", "http", "smtp"]
        }
        
        return await self.send_mcp_request("collaborator", parameters)
    
    async def generate_clickjacking_poc(self, target_url: str) -> Dict[str, Any]:
        """Generate clickjacking proof-of-concept with Clickbandit"""
        
        parameters = {
            "target_url": target_url,
            "frame_busting_checks": True
        }
        
        return await self.send_mcp_request("clickbandit", parameters)
    
    async def mine_hidden_parameters(self, target_url: str) -> Dict[str, Any]:
        """Find hidden parameters using Param Miner"""
        
        parameters = {
            "target_url": target_url,
            "wordlist": "default",
            "check_headers": True,
            "check_cookies": True
        }
        
        return await self.send_mcp_request("param_miner", parameters)
    
    async def get_site_map(self) -> Dict[str, Any]:
        """Get the current site map from Burp"""
        
        return await self.send_mcp_request("target", {"action": "get_site_map"})
    
    async def get_scan_results(self, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Get vulnerability scan results"""
        
        parameters = {}
        if scan_id:
            parameters["scan_id"] = scan_id
        
        return await self.send_mcp_request("scanner", {
            "action": "get_results",
            **parameters
        })
    
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
