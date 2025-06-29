#!/usr/bin/env python3
"""
Burp Suite MCP Server Setup Script
Configures and tests the connection to Burp Suite Professional MCP server
"""

import asyncio
import json
import logging
import sys
from pathlib import Path

import aiohttp
import yaml
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
logger = logging.getLogger(__name__)


class BurpMCPSetup:
    """Setup and configuration for Burp Suite MCP server"""
    
    def __init__(self, host: str = "localhost", port: int = 9876):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}/sse"
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def test_connection(self) -> bool:
        """Test connection to Burp Suite MCP server"""
        try:
            console.print("🔍 Testing connection to Burp Suite MCP server...")
            
            async with self.session.get(f"{self.base_url}/health", timeout=10) as response:
                if response.status == 200:
                    health_data = await response.json()
                    console.print("✅ MCP server connection successful!", style="green")
                    
                    # Display server info
                    info_table = Table(title="MCP Server Information")
                    info_table.add_column("Property", style="cyan")
                    info_table.add_column("Value", style="white")
                    
                    info_table.add_row("Server Status", "✅ Online")
                    info_table.add_row("Host", self.host)
                    info_table.add_row("Port", str(self.port))
                    info_table.add_row("Protocol", "SSE")
                    info_table.add_row("Base URL", self.base_url)
                    
                    if isinstance(health_data, dict):
                        for key, value in health_data.items():
                            info_table.add_row(key.replace('_', ' ').title(), str(value))
                    
                    console.print(info_table)
                    return True
                else:
                    console.print(f"❌ MCP server returned status {response.status}", style="red")
                    return False
                    
        except aiohttp.ClientTimeout:
            console.print("❌ Connection timeout - MCP server may not be running", style="red")
            return False
        except aiohttp.ClientConnectorError:
            console.print(f"❌ Cannot connect to {self.base_url} - check if Burp Suite MCP server is running", style="red")
            return False
        except Exception as e:
            console.print(f"❌ Connection test failed: {e}", style="red")
            return False
    
    async def get_available_tools(self) -> dict:
        """Get list of available Burp tools via MCP"""
        try:
            mcp_request = {
                "jsonrpc": "2.0",
                "id": "setup_tools_list",
                "method": "tools/list",
                "params": {}
            }
            
            async with self.session.post(
                f"{self.base_url}/rpc",
                json=mcp_request,
                headers={"Content-Type": "application/json"}
            ) as response:
                
                if response.status == 200:
                    result = await response.json()
                    if "result" in result:
                        return result["result"]
                    else:
                        return {"error": result.get("error", "Unknown error")}
                else:
                    return {"error": f"HTTP {response.status}"}
                    
        except Exception as e:
            return {"error": str(e)}
    
    def create_mcp_config(self, config_path: str = "config/mcp_settings.yaml"):
        """Create MCP configuration file"""
        try:
            config = {
                "mcp_server": {
                    "host": self.host,
                    "port": self.port,
                    "protocol": "sse",
                    "base_url": self.base_url,
                    "timeout_seconds": 30,
                    "retry_attempts": 3,
                    "retry_delay_seconds": 5,
                    "health_check_endpoint": "/health",
                    "health_check_interval_seconds": 60,
                    "auth": {
                        "type": "none"
                    }
                },
                "protocol_settings": {
                    "jsonrpc_version": "2.0",
                    "max_request_size_mb": 50,
                    "max_response_size_mb": 100,
                    "request_timeout_seconds": 300
                },
                "logging": {
                    "log_mcp_requests": True,
                    "log_mcp_responses": False,
                    "log_connection_events": True
                }
            }
            
            # Ensure config directory exists
            Path(config_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
            
            console.print(f"✅ Created MCP configuration: {config_path}", style="green")
            return True
            
        except Exception as e:
            console.print(f"❌ Failed to create MCP config: {e}", style="red")
            return False
    
    def show_burp_setup_instructions(self):
        """Display instructions for setting up Burp Suite Professional"""
        
        instructions = """
# Burp Suite Professional MCP Server Setup

## Prerequisites
1. Burp Suite Professional (latest version)
2. MCP extension for Burp Suite
3. Python 3.9+ environment

## Setup Steps

### 1. Install Burp Suite MCP Extension
- Open Burp Suite Professional
- Go to Extensions tab
- Click "Add" and select the MCP extension JAR file
- Configure the extension to listen on localhost:9876

### 2. Configure MCP Server
- In Burp Suite, go to MCP extension settings
- Set listen address: localhost
- Set listen port: 9876
- Enable Server-Sent Events (SSE) protocol
- Start the MCP server

### 3. Verify Tools Access
The following Burp tools should be available via MCP:
- Spider (web crawler)
- Scanner (vulnerability scanner)
- Intruder (attack tool)
- Repeater (request manipulation)
- Sequencer (session analysis)
- And 17 additional professional tools

### 4. Test Connection
Run this setup script to verify the connection:
```bash
python setup_burp_mcp.py --test-connection
```

## Troubleshooting

### Connection Refused
- Ensure Burp Suite Professional is running
- Verify MCP extension is loaded and started
- Check firewall settings for port 9876

### Authentication Issues
- MCP server may require API key authentication
- Update config/mcp_settings.yaml with credentials
- Restart the MCP server after configuration changes

### Tool Access Issues
- Verify Burp Suite Professional license is active
- Check that all extensions are properly loaded
- Restart Burp Suite if tools are not responding
        """
        
        panel = Panel(instructions, title="🔧 Burp Suite MCP Setup Instructions", 
                     title_align="left", border_style="blue")
        console.print(panel)


async def main():
    """Main setup function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Burp Suite MCP Server Setup")
    parser.add_argument("--host", default="localhost", help="MCP server host")
    parser.add_argument("--port", type=int, default=9876, help="MCP server port")
    parser.add_argument("--test-connection", action="store_true", help="Test MCP connection")
    parser.add_argument("--list-tools", action="store_true", help="List available tools")
    parser.add_argument("--create-config", action="store_true", help="Create MCP configuration file")
    parser.add_argument("--show-instructions", action="store_true", help="Show setup instructions")
    
    args = parser.parse_args()
    
    # Display banner
    banner = """
    ██████╗ ██╗   ██╗██████╗ ██████╗     ███╗   ███╗ ██████╗██████╗ 
    ██╔══██╗██║   ██║██╔══██╗██╔══██╗    ████╗ ████║██╔════╝██╔══██╗
    ██████╔╝██║   ██║██████╔╝██████╔╝    ██╔████╔██║██║     ██████╔╝
    ██╔══██╗██║   ██║██╔══██╗██╔═══╝     ██║╚██╔╝██║██║     ██╔═══╝ 
    ██████╔╝╚██████╔╝██║  ██║██║         ██║ ╚═╝ ██║╚██████╗██║     
    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝         ╚═╝     ╚═╝ ╚═════╝╚═╝     
    
    🔐 Burp Suite Professional MCP Server Setup
    """
    
    console.print(Panel(banner, style="bold blue"))
    
    if args.show_instructions:
        setup = BurpMCPSetup(args.host, args.port)
        setup.show_burp_setup_instructions()
        return
    
    async with BurpMCPSetup(args.host, args.port) as setup:
        if args.create_config:
            setup.create_mcp_config()
        
        if args.test_connection:
            connected = await setup.test_connection()
            
            if not connected:
                console.print("\n💡 Setup Tips:", style="yellow")
                console.print("1. Ensure Burp Suite Professional is running")
                console.print("2. Verify MCP extension is loaded and started")
                console.print("3. Check that port 9876 is not blocked by firewall")
                console.print("4. Run --show-instructions for detailed setup guide")
                sys.exit(1)
        
        if args.list_tools:
            console.print("🔍 Fetching available Burp tools...")
            tools = await setup.get_available_tools()
            
            if "error" in tools:
                console.print(f"❌ Failed to get tools list: {tools['error']}", style="red")
            else:
                tools_table = Table(title="Available Burp Suite Tools")
                tools_table.add_column("Tool Name", style="cyan")
                tools_table.add_column("Description", style="white")
                tools_table.add_column("Category", style="green")
                
                if "tools" in tools:
                    for tool in tools["tools"]:
                        tools_table.add_row(
                            tool.get("name", "Unknown"),
                            tool.get("description", "No description"),
                            tool.get("category", "General")
                        )
                else:
                    console.print("No tools information returned from MCP server")
                
                console.print(tools_table)
    
    if not any([args.test_connection, args.list_tools, args.create_config, args.show_instructions]):
        # Default action - run full setup
        async with BurpMCPSetup(args.host, args.port) as setup:
            console.print("🚀 Running full MCP setup...\n")
            
            # Create configuration
            setup.create_mcp_config()
            
            # Test connection
            connected = await setup.test_connection()
            
            if connected:
                # List available tools
                console.print("\n🔍 Fetching available tools...")
                tools = await setup.get_available_tools()
                
                if "error" not in tools:
                    console.print(f"✅ Found {len(tools.get('tools', []))} available tools")
                
                console.print("\n🎉 Burp Suite MCP setup completed successfully!", style="bold green")
                console.print("The framework is now ready to use Burp Suite Professional tools.")
            else:
                console.print("\n❌ Setup incomplete - MCP server connection failed", style="red")
                setup.show_burp_setup_instructions()


if __name__ == "__main__":
    asyncio.run(main())
