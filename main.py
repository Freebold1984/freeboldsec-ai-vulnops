

#!/usr/bin/env python3
"""
Freeboldsec AI VulnOps Framework - Main Entry Point
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.model_dispatcher import ModelDispatcher
from core.burp_mcp_client import BurpMCPClient
from core.memory_manager import MemoryManager
from config.settings import load_settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vulnops.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
console = Console()


def print_banner():
    """Display the framework banner"""
    banner = """
    ████████╗██████╗ ███████╗███████╗██████╗  ██████╗ ██╗     ██████╗ ███████╗███████╗ ██████╗
    ██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗██║     ██╔══██╗██╔════╝██╔════╝██╔════╝
    █████╗  ██████╔╝█████╗  █████╗  ██████╔╝██║   ██║██║     ██║  ██║███████╗█████╗  ██║     
    ██╔══╝  ██╔══██╗██╔══╝  ██╔══╝  ██╔══██╗██║   ██║██║     ██║  ██║╚════██║██╔══╝  ██║     
    ██║     ██║  ██║███████╗███████╗██████╔╝╚██████╔╝███████╗██████╔╝███████║███████╗╚██████╗
    ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝
    
    🔐 AI VulnOps Framework - Autonomous Vulnerability Research & Exploitation
    """
    
    console.print(Panel(banner, style="bold red"))


def show_status_table(burp_connected: bool, models_loaded: int):
    """Display system status"""
    table = Table(title="System Status")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details", style="white")
    
    # Burp Suite MCP connection
    burp_status = "✅ Connected" if burp_connected else "❌ Disconnected"
    table.add_row("Burp Suite MCP", burp_status, "localhost:9876/sse")
    
    # Model dispatcher
    model_status = f"✅ {models_loaded} models loaded" if models_loaded > 0 else "❌ No models"
    table.add_row("AI Models", model_status, "Multi-model routing active")
    
    # Memory system
    table.add_row("Memory Manager", "✅ Active", "Triage feedback enabled")
    
    console.print(table)


async def main():
    """Main application entry point"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Freeboldsec AI VulnOps Framework - Automated Vulnerability Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                                  # Full framework mode
  python main.py --demo                           # Demo mode without API keys
  python main.py --analyze processed_traffic.json
        """
    )
    parser.add_argument("--demo", action="store_true", help="Run in demo mode (no API keys required)")
    parser.add_argument("--analyze", help="Analyze processed traffic JSON file")
    
    args = parser.parse_args()
    
    # Handle demo mode
    if args.demo:
        console.print("🎭 Running in DEMO mode - simulated AI analysis", style="yellow")
        import subprocess
        subprocess.run([sys.executable, "demo.py"])
        return
    
    print_banner()
    
    try:
        # Load configuration
        settings = load_settings()
        console.print("📋 Configuration loaded successfully", style="green")
        
        # Initialize components
        console.print("🚀 Initializing framework components...")
        
        # Initialize MCP client for Burp Suite
        burp_client = BurpMCPClient(settings.burp_mcp_url)
        burp_connected = await burp_client.test_connection()
        
        # Initialize model dispatcher
        model_dispatcher = ModelDispatcher(settings.models_config)
        models_loaded = len(model_dispatcher.available_models)
        
        # Initialize memory manager
        memory_manager = MemoryManager(settings.memory_config)
        
        # Show system status
        show_status_table(burp_connected, models_loaded)
        
        if not burp_connected:
            console.print("⚠️  Burp Suite MCP server not available. Some features will be limited.", style="yellow")
        
        console.print("\n🎯 Framework ready for vulnerability operations!", style="bold green")
        console.print("Use the following commands to interact with the framework:")
        console.print("  • Import Burp logs: python -m core.preprocessor --import <burp_log>")
        console.print("  • Run triage: python -m core.model_dispatcher --triage <target>")
        console.print("  • Generate reports: python -m templates.report_generator --format hackerone")
        
    except Exception as e:
        logger.error(f"Failed to initialize framework: {e}")
        console.print(f"❌ Initialization failed: {e}", style="red")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
