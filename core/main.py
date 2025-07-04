"""
Freeboldsec AI VulnOps Framework - Main Entry Point

Author: Jason Haddix
Framework: The Bug Hunter's Methodology (TBHM) - AI Edition
Version: 2.5.0
"""

import asyncio
import logging
import os
import signal
import sys
import argparse
import yaml
from typing import Dict, Any

# Handle imports for both package and direct script usage
if __name__ == "__main__":
    # Running as a script - adjust path and use absolute imports
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.burp_mcp_client import BurpMCPClient
    from core.memory_manager import MemoryManager
    from core.model_dispatcher import ModelDispatcher
    from exploits.exploit_generator import ExploitGenerator
    from reporting.vuln_reporter import VulnReporter
    from utils.logger import setup_logger
else:
    # Running as a module - use relative imports
    from .burp_mcp_client import BurpMCPClient
    from .memory_manager import MemoryManager
    from .model_dispatcher import ModelDispatcher
    from ..exploits.exploit_generator import ExploitGenerator
    from ..reporting.vuln_reporter import VulnReporter
    from ..utils.logger import setup_logger

# Set up the main logger
logger = setup_logger("freeboldsec.main", level=logging.INFO)

# Global state for graceful shutdown
running = True


def load_config() -> Dict[str, Any]:
    """Load configuration from config file"""
    config_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config",
        "config.yaml"
    )
    
    if not os.path.exists(config_path):
        logger.warning(f"Config file not found at {config_path}, using defaults")
        return {}
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        if not config:
            config = {}
            
        logger.info(f"Loaded configuration from {config_path}")
        return config
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return {}


def signal_handler(sig, frame):
    """Handle Ctrl+C and other termination signals"""
    global running
    logger.info("Shutdown signal received, cleaning up...")
    running = False


async def run_framework(config: Dict[str, Any]):
    """Run the Freeboldsec AI VulnOps Framework"""
    
    # Get MCP configuration
    mcp_config = config.get("mcp", {})
    mcp_url = mcp_config.get("url", "http://127.0.0.1:9876/sse")
    mcp_headers = mcp_config.get("headers", {})
    
    # Get logging configuration
    logging_config = config.get("logging", {})
    log_level_str = logging_config.get("level", "info").upper()
    log_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    log_level = log_levels.get(log_level_str, logging.INFO)
    
    # Get security configuration
    security_config = config.get("security", {})
    enable_auto_exploit = security_config.get("enableAutoExploit", True)
    vulnerability_confidence_threshold = security_config.get("vulnerabilityConfidenceThreshold", 0.65)
    
    # Get performance configuration
    performance_config = config.get("performance", {})
    parallel_threads = performance_config.get("parallelThreads", 8)
    context_window_size = performance_config.get("contextWindowSize", 50)
    
    # Initialize components
    logger.info("Initializing Freeboldsec AI VulnOps Framework components...")
    
    memory_manager = MemoryManager(
        max_items=context_window_size,
        cleanup_interval=60
    )
    
    model_dispatcher = ModelDispatcher()
    
    exploit_generator = ExploitGenerator(
        enable_validation=enable_auto_exploit
    )
    
    vuln_reporter = VulnReporter(
        report_format="markdown",
        include_metadata=True,
        include_raw_data=True,
        include_exploit_code=True
    )
    
    # Initialize the Burp MCP client
    mcp_client = BurpMCPClient(
        url=mcp_url,
        headers=mcp_headers,
        memory_manager=memory_manager,
        model_dispatcher=model_dispatcher,
        exploit_generator=exploit_generator,
        vuln_reporter=vuln_reporter,
        vulnerability_confidence_threshold=vulnerability_confidence_threshold,
        enable_auto_exploit=enable_auto_exploit
    )
    
    try:
        # Connect to the Burp MCP server
        logger.info(f"Connecting to Burp MCP at {mcp_url}...")
        
        # Start the MCP client in a task
        mcp_task = asyncio.create_task(mcp_client.connect())
        
        # Wait for the framework to be stopped
        while running:
            await asyncio.sleep(1)
            
        # Cancel the MCP client task
        mcp_task.cancel()
        
    except asyncio.CancelledError:
        logger.info("Framework execution cancelled")
    except Exception as e:
        logger.error(f"Framework execution failed: {e}")
    finally:
        # Clean up
        logger.info("Shutting down Freeboldsec AI VulnOps Framework...")
        
        # Close the MCP client
        await mcp_client.close()


def main():
    """Main entry point for the framework"""
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Freeboldsec AI VulnOps Framework")
    parser.add_argument(
        "--config", 
        help="Path to configuration file",
        default=os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config",
            "config.yaml"
        )
    )
    parser.add_argument(
        "--log-level",
        help="Logging level (debug, info, warning, error, critical)",
        default="info"
    )
    
    args = parser.parse_args()
    
    # Set up logging
    log_level_str = args.log_level.upper()
    log_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    log_level = log_levels.get(log_level_str, logging.INFO)
    
    # Configure the root logger
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Load configuration
    config = load_config()
    
    # Print banner
    print("\n" + "=" * 80)
    print("🛡️  Freeboldsec AI VulnOps Framework v2.5.0")
    print("🔍  The Bug Hunter's Methodology (TBHM) - AI Edition")
    print("🧠  Created by Jason Haddix")
    print("=" * 80 + "\n")
    
    # Run the framework
    try:
        asyncio.run(run_framework(config))
    except KeyboardInterrupt:
        logger.info("Framework stopped by user")
    except Exception as e:
        logger.error(f"Framework execution failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    # When running directly as a script (not as a module)
    print("\n" + "=" * 80)
    print("🛡️  Freeboldsec AI VulnOps Framework v2.5.0")
    print("🔍  The Bug Hunter's Methodology (TBHM) - AI Edition")
    print("🧠  Created by Jason Haddix")
    print("=" * 80)
    print("\n⚠️  NOTE: This script is designed to be run as a module.")
    print("For best results, use one of the following methods:")
    print("1. Use the run_freeboldsec_vulnops.sh script")
    print("2. Run with: python -m core.main")
    print("3. Run with: PYTHONPATH=\"$(pwd)\" python -m core.main\n")
    
    # Still run the script for convenience
    print("🚀 Continuing with direct script execution...\n")
    sys.exit(main())
