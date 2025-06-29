"""
Settings Configuration Loader
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FrameworkSettings:
    """Main framework settings"""
    # Core settings
    mode: str = "production"
    debug_enabled: bool = False
    data_directory: str = "data/"
    logs_directory: str = "logs/"
    
    # Burp integration
    burp_mcp_url: str = "http://localhost:9876/sse"
    auto_connect: bool = True
    
    # Model configuration
    models_config: str = "config/models.yaml"
    default_triage_model: str = "claude-3-sonnet"
    
    # Memory management
    memory_config: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.memory_config is None:
            self.memory_config = {
                "retention_days": 90,
                "similarity_threshold": 0.85
            }


def load_settings(config_path: str = "config/settings.yaml") -> FrameworkSettings:
    """Load framework settings from YAML file"""
    
    config_file = Path(config_path)
    
    # Default settings
    settings_dict = {
        "framework": {
            "mode": "production",
            "debug_enabled": False
        },
        "core": {
            "data_directory": "data/",
            "logs_directory": "logs/"
        },
        "burp_integration": {
            "mcp_config_file": "config/mcp_settings.yaml",
            "auto_connect": True
        },
        "ai_models": {
            "config_file": "config/models.yaml",
            "default_triage_model": "claude-3-sonnet"
        },
        "memory": {
            "retention_days": 90,
            "similarity_threshold": 0.85
        }
    }
    
    # Load from file if it exists
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                file_config = yaml.safe_load(f)
                # Merge with defaults
                settings_dict.update(file_config)
                logger.info(f"Loaded settings from {config_path}")
        except Exception as e:
            logger.warning(f"Failed to load settings file: {e}, using defaults")
    else:
        logger.warning(f"Settings file not found: {config_path}, using defaults")
    
    # Extract MCP URL from separate config if needed
    burp_mcp_url = "http://localhost:9876/sse"
    mcp_config_file = settings_dict.get("burp_integration", {}).get("mcp_config_file", "config/mcp_settings.yaml")
    
    if Path(mcp_config_file).exists():
        try:
            with open(mcp_config_file, 'r') as f:
                mcp_config = yaml.safe_load(f)
                mcp_server = mcp_config.get("mcp_server", {})
                host = mcp_server.get("host", "localhost")
                port = mcp_server.get("port", 9876)
                protocol = mcp_server.get("protocol", "sse")
                burp_mcp_url = f"http://{host}:{port}/{protocol}"
        except Exception as e:
            logger.warning(f"Failed to load MCP settings: {e}")
    
    # Create settings object
    return FrameworkSettings(
        mode=settings_dict.get("framework", {}).get("mode", "production"),
        debug_enabled=settings_dict.get("framework", {}).get("debug_enabled", False),
        data_directory=settings_dict.get("core", {}).get("data_directory", "data/"),
        logs_directory=settings_dict.get("core", {}).get("logs_directory", "logs/"),
        burp_mcp_url=burp_mcp_url,
        auto_connect=settings_dict.get("burp_integration", {}).get("auto_connect", True),
        models_config=settings_dict.get("ai_models", {}).get("config_file", "config/models.yaml"),
        default_triage_model=settings_dict.get("ai_models", {}).get("default_triage_model", "claude-3-sonnet"),
        memory_config=settings_dict.get("memory", {"retention_days": 90, "similarity_threshold": 0.85})
    )
