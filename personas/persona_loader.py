"""
Persona Loader - Loads specialized security personas for different AI tasks
"""

import os
import logging
import sys
from typing import Dict, Any, Optional

# Handle both module and direct script imports
try:
    # When imported as a module
    from ..utils.logger import setup_logger
except ImportError:
    # When running as a script or directly imported
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from utils.logger import setup_logger

logger = setup_logger("freeboldsec.personas.loader", level=logging.INFO)

# Base directory for persona prompts
PERSONAS_DIR = os.path.dirname(os.path.abspath(__file__))

# Cache loaded personas
_persona_cache: Dict[str, Dict[str, Any]] = {}


class Persona:
    """
    Security persona for specialized AI prompting
    
    Each persona has different expertise and prompting styles for
    various security tasks.
    """
    
    def __init__(self, name: str, prompt_templates: Dict[str, str]):
        """
        Initialize a security persona
        
        Args:
            name: Name of the persona
            prompt_templates: Dictionary of prompt templates for different tasks
        """
        self.name = name
        self.prompt_templates = prompt_templates
    
    def get_prompt_for_request_analysis(self, **kwargs) -> str:
        """Generate a prompt for analyzing HTTP requests"""
        template = self.prompt_templates.get("request_analysis", 
            """
            Analyze this HTTP request for potential security vulnerabilities:
            
            URL: {url}
            Method: {method}
            
            Focus on identifying potential injection points in the parameters:
            {params}
            
            Identify any parameters that could be vulnerable to:
            - SQL Injection
            - XSS (Cross-Site Scripting)
            - Command Injection
            - SSRF (Server-Side Request Forgery)
            - Path Traversal
            - Insecure Deserialization
            
            For each potentially vulnerable parameter, explain why it might be exploitable.
            """
        )
        
        return template.format(**kwargs)
    
    def get_prompt_for_response_analysis(self, **kwargs) -> str:
        """Generate a prompt for analyzing HTTP responses"""
        template = self.prompt_templates.get("response_analysis",
            """
            Analyze this HTTP response for potential security vulnerabilities:
            
            Status Code: {status_code}
            
            Headers:
            {headers}
            
            Body:
            {body}
            
            Look for:
            1. Error messages that might reveal sensitive information
            2. Potential information disclosure
            3. Signs of insecure configurations
            4. Indicators of vulnerable components
            5. Authentication/authorization issues
            
            For each finding, provide the evidence and explain the potential security impact.
            """
        )
        
        return template.format(**kwargs)
        
    def get_prompt_for_targeted_response_analysis(self, **kwargs) -> str:
        """Generate a prompt for analyzing HTTP responses with known injection points"""
        template = self.prompt_templates.get("targeted_response_analysis",
            """
            Analyze this HTTP response for potential security vulnerabilities.
            
            Status Code: {status_code}
            
            Headers:
            {headers}
            
            Body:
            {body}
            
            The following potential injection points were identified in the request:
            {injection_points}
            
            Determine if any of these injection points show signs of exploitation success.
            For each finding, provide the evidence and explain the potential security impact.
            """
        )
        
        return template.format(**kwargs)
    
    def get_prompt_for_error_analysis(self, **kwargs) -> str:
        """Generate a prompt for analyzing error responses"""
        template = self.prompt_templates.get("error_analysis",
            """
            Analyze this HTTP error response for potential security vulnerabilities:
            
            Status Code: {status_code}
            
            Headers:
            {headers}
            
            Error Body:
            {body}
            
            Look specifically for:
            1. Stack traces or error messages that reveal internal implementation details
            2. Database error messages that might indicate SQL injection vulnerabilities
            3. File paths that reveal server directory structure
            4. API keys, credentials, or sensitive configuration information
            5. Version information that could indicate vulnerable components
            
            For each finding, provide the evidence and explain the potential security impact.
            """
        )
        
        return template.format(**kwargs)
    
    def get_prompt_for_issue_validation(self, **kwargs) -> str:
        """Generate a prompt for validating detected security issues"""
        template = self.prompt_templates.get("issue_validation",
            """
            Validate the following security issue detected by Burp Suite:
            
            Issue: {issue_name}
            Severity: {severity}
            Confidence: {confidence}
            
            Issue Detail:
            {issue_detail}
            
            Issue Background:
            {issue_background}
            
            Remediation:
            {remediation}
            
            Determine if this is a valid security issue by:
            1. Analyzing the evidence provided
            2. Checking for signs of false positives
            3. Evaluating the potential security impact
            4. Considering the application context
            
            Provide your reasoning and conclude whether this is a valid security issue.
            """
        )
        
        return template.format(**kwargs)
    
    def get_prompt_for_detailed_vuln_analysis(self, **kwargs) -> str:
        """Generate a prompt for detailed vulnerability analysis"""
        template = self.prompt_templates.get("detailed_vuln_analysis",
            """
            Perform a detailed analysis of this potential {vuln_type} vulnerability:
            
            Evidence:
            {evidence}
            
            Analyze the request and response to determine if this is a confirmed vulnerability.
            
            If confirmed, provide:
            1. A detailed description of the vulnerability
            2. The severity rating (low, medium, high, critical)
            3. Technical background explaining the vulnerability
            4. Recommendations for remediation
            
            Be conservative in your analysis - only confirm clear vulnerabilities.
            """
        )
        
        return template.format(**kwargs)
    
    def get_prompt_for_exploit_generation(self, **kwargs) -> str:
        """Generate a prompt for exploit generation"""
        template = self.prompt_templates.get("exploit_generation",
            """
            Generate a proof-of-concept exploit for the confirmed {vuln_type} vulnerability.
            
            Vulnerability details:
            {issue_data}
            
            Analysis result:
            {analysis_result}
            
            Create a minimal, safe exploit that demonstrates the vulnerability without causing damage.
            
            Include:
            1. Exploit code (preferably in Python using the requests library)
            2. Instructions for running the exploit
            3. Expected results when the exploit succeeds
            4. Any prerequisites for exploitation
            
            The exploit should be minimal and focused on demonstrating the vulnerability.
            """
        )
        
        return template.format(**kwargs)


def load_persona(persona_name: str) -> Persona:
    """
    Load a persona by name
    
    Args:
        persona_name: Name of the persona to load
        
    Returns:
        Persona object
    """
    global _persona_cache
    
    # Check cache first
    if persona_name in _persona_cache:
        logger.debug(f"Loaded persona {persona_name} from cache")
        return _persona_cache[persona_name]
    
    # Get persona templates file path
    persona_file = os.path.join(PERSONAS_DIR, f"{persona_name}.md")
    
    # Default templates
    default_templates = {
        "system": f"You are an expert security professional specialized in {persona_name.replace('_', ' ')}."
    }
    
    # Try to load persona templates from file
    if os.path.exists(persona_file):
        try:
            with open(persona_file, 'r') as f:
                content = f.read()
                
            # Simple parsing: sections are marked with ## and the name
            sections = {}
            current_section = "system"
            current_content = []
            
            for line in content.split('\n'):
                if line.startswith('## '):
                    # Save previous section
                    if current_content:
                        sections[current_section] = '\n'.join(current_content).strip()
                        current_content = []
                    
                    # Start new section
                    current_section = line[3:].strip().lower().replace(' ', '_')
                else:
                    current_content.append(line)
            
            # Save last section
            if current_content:
                sections[current_section] = '\n'.join(current_content).strip()
            
            # At minimum, we need a system prompt
            if "system" not in sections and content:
                sections["system"] = content
            
            logger.info(f"Loaded persona {persona_name} from {persona_file}")
            
            # Create persona object
            persona = Persona(persona_name, sections)
            
            # Cache for future use
            _persona_cache[persona_name] = persona
            
            return persona
            
        except Exception as e:
            logger.warning(f"Failed to load persona {persona_name}: {e}")
    else:
        logger.warning(f"Persona file not found: {persona_file}")
    
    # Fall back to default persona
    logger.info(f"Using default persona for {persona_name}")
    persona = Persona(persona_name, default_templates)
    
    # Cache for future use
    _persona_cache[persona_name] = persona
    
    return persona


def setup_personas() -> None:
    """Initialize all available personas"""
    if not os.path.exists(PERSONAS_DIR):
        logger.warning(f"Personas directory not found: {PERSONAS_DIR}")
        return
        
    for filename in os.listdir(PERSONAS_DIR):
        if filename.endswith(".md"):
            persona_name = filename[:-3]  # Remove .md extension
            load_persona(persona_name)
            
    logger.info(f"Loaded {len(_persona_cache)} security personas")
