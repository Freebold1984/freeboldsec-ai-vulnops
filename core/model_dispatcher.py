"""
Model Dispatcher - Routes requests to optimal AI models for vulnerability analysis

Part of the Freeboldsec AI VulnOps Framework
Created by Jason Haddix (BishopFox)
"""

import asyncio
import json
import logging
import os
import time
from typing import Dict, Any, List, Optional, Union, NamedTuple
from enum import Enum
from dataclasses import dataclass

import aiohttp

try:
    import yaml
except ImportError:
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml"])
    import yaml


logger = logging.getLogger(__name__)


class TaskType(Enum):
    """Types of tasks for AI processing"""
    PARAMETER_ANALYSIS = "parameter_analysis"
    RESPONSE_ANALYSIS = "response_analysis"
    ERROR_ANALYSIS = "error_analysis"
    ISSUE_VALIDATION = "issue_validation"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOIT_GENERATION = "exploit_generation"
    REPORT_GENERATION = "report_generation"
    TRIAGE = "triage"
    RECON = "recon"
    EXPLOIT = "exploit"
    REPORT = "report"
    AUTH_AUDIT = "auth_audit"


@dataclass
class ModelConfig:
    """Configuration for an AI model"""
    name: str
    provider: str
    model_id: str
    api_key: str = ""
    max_tokens: int = 4000
    temperature: float = 0.1
    specialized_for: List[TaskType] = None
    
    def __post_init__(self):
        if self.specialized_for is None:
            self.specialized_for = []


class ModelDispatcher:
    """
    Routes AI tasks to the most appropriate model based on context and expertise
    
    Features:
    - Model specialization for different security tasks
    - Automatic fallback to alternative models
    - Request throttling and rate limiting
    - Result caching
    """
    
    def __init__(self, config_path: str = None):
        """Initialize the model dispatcher"""
        self.session: Optional[aiohttp.ClientSession] = None
        self.config_path = config_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config",
            "models.yaml"
        )
        
        # Model configurations
        self.models: Dict[str, ModelConfig] = {}
        
        # Task to model mapping for fallback mode
        self.model_routing = {
            "parameter_analysis": "claude-3.5-sonnet",
            "response_analysis": "claude-3.7-sonnet",
            "error_analysis": "claude-3.7-sonnet",
            "issue_validation": "claude-3.7-sonnet-thought",
            "vulnerability_analysis": "claude-sonnet-4",
            "exploit_generation": "gpt-4o",
            "report_generation": "claude-3.7-sonnet-thought"
        }
        
        # Persona prompts for different task types
        self.personas: Dict[TaskType, str] = {}
        
        # Simple rate limiting
        self.last_request_time: Dict[str, float] = {}
        self.min_request_interval = 0.5  # seconds
        
        # Simple result cache
        self.result_cache: Dict[str, Dict[str, Any]] = {}
        
        # Try to load configuration - gracefully fallback if not available
        try:
            self._load_configuration()
        except Exception as e:
            logger.warning(f"Failed to load model configuration: {e}. Using defaults.")
        
        # Initialize API clients
        self._initialize_clients()
        
        # Load persona prompts
        self._load_personas()
        
        logger.info("ModelDispatcher initialized with AI model routing")
    
    async def _ensure_session(self) -> None:
        """Ensure we have an active aiohttp session"""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
    
    async def route_request(
        self, 
        task_type: str, 
        prompt: str,
        context: Optional[Dict[str, Any]] = None,
        model_override: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Route a request to the appropriate AI model
        
        Args:
            task_type: Type of task to perform
            prompt: The prompt to send to the model
            context: Additional context for the request
            model_override: Override the default model for this task
            
        Returns:
            The model's response as a dictionary
        """
        # Apply rate limiting
        await self._apply_rate_limiting(task_type)
        
        # Check cache first
        cache_key = self._generate_cache_key(task_type, prompt)
        if cache_key in self.result_cache:
            logger.debug(f"Cache hit for {task_type}")
            return self.result_cache[cache_key]
        
        try:
            # Find task enum from string
            task_enum = None
            for tt in TaskType:
                if tt.value == task_type:
                    task_enum = tt
                    break
            
            if task_enum:
                # Try to find a specialized model for this task
                model_config = self._select_optimal_model(task_enum, str(context or ""))
                if model_config:
                    # Prepare messages for the model
                    messages = self._prepare_messages_for_task(task_enum, prompt, context)
                    
                    # Record time for rate limiting
                    self.last_request_time[task_type] = time.time()
                    
                    # Make the actual API call based on provider
                    if model_config.provider == "ollama":
                        response_text = await self._call_ollama_model(model_config, messages)
                        
                        # Try to parse the response as JSON
                        try:
                            result = json.loads(response_text)
                        except json.JSONDecodeError:
                            # If not JSON, wrap in a simple structure
                            result = {"response": response_text}
                    else:
                        # Fall back to mock response for now
                        logger.warning(f"Provider {model_config.provider} not implemented, using mock response")
                        result = self._generate_mock_response(task_type, prompt, context)
                else:
                    # No specialized model found
                    logger.warning(f"No specialized model found for {task_type}, using mock response")
                    result = self._generate_mock_response(task_type, prompt, context)
            else:
                # Task type not found in enum
                logger.warning(f"Task type {task_type} not found in TaskType enum, using mock response")
                result = self._generate_mock_response(task_type, prompt, context)
            
            # Cache the result
            self.result_cache[cache_key] = result
            
            return result
            
        except Exception as e:
            logger.error(f"Error routing request to AI model: {str(e)}")
            return {"error": str(e), "task_type": task_type}
    
    async def _apply_rate_limiting(self, task_type: str) -> None:
        """Apply rate limiting to avoid overwhelming the AI services"""
        if task_type in self.last_request_time:
            elapsed = time.time() - self.last_request_time[task_type]
            if elapsed < self.min_request_interval:
                delay = self.min_request_interval - elapsed
                logger.debug(f"Rate limiting applied, waiting {delay:.2f}s")
                await asyncio.sleep(delay)
    
    def _generate_cache_key(self, task_type: str, prompt: str) -> str:
        """Generate a cache key for a request"""
        # In a real implementation, you might want to use a hash function
        return f"{task_type}:{prompt[:50]}"
    
    def _generate_mock_response(
        self, 
        task_type: str, 
        prompt: str,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate a mock response for testing
        
        In a real implementation, this would be replaced with actual API calls
        """
        if task_type == "parameter_analysis":
            return {
                "potential_injection_points": [
                    {"parameter": "id", "risk": "high", "reason": "Integer parameter might be vulnerable to SQL injection"},
                    {"parameter": "search", "risk": "medium", "reason": "Search parameter might be vulnerable to XSS"}
                ]
            }
        elif task_type == "response_analysis" or task_type == "error_analysis":
            return {
                "vulnerability_indicators": [
                    {
                        "type": "sql_injection",
                        "confidence": 0.85,
                        "evidence": "SQL error message in response"
                    }
                ]
            }
        elif task_type == "issue_validation":
            return {
                "is_valid": True,
                "confidence": 0.92,
                "reasoning": "The issue shows clear evidence of vulnerability"
            }
        elif task_type == "vulnerability_analysis":
            return {
                "is_confirmed": True,
                "name": "SQL Injection",
                "severity": "high",
                "description": "SQL injection vulnerability in id parameter",
                "background": "SQL injection allows attackers to execute arbitrary SQL commands",
                "remediation": "Use parameterized queries to prevent SQL injection"
            }
        elif task_type == "exploit_generation":
            return {
                "exploit_code": "python -c 'import requests; print(requests.get(\"http://example.com/vuln?id=1%27%20OR%201=1--\").text)'",
                "exploit_type": "poc",
                "generation_info": {
                    "timestamp": time.time(),
                    "model": "gpt-4o"
                }
            }
        elif task_type == "report_generation":
            return {
                "report": "# Vulnerability Report\n\n## SQL Injection in ID Parameter\n\n..."
            }
        else:
            return {"message": "Task type not recognized"}
        self._load_personas()
    
    def _load_configuration(self):
        """Load model configurations from YAML"""
        # Create config directory if it doesn't exist
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        
        # Check if config file exists
        if not os.path.exists(self.config_path):
            logger.warning(f"Config file not found at {self.config_path}, creating default")
            self._create_default_config()
        
        # Load config from file
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if not config or 'models' not in config:
                logger.warning("Invalid config file, using defaults")
                return
                
            # Clear existing models
            self.models.clear()
            
            # Load models from config
            for model_name, model_data in config.get('models', {}).items():
                specialized_for = []
                for task_name in model_data.get('specialized_for', []):
                    try:
                        specialized_for.append(TaskType(task_name))
                    except ValueError:
                        logger.warning(f"Unknown task type: {task_name}")
                
                self.models[model_name] = ModelConfig(
                    name=model_name,
                    provider=model_data['provider'],
                    api_key=model_data.get('api_key', ''),
                    model_id=model_data['model_id'],
                    max_tokens=model_data.get('max_tokens', 4000),
                    temperature=model_data.get('temperature', 0.1),
                    specialized_for=specialized_for
                )
            
            logger.info(f"Loaded {len(self.models)} model configurations")
            
        except Exception as e:
            logger.error(f"Failed to load model configuration: {e}")
            logger.warning("Using default model configuration")
            self._create_default_config()
    
    def _create_default_config(self):
        """Create a default configuration file"""
        default_config = {
            'models': {
                'claude-sonnet-4': {
                    'provider': 'anthropic',
                    'model_id': 'claude-3-sonnet-20240229',
                    'max_tokens': 4096,
                    'temperature': 0.1,
                    'specialized_for': [
                        'vulnerability_analysis',
                        'report_generation'
                    ]
                },
                'gpt-4o': {
                    'provider': 'openai',
                    'model_id': 'gpt-4o',
                    'max_tokens': 4096,
                    'temperature': 0.2,
                    'specialized_for': [
                        'exploit_generation',
                        'parameter_analysis'
                    ]
                },
                'mistral-large': {
                    'provider': 'ollama',
                    'model_id': 'mistral:latest',
                    'max_tokens': 2048,
                    'temperature': 0.1,
                    'specialized_for': [
                        'error_analysis',
                        'issue_validation'
                    ]
                }
            }
        }
        
        # Save default config
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            
            # Load the models we just created
            for model_name, model_data in default_config['models'].items():
                specialized_for = []
                for task_name in model_data.get('specialized_for', []):
                    try:
                        specialized_for.append(TaskType(task_name))
                    except ValueError:
                        pass
                
                self.models[model_name] = ModelConfig(
                    name=model_name,
                    provider=model_data['provider'],
                    api_key='',
                    model_id=model_data['model_id'],
                    max_tokens=model_data.get('max_tokens', 4000),
                    temperature=model_data.get('temperature', 0.1),
                    specialized_for=specialized_for
                )
            
            logger.info(f"Created default config with {len(self.models)} models")
        except Exception as e:
            logger.error(f"Failed to create default config: {e}")
            # If we can't create the config file, add some basic models in memory
            self.models = {
                'default-model': ModelConfig(
                    name='default-model',
                    provider='ollama',
                    model_id='mistral:latest',
                    max_tokens=2048,
                    temperature=0.1,
                    specialized_for=[]
                )
            }
    
    def _initialize_clients(self):
        """Initialize API clients for different providers"""
        # All models are Ollama, no special clients needed.
        pass


    
    def _load_personas(self):
        """Load persona prompts for different task types"""
        persona_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "personas"
        )
        
        # Create personas directory if it doesn't exist
        os.makedirs(persona_dir, exist_ok=True)
        
        # Mapping of task types to persona file names
        persona_mapping = {
            TaskType.TRIAGE: "triage_analyst.md",
            TaskType.RECON: "recon_strategist.md",
            TaskType.EXPLOIT: "exploit_architect.md",
            TaskType.REPORT: "report_engineer.md",
            TaskType.AUTH_AUDIT: "auth_logic_auditor.md",
            TaskType.PARAMETER_ANALYSIS: "parameter_analyst.md",
            TaskType.RESPONSE_ANALYSIS: "response_analyst.md",
            TaskType.ERROR_ANALYSIS: "error_analyst.md",
            TaskType.ISSUE_VALIDATION: "issue_validator.md",
            TaskType.VULNERABILITY_ANALYSIS: "vulnerability_analyst.md",
            TaskType.EXPLOIT_GENERATION: "exploit_generator.md",
            TaskType.REPORT_GENERATION: "report_generator.md"
        }
        
        # Load each persona from file
        for task_type, filename in persona_mapping.items():
            file_path = os.path.join(persona_dir, filename)
            
            # Check if file exists
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        self.personas[task_type] = f.read()
                    logger.debug(f"Loaded persona for {task_type.value} from {file_path}")
                except Exception as e:
                    logger.warning(f"Failed to load persona from {file_path}: {e}")
                    self._create_default_persona(task_type, file_path)
            else:
                # Create default persona
                self._create_default_persona(task_type, file_path)
    
    def _create_default_persona(self, task_type: TaskType, file_path: str):
        """Create a default persona prompt for a task type"""
        
        # Basic persona templates
        default_personas = {
            TaskType.TRIAGE: """# Triage Analyst Persona

You are an expert security triage analyst specializing in vulnerability assessment and prioritization.

## Expertise
- Vulnerability assessment and severity rating
- Identifying false positives vs. true vulnerabilities
- Quick classification of security issues
- Risk assessment and business impact analysis

## Approach
- Be thorough but efficient in your analysis
- Focus on determining if reported issues are real vulnerabilities
- Assess potential impact and exploitation difficulty
- Provide clear prioritization guidance
- Use specific technical evidence to support your conclusions

## Communication Style
- Clear, direct, and factual
- Technical but precise
- Prioritize clarity and actionability
- Include severity ratings and confidence levels

When analyzing potential security issues:
1. Evaluate the technical evidence
2. Determine if it's a true vulnerability or false positive
3. Assess the severity (Critical, High, Medium, Low)
4. Estimate exploitation difficulty
5. Recommend prioritization
""",
            TaskType.RECON: """# Reconnaissance Strategist Persona

You are an elite reconnaissance specialist who identifies attack vectors and security weaknesses in target systems.

## Expertise
- Passive and active reconnaissance techniques
- Attack surface mapping and analysis
- Identifying potential entry points
- Subdomain enumeration and asset discovery
- Content discovery and hidden endpoint identification

## Approach
- Be thorough and methodical in your analysis
- Start with passive techniques before suggesting active ones
- Look for non-obvious attack vectors
- Identify the most promising paths for vulnerability discovery
- Prioritize based on potential security impact

## Communication Style
- Structured and analytical
- Focus on specific findings and their security implications
- Highlight high-value targets and why they matter
- Provide clear recommendations for further testing

When conducting reconnaissance:
1. Map the complete attack surface
2. Identify technology stack and potential weaknesses
3. Discover non-obvious entry points and assets
4. Prioritize targets based on vulnerability potential
5. Recommend specific vectors for further testing
""",
            TaskType.EXPLOIT: """# Exploit Architect Persona

You are an expert exploit developer specializing in creating proof-of-concept exploits for security vulnerabilities.

## Expertise
- Exploit development and weaponization
- Understanding vulnerability mechanics
- Bypassing security controls
- Creating reliable proof-of-concept code
- Exploit chain construction

## Approach
- Focus on creating working, reliable exploits
- Start with minimal viable exploits
- Consider defense bypasses when necessary
- Create exploits that demonstrate real impact
- Document each step clearly

## Communication Style
- Technical and precise
- Step-by-step explanations
- Code-focused with clear comments
- Include validation methods

When developing exploits:
1. Analyze the vulnerability mechanics in detail
2. Create a minimal proof-of-concept
3. Ensure reliability and repeatability
4. Document exact steps to reproduce
5. Explain the impact clearly
""",
            TaskType.REPORT: """# Report Engineer Persona

You are an expert security report writer who specializes in creating clear, impactful vulnerability reports.

## Expertise
- Technical writing for security audiences
- Vulnerability description and explanation
- Impact assessment and business risk communication
- Remediation guidance
- Creating reproducible proof-of-concept steps

## Approach
- Write clearly and technically without unnecessary jargon
- Focus on communicating impact to both technical and business stakeholders
- Provide concrete evidence and reproduction steps
- Include actionable remediation guidance
- Structure reports for maximum clarity

## Communication Style
- Professional and precise
- Well-structured with clear sections
- Technical but accessible
- Evidence-based

When writing security reports:
1. Provide a clear executive summary
2. Include detailed technical description
3. Document exact reproduction steps
4. Explain the real-world impact
5. Provide specific remediation guidance
"""
        }
        
        # Create default content for other task types if not specifically defined
        default_content = default_personas.get(
            task_type, 
            f"""# {task_type.value.replace('_', ' ').title()} Persona

You are an expert security professional specializing in {task_type.value.replace('_', ' ')}.

## Expertise
- Deep technical knowledge in {task_type.value.replace('_', ' ')}
- Advanced security testing methodologies
- Identifying and analyzing security weaknesses
- Security best practices and mitigations

## Approach
- Be thorough and methodical in your analysis
- Focus on accuracy and technical precision
- Look for non-obvious security issues
- Provide evidence-based conclusions

## Communication Style
- Clear, technical, and precise
- Evidence-based assessments
- Structured analysis
- Action-oriented recommendations

When performing {task_type.value.replace('_', ' ')} tasks:
1. Analyze the technical evidence carefully
2. Identify potential security weaknesses
3. Assess severity and exploitability
4. Provide clear and actionable recommendations
"""
        )
        
        # Save to file
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w') as f:
                f.write(default_content)
            
            # Store in memory
            self.personas[task_type] = default_content
            
            logger.info(f"Created default persona for {task_type.value} at {file_path}")
        except Exception as e:
            logger.warning(f"Failed to create default persona file for {task_type.value}: {e}")
            # Still store in memory even if file creation fails
            self.personas[task_type] = default_content
    
    def _select_optimal_model(self, task_type: TaskType, context: str = "") -> Optional[ModelConfig]:
        """Select the best model for a given task type"""
        
        # First, look for models specialized for this task
        specialized_models = []
        for model in self.models.values():
            if task_type in model.specialized_for:
                specialized_models.append(model)
        
        if specialized_models:
            # For now, just return the first specialized model
            # In a more advanced implementation, could select based on context
            return specialized_models[0]
        
        # No specialized model found, return a default one if available
        if self.models:
            return next(iter(self.models.values()))
        
        # No models available
        return None


    async def _call_ollama_model(self, model: ModelConfig, messages: List[Dict]) -> str:
        """Call local Ollama model via CLI with proper format"""
        import subprocess, json, tempfile, sys
        
        # Build prompt string from messages
        prompt = ""
        for msg in messages:
            role = msg['role'].upper()
            content = msg['content']
            if role == "SYSTEM":
                prompt += f"System: {content}\n\n"
            elif role == "USER":
                prompt += f"User: {content}\n\n"
            else:
                prompt += f"{role}: {content}\n\n"
        
        prompt += "Assistant: "
        
        try:
            # Create a temporary file for the prompt
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp:
                tmp_path = tmp.name
                tmp.write(prompt)
            
            # Use cat to pipe the prompt to ollama
            cmd = f"cat {tmp_path} | ollama run {model.model_id}"
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=120)  # 2 minute timeout
            
            # Clean up temporary file
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            
            if process.returncode != 0:
                logger.error(f"Ollama CLI failed: {stderr}")
                # Return a fallback response for development
                return json.dumps({
                    "has_potential_vulns": False,
                    "risk_level": "LOW",
                    "confidence_score": 0.1,
                    "summary": "Ollama analysis unavailable - using pattern matching results",
                    "bug_bounty_potential": "LOW"
                })
            
            return stdout.strip()
            
        except subprocess.TimeoutExpired:
            process.kill()
            logger.error("Ollama call timed out")
            return json.dumps({
                "has_potential_vulns": False,
                "risk_level": "LOW", 
                "summary": "Analysis timed out"
            })
        except Exception as e:
            logger.error(f"Ollama CLI call failed: {e}")
            # Return fallback response
            return json.dumps({
                "has_potential_vulns": False,
                "risk_level": "LOW",
                "confidence_score": 0.1,
                "summary": "AI analysis unavailable - check pattern matching results above",
                "bug_bounty_potential": "NONE"
            })



    async def dispatch_task(

        self, 
        task_type: TaskType, 
        user_input: str, 
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Dispatch a task to the optimal AI model"""
        
        context = context or {}

        model = self._select_optimal_model(task_type, str(context))
        if not model:
            raise ValueError("No suitable model available")
        
        # Prepare messages
        persona_prompt = self.personas.get(task_type, "")
        
        messages = [
            {"role": "system", "content": persona_prompt},
            {"role": "user", "content": f"Context: {json.dumps(context, indent=2)}\n\nTask: {user_input}"}
        ]
        
        # Call appropriate API
        try:
            if model.provider == "ollama":
                response = await self._call_ollama_model(model, messages)
            else:
                raise ValueError(f"Unsupported provider: {model.provider}")

            
            return {
                "task_type": task_type.value,
                "model_used": model.name,
                "response": response,
                "context": context,
                "success": True
            }
            
        except Exception as e:
            logger.error(f"Task dispatch failed: {e}")
            return {
                "task_type": task_type.value,
                "model_used": model.name,
                "error": str(e),
                "success": False
            }

    
    async def generate_recon_strategy(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate reconnaissance strategy for a target"""
        
        return await self.dispatch_task(
            TaskType.RECON,
            "Review the target information and suggest optimal reconnaissance strategies. Identify high-value endpoints and attack vectors.",
            target_info
        )
    
    async def create_exploit_poc(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create proof-of-concept exploit code"""
        
        return await self.dispatch_task(
            TaskType.EXPLOIT,
            "Create a detailed proof-of-concept exploit for the identified vulnerability. Include step-by-step instructions and working code.",
            vulnerability_data
        )
    
    async def analyze_burp_log(self, log_path: str) -> Dict[str, Any]:
        """Analyze Burp Suite logs for vulnerabilities"""
        
        # Load and preprocess the log
        with open(log_path, 'r') as f:
            log_data = json.load(f)
        
        triage_result = await self.dispatch_task(
            TaskType.TRIAGE,
            "Analyze the processed Burp Suite data and identify real vulnerabilities. Focus on high-impact issues like XSS, IDOR, SSRF, and authentication bypasses.",
            {"log_data": log_data}
        )
        
        return {
            "vulnerability_analysis": triage_result,
        }

    
    @property
    def available_models(self) -> List[str]:
        """Return list of available model names"""
        return list(self.models.keys())


# CLI interface for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Model Dispatcher CLI")
    parser.add_argument("--triage", help="Analyze Burp log file")
    parser.add_argument("--recon", help="Generate recon strategy (JSON file)")
    parser.add_argument("--exploit", help="Create exploit PoC (JSON file)")
    
    args = parser.parse_args()
    
    async def cli_main():
        dispatcher = ModelDispatcher()
        
        if args.triage:
            result = await dispatcher.analyze_burp_log(args.triage)
            print(json.dumps(result, indent=2))
        elif args.recon:
            with open(args.recon, 'r') as f:
                target_data = json.load(f)
            result = await dispatcher.generate_recon_strategy(target_data)
            print(json.dumps(result, indent=2))
        elif args.exploit:
            with open(args.exploit, 'r') as f:
                vuln_data = json.load(f)
            result = await dispatcher.create_exploit_poc(vuln_data)
            print(json.dumps(result, indent=2))
    
    asyncio.run(cli_main())
