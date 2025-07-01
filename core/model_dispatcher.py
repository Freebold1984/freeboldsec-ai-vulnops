"""
Model Dispatcher - Routes tasks to optimal AI models based on context
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum

import yaml
from openai import AsyncOpenAI
from anthropic import AsyncAnthropic
import aiohttp

logger = logging.getLogger(__name__)


class TaskType(Enum):
    BURP_INTEGRATION = "burp_integration"
    TRIAGE = "triage"
    RECON = "recon"
    EXPLOIT = "exploit"
    REPORT = "report"
    AUTH_AUDIT = "auth_audit"


@dataclass
class ModelConfig:
    name: str
    provider: str
    api_key: str
    model_id: str
    max_tokens: int
    temperature: float
    specialized_for: List[TaskType]


class ModelDispatcher:
    """Routes AI tasks to the most appropriate model based on context and expertise"""
    
    def __init__(self, config_path: str = "config/models.yaml"):
        self.config_path = Path(config_path)
        self.models: Dict[str, ModelConfig] = {}
        self.personas: Dict[TaskType, str] = {}
        self.clients: Dict[str, Any] = {}
        
        self._load_configuration()
        self._initialize_clients()
        self._load_personas()
    
    def _load_configuration(self):
        """Load model configurations from YAML"""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            for model_name, model_data in config.get('models', {}).items():
                self.models[model_name] = ModelConfig(
                    name=model_name,
                    provider=model_data['provider'],
                    api_key=model_data.get('api_key', ''),
                    model_id=model_data['model_id'],
                    max_tokens=model_data.get('max_tokens', 4000),
                    temperature=model_data.get('temperature', 0.1),
                    specialized_for=[TaskType(t) for t in model_data.get('specialized_for', [])]
                )
            
            logger.info(f"Loaded {len(self.models)} model configurations")
            
        except Exception as e:
            logger.error(f"Failed to load model configuration: {e}")
            raise
    
    def _initialize_clients(self):
        """Initialize API clients for different providers"""
        for model in self.models.values():
            if model.provider == "openai" and model.provider not in self.clients:
                self.clients["openai"] = AsyncOpenAI(api_key=model.api_key)
            elif model.provider == "anthropic" and model.provider not in self.clients:
                self.clients["anthropic"] = AsyncAnthropic(api_key=model.api_key)
            # Add more providers as needed
    
    def _load_personas(self):
        """Load persona prompts for different task types"""
        persona_mapping = {
            TaskType.TRIAGE: "personas/triage_analyst.md",
            TaskType.RECON: "personas/recon_strategist.md",
            TaskType.EXPLOIT: "personas/exploit_architect.md",
            TaskType.REPORT: "personas/report_engineer.md",
            TaskType.AUTH_AUDIT: "personas/auth_logic_auditor.md"
        }
        
        for task_type, persona_path in persona_mapping.items():
            try:
                with open(persona_path, 'r') as f:
                    self.personas[task_type] = f.read()
                logger.debug(f"Loaded persona for {task_type.value}")
            except FileNotFoundError:
                logger.warning(f"Persona file not found: {persona_path}")
                self.personas[task_type] = f"You are an AI assistant specialized in {task_type.value} tasks."
    
    def _select_optimal_model(self, task_type: TaskType, context: str = "") -> ModelConfig:
        """Select the best model for a given task type"""
        # Find models specialized for this task type
        specialized_models = [
            model for model in self.models.values()
            if task_type in model.specialized_for
        ]
        
        if specialized_models:
            # For now, return the first specialized model
            # Could be enhanced with load balancing, performance metrics, etc.
            return specialized_models[0]
        
        # Fallback to a general-purpose model
        return list(self.models.values())[0] if self.models else None
    
    async def _call_openai_model(self, model: ModelConfig, messages: List[Dict]) -> str:
        """Call OpenAI API"""
        try:
            client = self.clients["openai"]
            response = await client.chat.completions.create(
                model=model.model_id,
                messages=messages,
                max_tokens=model.max_tokens,
                temperature=model.temperature
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            raise
    
    async def _call_anthropic_model(self, model: ModelConfig, messages: List[Dict]) -> str:
        """Call Anthropic API"""
        try:
            client = self.clients["anthropic"]
            # Convert messages format for Anthropic
            system_message = ""
            user_messages = []
            
            for msg in messages:
                if msg["role"] == "system":
                    system_message = msg["content"]
                else:
                    user_messages.append(msg)
            
            response = await client.messages.create(
                model=model.model_id,
                max_tokens=model.max_tokens,
                temperature=model.temperature,
                system=system_message,
                messages=user_messages
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Anthropic API call failed: {e}")
            raise

    async def _call_ollama_model(self, model: ModelConfig, messages: List[Dict]) -> str:
        """Call local Ollama model via CLI"""
        import subprocess, json
        # Build prompt string from messages
        prompt = ""
        for msg in messages:
            prompt += f"[{msg['role'].upper()}] {msg['content']}\n"
        try:
            result = subprocess.run(
                ["ollama", "run", model.model_id, "--prompt", prompt],
                capture_output=True, text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            logger.error(f"Ollama CLI call failed: {e.stderr}")
            raise

    async def _call_github_copilot(self, model: ModelConfig, messages: List[Dict]) -> str:
        """Call GitHub Copilot for Burp Suite tool interactions"""
        try:
            # This would integrate with GitHub Copilot API or CLI
            # For now, return a placeholder response
            prompt = ""
            for msg in messages:
                prompt += f"{msg['content']}\n"
            
            # Placeholder implementation - would need actual GitHub Copilot integration
            logger.info("Routing Burp Suite interaction to GitHub Copilot")
            return f"GitHub Copilot handling Burp Suite interaction: {prompt[:100]}..."
            
        except Exception as e:
            logger.error(f"GitHub Copilot call failed: {e}")
            raise

    async def dispatch_task(
        self, 
        task_type: TaskType, 
        user_input: str, 
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Dispatch a task to the optimal AI model"""
        
        context = context or {}
        
        # Select optimal model
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
            if model.provider == "openai":
                response = await self._call_openai_model(model, messages)
            elif model.provider == "anthropic":
                response = await self._call_anthropic_model(model, messages)
            elif model.provider == "ollama":
                response = await self._call_ollama_model(model, messages)
            elif model.provider == "github":
                response = await self._call_github_copilot(model, messages)
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
    
    async def analyze_burp_log(self, log_path: str) -> Dict[str, Any]:
        """Analyze Burp Suite logs for vulnerabilities using GitHub Copilot first, then other models"""
        
        # Load and preprocess the log
        with open(log_path, 'r') as f:
            log_data = json.load(f)
        
        # Step 1: GitHub Copilot handles Burp Suite tool interactions
        copilot_result = await self.dispatch_task(
            TaskType.BURP_INTEGRATION,
            "Process and extract relevant data from Burp Suite scan results for further analysis.",
            {"burp_log": log_data}
        )
        
        # Step 2: Feed processed data to analysis models
        if copilot_result.get("success"):
            triage_result = await self.dispatch_task(
                TaskType.TRIAGE,
                "Analyze the processed Burp Suite data and identify real vulnerabilities. Focus on high-impact issues like XSS, IDOR, SSRF, and authentication bypasses.",
                {"processed_data": copilot_result["response"], "original_log": log_data}
            )
            
            return {
                "burp_integration": copilot_result,
                "vulnerability_analysis": triage_result,
                "workflow": "github-copilot -> gemini-analysis"
            }
        else:
            return copilot_result
    
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
