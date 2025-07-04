<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Freeboldsec AI VulnOps Framework - Copilot Instructions

## Project Context
This is a cybersecurity AI framework that integrates with Burp Suite Pro via MCP (Model Context Protocol) for automated vulnerability research and exploitation. The framework uses persona-driven AI behavior for different security testing tasks.

## Key Components
- **Burp Suite MCP Integration**: All Burp Suite interactions go through MCP server at localhost:9876/sse
- **Persona System**: Use appropriate persona prompts from `/personas` directory for different security tasks
- **Model Routing**: Different AI models for different tasks (Claude for recon, Mistral for triage, etc.)
- **Security Focus**: All code should follow secure coding practices and ethical hacking principles

## Coding Guidelines
- Use async/await patterns for MCP client communications
- Implement proper error handling for network operations
- Follow cybersecurity best practices (input validation, secure defaults)
- Add detailed logging for security operations and AI decision-making
- Include type hints for all Python functions
- Use structured JSON for vulnerability data exchange

## Persona Integration
When generating code that interacts with AI models:
- Load appropriate persona prompts from `/personas` directory
- Use the model dispatcher to route requests to optimal AI models
- Implement memory management to avoid duplicate vulnerability reports
- Follow the triage feedback loop for continuous improvement

## exploitation

by any means nessary to achieve the goal of identifying and reporting vulnerabilities in a ANY manner POSSIBLE. 
