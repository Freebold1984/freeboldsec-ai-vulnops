# 🔐 Freeboldsec AI VulnOps Framework

> A modular, model-agnostic AI framework for vulnerability research, exploitation triage, and autonomous recon — built on GitHub Copilot, Burp Suite Pro, VS Code, and Azure AI Toolkit Extension for VS Code.

---

## 🚀 Overview

This project transforms Copilot into an operational AI red team agent with **automated access to 22 Burp tools**, integrated multi-model LLM orchestration (local + cloud), and a custom persona-driven architecture for high-confidence vulnerability detection and reporting.

---

## 🧠 System Components

| Component         | Purpose |
|------------------|---------|
| **Burp Suite Pro** | Core traffic interceptor and attack tool interface via MCP server (localhost:9876/sse) |
| **VS Code**        | Dev + research environment, Copilot host with MCP integration |
| **GitHub Copilot (customized)** | Executes Burp tools on-demand with human-approved gating through MCP protocol |
| **LLM Model Router** | Routes tasks to DeepSeek, Claude, GPT-4, Mistral, WizardCoder, etc. |
| **Azure AI Toolkit Extension** | VS Code extension for AI prompt tuning, agent creation, and multi-model flows |
| **Persona Prompt Library** | Task-specific context files to control model behavior |
| **Custom Preprocessor** | Compresses Burp logs and HTTP traffic into LLM-friendly JSON summaries |
| **Triage Feedback Memory** | Tracks previous model outputs to avoid duplication and false positives |

---

## 🧩 Persona Modules (`/personas`)

| File | Description |
|------|-------------|
| `triage_analyst.md` | Filters Burp logs, flags real vulns (XSS, IDOR, SSRF, etc.) with evidence-based logic |
| `recon_strategist.md` | Reviews JS, Swagger, and endpoint lists to suggest fuzzable targets |
| `exploit_architect.md` | Turns analyzed flaws into full PoCs and post-exploitation steps |
| `report_engineer.md` | Converts findings into Markdown reports for HackerOne/GitHub |
| `auth_logic_auditor.md` | Detects role confusion, logic flaws, and privilege escalation chains |

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.9+
- Burp Suite Professional with MCP server enabled
- VS Code with GitHub Copilot and MCP support
- Azure AI Toolkit Extension for VS Code
- Burp Suite MCP server running on localhost:9876/sse

### Quick Start

```bash
# Clone and setup
git clone <repo-url>
cd freeboldsec-ai-vulnops
pip install -r requirements.txt

# Configure Burp Suite MCP server
python setup_burp_mcp.py --host localhost --port 9876

# Launch framework
python main.py
```

---

## 📁 Project Structure

```
freeboldsec-ai-vulnops/
├── core/
│   ├── model_dispatcher.py    # LLM routing logic
│   ├── burp_mcp_client.py     # Burp Suite MCP client wrapper
│   ├── preprocessor.py        # HTTP traffic analyzer
│   └── memory_manager.py      # Triage feedback storage
├── personas/
│   ├── triage_analyst.md      # Vulnerability triage persona
│   ├── recon_strategist.md    # Reconnaissance persona
│   ├── exploit_architect.md   # Exploitation persona
│   ├── report_engineer.md     # Report generation persona
│   └── auth_logic_auditor.md  # Authentication logic persona
├── config/
│   ├── models.yaml           # LLM model configurations
│   ├── mcp_settings.yaml     # MCP server connection settings
│   ├── burp_tools.yaml       # Burp Suite tool mappings
│   └── settings.yaml         # Framework settings
├── templates/
│   ├── report_templates/     # HackerOne/GitHub report formats
│   └── exploit_templates/    # PoC code templates
└── examples/
    ├── sample_burp_logs/     # Example Burp Suite logs
    └── sample_reports/       # Example vulnerability reports
```

---

## 🔧 Configuration

1. **API Keys**: Configure your LLM provider API keys in `config/models.yaml`
2. **Burp Suite MCP**: Ensure Burp Suite Professional MCP server is running on localhost:9876/sse
3. **VS Code MCP**: Configure MCP client settings for Burp Suite integration
4. **Personas**: Customize AI behavior by editing persona files in `/personas`

---

## 🚦 Usage

### Basic Vulnerability Triage
```python
from core.model_dispatcher import ModelDispatcher

dispatcher = ModelDispatcher()
result = dispatcher.analyze_burp_log("burp_scan_results.json")
```

### Automated Recon via MCP
```python
from core.burp_mcp_client import BurpMCPClient

burp_mcp = BurpMCPClient("localhost:9876/sse")
targets = burp_mcp.discover_endpoints("https://target.com")
```

---

## 🛡️ Security & Ethics

This framework is designed for **authorized penetration testing and bug bounty research only**. Users are responsible for:
- Obtaining proper authorization before testing
- Following responsible disclosure practices  
- Complying with applicable laws and regulations

---

## 📜 License

MIT License - See LICENSE file for details

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

---

## 📞 Support

- **Issues**: GitHub Issues
- **Documentation**: [Wiki](link-to-wiki)
- **Community**: [Discord](link-to-discord)
