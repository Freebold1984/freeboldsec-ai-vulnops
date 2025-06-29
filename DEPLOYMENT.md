# Freeboldsec AI VulnOps Framework - Deployment Guide

## 🚀 Quick Setup on Target Machine

### Prerequisites
- Python 3.8+
- Git
- Burp Suite Professional (optional for MCP integration)

### Installation Steps

1. **Clone the Repository**
   ```bash
   git clone <your-repo-url>
   cd freeboldsec-ai-vulnops
   ```

2. **Create Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Linux/Mac
   # OR
   venv\Scripts\activate     # Windows
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure API Keys** (Optional - for full AI analysis)
   Edit `config/settings.yaml` and add your API keys:
   ```yaml
   api_keys:
     openai: "your-openai-api-key"
     anthropic: "your-anthropic-api-key"
     groq: "your-groq-api-key"
   ```

5. **Test the Framework**
   ```bash
   # Process sample data
   python core/preprocessor.py --har examples/sample_burp_logs/sample_traffic_clean.har
   
   # Run basic analysis
   python main.py --analyze processed_traffic.json
   
   # Or use the demo mode
   python main.py --demo
   ```

## 🔧 Configuration Options

### Model Configuration (`config/models.yaml`)
- Configure which AI models to use for different tasks
- Set model priorities and fallback options
- Adjust temperature and token limits

### Burp Suite Integration (`config/mcp_settings.yaml`)
- MCP server endpoint configuration
- Burp Suite tool preferences
- Authentication settings

### Security Settings (`config/settings.yaml`)
- Rate limiting configurations
- Memory management settings
- Logging preferences

## 📁 Key Files for Your Target Machine

### Essential Files:
- `main.py` - Main framework entry point
- `core/` - All core framework modules
- `personas/` - AI persona prompts
- `config/` - Configuration files
- `requirements.txt` - Python dependencies
- `examples/` - Sample data for testing

### Optional Files:
- `setup_burp_mcp.py` - Burp Suite MCP server setup
- `processed_*.json` - Sample processed data (will be regenerated)

## 🎯 Usage Examples

### Analyze Burp Suite HAR Export
```bash
python core/preprocessor.py --har your_burp_export.har
python main.py --analyze processed_traffic.json
```

### Connect to Live Burp Suite (MCP)
```bash
python main.py --burp-live --endpoint localhost:9876/sse
```

### Generate Vulnerability Report
```bash
python main.py --report --input processed_traffic.json --output vulnerability_report.md
```

## 🔒 Security Notes

- The framework is designed for **authorized testing only**
- All sample data contains sanitized/educational payloads
- Configure proper rate limiting for production use
- Store API keys securely (use environment variables)

## 🐛 Troubleshooting

### Common Issues:
1. **ModuleNotFoundError**: Ensure all dependencies are installed in virtual environment
2. **API Key Errors**: Verify API keys are correctly configured
3. **Burp Suite Connection**: Check MCP server is running on correct port
4. **Permission Errors**: Ensure proper file permissions for log/output directories

### Getting Help:
- Check the `examples/` directory for sample usage
- Review persona prompts in `personas/` for AI behavior customization
- Examine `config/` files for advanced configuration options
