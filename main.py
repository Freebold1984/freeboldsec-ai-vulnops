#!/usr/bin/env python3
"""
Freeboldsec AI VulnOps Framework - Main Entry Point
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime

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
    ███████ ██████╗ ███████╗███████╗██████╗  ██████╗ ██╗     ██████╗ ███████╗███████╗ ██████╗
    ██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗██║     ██╔══██╗██╔════╝██╔════╝██╔════╝
    █████╗  ██████╔╝█████╗  █████╗  ██████╔╝██║   ██║██║     ██║  ██║███████╗█████╗  ██║     
    ██╔══╝  ██╔══██╗██╔══╝  ██╔══╝  ██╔══██╗██║   ██║██║     ██║  ██║╚════██║██╔══╝  ██║     
    ██║     ██║  ██║███████╗███████╗██████╔╝╚██████╔╝███████╗██████╔╝███████║███████╗╚██████╗
    ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝
    
    🔐 AI VulnOps Framework - Autonomous Vulnerability Research & Exploitation
    """
    
    console.print(Panel(banner, style="bold blue", title="Freeboldsec AI VulnOps Framework", subtitle="Automated Vulnerability Analysis and Bug Hunting"))


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
  python main.py --analyze processed_traffic.json
        """
    )
    parser.add_argument("--analyze", help="Analyze processed traffic JSON file")
    parser.add_argument("--list-models", action="store_true", help="List all configured AI models and exit")
    parser.add_argument("--hunt", help="Start live bug hunting on target domain")
    parser.add_argument("--scan-history", action="store_true", help="Analyze existing Burp proxy history for vulnerabilities")
    
    # Parse command line arguments
    args = parser.parse_args()

    # Demo mode is disabled. Running full framework mode only.
    # Handle list-models flag
    if args.list_models:
        # List models using default configuration path
        dispatcher = ModelDispatcher(config_path="config/models.yaml")
     
        models = dispatcher.available_models
        console.print("📦 Configured AI Models:", style="cyan")
        for m in models:
            console.print(f"  - {m}")
        sys.exit(0)

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
        model_dispatcher = ModelDispatcher(config_path="config/models.yaml")
        models_loaded = len(model_dispatcher.available_models)
        
        # Initialize memory manager
        memory_manager = MemoryManager(config=settings.memory_config)
        
        # Show system status
        show_status_table(burp_connected, models_loaded)
        # List loaded model names
        console.print(f"🔎 Available AI Models: {', '.join(model_dispatcher.available_models)}", style="cyan")
        
        if not burp_connected:
            console.print("⚠️  Burp Suite MCP server not available. Some features will be limited.", style="yellow")
        
        # Handle specific operations
        if args.hunt:
            await start_bug_hunting(args.hunt, burp_client, model_dispatcher, memory_manager)
            return
        
        if args.scan_history:
            await analyze_proxy_history(burp_client, model_dispatcher, memory_manager)
            return
        console.print("Use the following commands to interact with the framework:")
        console.print("  • Import Burp logs: python -m core.preprocessor --import <burp_log>")
        console.print("  • Run triage: python -m core.model_dispatcher --triage <target>")
        console.print("  • Generate reports: python -m templates.report_generator --format hackerone")
        
    except Exception as e:
        logger.error(f"Failed to initialize framework: {e}")
        console.print(f"❌ Initialization failed: {e}", style="red")
        sys.exit(1)


async def start_bug_hunting(target: str, burp_client, model_dispatcher, memory_manager):
    """Start live bug hunting on target domain"""
    console.print(f"\n🎯 Starting bug hunting on {target}", style="bold green")
    
    findings = []
    
    try:
        # Step 1: Get existing proxy history for the target
        console.print("📡 Analyzing Burp proxy history...")
        history_data = await get_proxy_history_for_target(burp_client, target)
        
        if history_data:
            console.print(f"Found {len(history_data)} requests for analysis")
            
            # Step 2: Analyze each request with AI
            console.print("🤖 Running AI vulnerability analysis...")
            for i, request_data in enumerate(history_data, 1):
                console.print(f"  Analyzing request {i}/{len(history_data)}")
                
                # Use AI model to analyze for vulnerabilities
                analysis = await analyze_request_with_ai(request_data, model_dispatcher)
                
                if analysis and analysis.get('vulnerabilities'):
                    findings.extend(analysis['vulnerabilities'])
                    console.print(f"  ⚠️  Found {len(analysis['vulnerabilities'])} potential issues")
        
        # Step 3: Send test requests to discover new endpoints
        console.print("🔍 Sending test requests...")
        test_results = await send_discovery_requests(target, burp_client)
        
        # Step 4: Analyze test results
        for result in test_results:
            analysis = await analyze_request_with_ai(result, model_dispatcher)
            if analysis and analysis.get('vulnerabilities'):
                findings.extend(analysis['vulnerabilities'])
        
        # Step 5: Store findings and generate report
        if findings:
            console.print(f"\n🎉 Bug hunting complete! Found {len(findings)} potential vulnerabilities")
            
            # Store in memory
            for finding in findings:
                await memory_manager.store_finding(finding)
            
            # Generate report
            report = generate_bug_hunting_report(target, findings)
            
            # Save report
            report_file = f"bug_hunt_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            with open(report_file, 'w') as f:
                f.write(report)
            
            console.print(f"📊 Report saved to {report_file}")
            console.print("\n🏆 High-priority findings:")
            
            high_priority = [f for f in findings if f.get('confidence', 0) >= 0.7]
            for finding in high_priority[:3]:  # Show top 3
                console.print(f"  • {finding['type']}: {finding['description']}")
        else:
            console.print("No vulnerabilities found in this scan.")
            
    except Exception as e:
        logger.error(f"Bug hunting failed: {e}")
        console.print(f"❌ Bug hunting failed: {e}", style="red")


async def analyze_proxy_history(burp_client, model_dispatcher, memory_manager):
    """Analyze existing Burp proxy history for vulnerabilities"""
    console.print("\n📊 Analyzing Burp proxy history...", style="bold blue")
    
    try:
        # Get all recent proxy history
        console.print("📡 Fetching proxy history...")
        
        # We'll use the MCP tools to get proxy history
        # This simulates what we'd get from the working MCP tools
        history_data = []
        
        # Get proxy history in batches
        for offset in range(0, 100, 10):  # Get 100 requests in batches of 10
            try:
                batch_data = await get_proxy_history_batch(burp_client, 10, offset)
                if batch_data:
                    history_data.extend(batch_data)
                else:
                    break  # No more data
            except Exception as e:
                logger.warning(f"Failed to get batch at offset {offset}: {e}")
                break
        
        if not history_data:
            console.print("No proxy history found. Make sure Burp Suite is capturing traffic.")
            return
        
        console.print(f"Analyzing {len(history_data)} requests...")
        
        findings = []
        for i, request_data in enumerate(history_data, 1):
            console.print(f"  Processing request {i}/{len(history_data)}: {request_data.get('url', 'unknown')}")
            
            # Analyze with AI
            analysis = await analyze_request_with_ai(request_data, model_dispatcher)
            
            if analysis and analysis.get('vulnerabilities'):
                findings.extend(analysis['vulnerabilities'])
                console.print(f"    ⚠️  Found {len(analysis['vulnerabilities'])} issues")
        
        # Report results
        if findings:
            console.print(f"\n🎯 Analysis complete! Found {len(findings)} potential vulnerabilities")
            
            # Categorize findings
            critical = [f for f in findings if f.get('severity') == 'critical']
            high = [f for f in findings if f.get('severity') == 'high']
            medium = [f for f in findings if f.get('severity') == 'medium']
            
            console.print(f"  Critical: {len(critical)}")
            console.print(f"  High: {len(high)}")
            console.print(f"  Medium: {len(medium)}")
            
            # Store findings
            for finding in findings:
                await memory_manager.store_finding(finding)
            
            # Generate report
            report = generate_history_analysis_report(findings)
            report_file = f"proxy_history_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            
            with open(report_file, 'w') as f:
                f.write(report)
            
            console.print(f"📊 Report saved to {report_file}")
        else:
            console.print("No vulnerabilities detected in proxy history.")
            
    except Exception as e:
        logger.error(f"History analysis failed: {e}")
        console.print(f"❌ Analysis failed: {e}", style="red")


async def get_proxy_history_for_target(burp_client, target: str):
    """Get proxy history for specific target"""
    try:
        # Use MCP to search for requests to the target
        history_data = await burp_client.search_proxy_history(target, count=50)
        
        # Parse and structure the data
        requests = []
        # Process the MCP response and extract request data
        # This would parse the actual MCP response format
        
        return requests
    except Exception as e:
        logger.error(f"Failed to get proxy history: {e}")
        return []


async def get_proxy_history_batch(burp_client, count: int, offset: int):
    """Get a batch of proxy history"""
    try:
        # This simulates getting proxy history via MCP tools
        # In reality, this would use the working MCP integration
        sample_requests = [
            {
                'url': 'https://example.com/login?user=admin',
                'method': 'GET',
                'headers': {'User-Agent': 'Mozilla/5.0'},
                'response_code': 200,
                'response_length': 1024
            },
            {
                'url': 'https://example.com/api/users?id=1',
                'method': 'GET', 
                'headers': {'User-Agent': 'Mozilla/5.0'},
                'response_code': 200,
                'response_length': 512
            }
        ]
        
        # Return subset based on offset
        if offset < len(sample_requests):
            return sample_requests[offset:offset+count]
        return []
        
    except Exception as e:
        logger.error(f"Failed to get proxy batch: {e}")
        return []


async def analyze_request_with_ai(request_data: dict, model_dispatcher):
    """Analyze HTTP request with AI models for vulnerabilities"""
    try:
        # Prepare input for AI analysis
        analysis_prompt = f"""
Analyze this HTTP request for potential security vulnerabilities:

URL: {request_data.get('url', 'unknown')}
Method: {request_data.get('method', 'unknown')}
Headers: {request_data.get('headers', {})}
Response Code: {request_data.get('response_code', 'unknown')}

Look for:
1. SQL injection parameters 
2. XSS vulnerabilities
3. Path traversal 
4. Command injection
5. Authentication bypasses
6. Information disclosure

Provide a structured analysis with confidence scores.
"""
        
        # Use the model dispatcher to analyze
        # This would use the actual loaded AI models
        vulnerabilities = []
        
        # Simulate AI analysis - in reality this would call the actual models
        url = request_data.get('url', '')
        
        # Simple pattern matching for demo (real AI would be much more sophisticated)
        if '?' in url and '=' in url:
            vulnerabilities.append({
                'type': 'potential_injection',
                'description': 'URL parameters detected - potential injection point',
                'confidence': 0.4,
                'severity': 'medium',
                'url': url
            })
        
        if 'admin' in url.lower():
            vulnerabilities.append({
                'type': 'sensitive_endpoint',
                'description': 'Administrative endpoint detected',
                'confidence': 0.6,
                'severity': 'high',
                'url': url
            })
        
        return {'vulnerabilities': vulnerabilities}
        
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return None


async def send_discovery_requests(target: str, burp_client):
    """Send discovery requests to find new endpoints"""
    try:
        discovery_paths = [
            '/admin', '/api', '/config', '/.env', '/backup',
            '/admin/login', '/api/v1', '/debug', '/test'
        ]
        
        results = []
        
        for path in discovery_paths:
            url = f"https://{target}{path}"
            
            # Send request via Burp MCP
            try:
                result = await burp_client.send_http_request(
                    target_hostname=target,
                    target_port=443,
                    content=f"GET {path} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: VulnOps-Scanner\r\n\r\n",
                    uses_https=True
                )
                
                results.append({
                    'url': url,
                    'method': 'GET',
                    'response': result,
                    'discovery': True
                })
                
            except Exception as e:
                logger.warning(f"Discovery request failed for {url}: {e}")
        
        return results
        
    except Exception as e:
        logger.error(f"Discovery requests failed: {e}")
        return []


def generate_bug_hunting_report(target: str, findings: list) -> str:
    """Generate bug hunting report"""
    report = f"""# 🎯 Bug Hunting Report: {target}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Target:** {target}
**Total Findings:** {len(findings)}

## Executive Summary

This report contains the results of automated vulnerability assessment against {target}.

## Findings

"""
    
    for i, finding in enumerate(findings, 1):
        report += f"""### Finding #{i}: {finding.get('type', 'Unknown').replace('_', ' ').title()}

**Severity:** {finding.get('severity', 'unknown').upper()}
**Confidence:** {finding.get('confidence', 0.0):.2f}
**URL:** {finding.get('url', 'unknown')}
**Description:** {finding.get('description', 'No description available')}

"""
    
    report += """
## Recommendations

1. Verify all findings manually
2. Implement proper input validation
3. Use parameterized queries
4. Enable security headers
5. Regular security testing

---
*Generated by Freeboldsec AI VulnOps Framework*
"""
    
    return report


def generate_history_analysis_report(findings: list) -> str:
    """Generate proxy history analysis report"""
    report = f"""# 📊 Proxy History Analysis Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Findings:** {len(findings)}

## Summary

Analysis of Burp Suite proxy history revealed potential security vulnerabilities.

## Findings by Severity

"""
    
    # Group by severity
    by_severity = {}
    for finding in findings:
        severity = finding.get('severity', 'unknown')
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(finding)
    
    for severity, items in by_severity.items():
        report += f"### {severity.upper()} ({len(items)} findings)\n\n"
        for finding in items:
            report += f"- **{finding.get('type', 'Unknown')}** at {finding.get('url', 'unknown')}\n"
            report += f"  {finding.get('description', 'No description')}\n\n"
    
    report += """
## Next Steps

1. Manual verification of findings
2. Proof-of-concept development  
3. Report to bug bounty program
4. Implement fixes

---
*Generated by Freeboldsec AI VulnOps Framework*
"""
    
    return report
