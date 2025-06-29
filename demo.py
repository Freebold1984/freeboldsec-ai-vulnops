#!/usr/bin/env python3
"""
Demo Mode for Freeboldsec AI VulnOps Framework
Demonstrates framework capabilities without requiring API keys
"""

import json
import sys
from pathlib import Path
from datetime import datetime

def load_sample_data():
    """Load the processed sample data"""
    try:
        with open('processed_traffic.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("❌ No processed data found. Please run the preprocessor first:")
        print("   python core/preprocessor.py --har examples/sample_burp_logs/sample_traffic_clean.har")
        return None

def simulate_ai_analysis(data):
    """Simulate AI analysis without requiring API keys"""
    
    # Simulate triage analysis
    triage_results = []
    
    for item in data.get('high_priority_items', []):
        url = item['request']['url']
        method = item['request']['method']
        findings = item.get('findings', [])
        
        # Create simulated AI triage
        risk_level = "HIGH" if any("sql injection" in f.lower() for f in findings) else "MEDIUM"
        
        triage_results.append({
            "url": url,
            "method": method,
            "risk_level": risk_level,
            "vulnerability_types": findings,
            "ai_confidence": 0.85,
            "recommended_actions": [
                "Validate input sanitization",
                "Test for additional injection points",
                "Review database query construction"
            ] if risk_level == "HIGH" else [
                "Monitor for exploitation attempts",
                "Review access controls"
            ],
            "exploitation_potential": "High - Direct SQL injection detected" if risk_level == "HIGH" else "Medium - Information disclosure possible"
        })
    
    return triage_results

def generate_demo_report(analysis_results):
    """Generate a demo vulnerability report"""
    
    report = f"""# 🔍 Freeboldsec AI VulnOps Framework - Demo Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Mode:** Demo Analysis (Simulated AI)

## 📊 Executive Summary

This report demonstrates the Freeboldsec AI VulnOps Framework's capability to analyze web application traffic and identify security vulnerabilities using AI-powered triage.

### Key Findings:
"""
    
    high_risk = sum(1 for r in analysis_results if r['risk_level'] == 'HIGH')
    medium_risk = sum(1 for r in analysis_results if r['risk_level'] == 'MEDIUM')
    
    report += f"""
- **High Risk Vulnerabilities:** {high_risk}
- **Medium Risk Vulnerabilities:** {medium_risk}
- **Total Issues Analyzed:** {len(analysis_results)}

## 🚨 Detailed Vulnerability Analysis

"""
    
    for i, result in enumerate(analysis_results, 1):
        report += f"""
### {i}. {result['risk_level']} RISK - {result['url']}

**Method:** {result['method']}
**AI Confidence:** {result['ai_confidence']:.2%}

**Vulnerability Types:**
"""
        for vuln_type in result['vulnerability_types']:
            report += f"- {vuln_type}\n"
        
        report += f"""
**Exploitation Potential:**
{result['exploitation_potential']}

**Recommended Actions:**
"""
        for action in result['recommended_actions']:
            report += f"- {action}\n"
        
        report += "\n---\n"
    
    report += f"""
## 🤖 AI Framework Capabilities Demonstrated

This demo showcases the following framework features:

### ✅ **Traffic Analysis**
- HAR file processing and vulnerability detection
- Pattern recognition for common attack vectors
- Risk prioritization based on severity

### ✅ **AI-Powered Triage**
- Automated vulnerability classification
- Confidence scoring for findings
- Contextual analysis of exploitation potential

### ✅ **Persona-Driven Analysis**
In full mode, the framework uses specialized AI personas:
- **Triage Analyst**: Initial vulnerability assessment
- **Recon Strategist**: Attack surface analysis  
- **Exploit Architect**: Exploitation potential evaluation
- **Report Engineer**: Professional report generation
- **Auth Logic Auditor**: Authentication bypass detection

### ✅ **Integration Capabilities**
- Burp Suite Professional (via MCP)
- Multiple AI models (GPT-4, Claude, Mistral)
- Structured vulnerability reporting
- Memory management for duplicate detection

## 🔄 Next Steps

To use the full framework with live AI analysis:

1. Configure API keys in `config/settings.yaml`
2. Connect to Burp Suite via MCP server
3. Run live vulnerability triage on real traffic
4. Generate professional penetration testing reports

---

*This is a demonstration of the Freeboldsec AI VulnOps Framework. For authorized security testing only.*
"""
    
    return report

def main():
    print("🤖 Freeboldsec AI VulnOps Framework - Demo Mode")
    print("=" * 50)
    
    # Load sample data
    print("📊 Loading processed vulnerability data...")
    data = load_sample_data()
    if not data:
        sys.exit(1)
    
    print(f"✅ Loaded {data['metadata']['total_items']} analyzed items")
    
    # Simulate AI analysis
    print("🧠 Running simulated AI triage analysis...")
    analysis_results = simulate_ai_analysis(data)
    
    # Generate report
    print("📝 Generating vulnerability report...")
    report = generate_demo_report(analysis_results)
    
    # Save report
    report_file = f"demo_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"✅ Demo report generated: {report_file}")
    print("\n" + "=" * 50)
    print("🎯 Demo Summary:")
    print(f"   • Analyzed {len(analysis_results)} vulnerabilities")
    print(f"   • High risk issues: {sum(1 for r in analysis_results if r['risk_level'] == 'HIGH')}")
    print(f"   • Medium risk issues: {sum(1 for r in analysis_results if r['risk_level'] == 'MEDIUM')}")
    print(f"   • Report saved to: {report_file}")
    print("\n🚀 Ready for deployment to your target machine!")

if __name__ == "__main__":
    main()
