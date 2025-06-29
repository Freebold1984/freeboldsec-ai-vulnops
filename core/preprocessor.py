"""
HTTP Traffic Preprocessor - Converts Burp logs and HTTP traffic into LLM-friendly format
"""

import json
import logging
import re
import base64
import gzip
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass

import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs, unquote

logger = logging.getLogger(__name__)


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    timestamp: datetime


@dataclass
class HttpResponse:
    status_code: int
    headers: Dict[str, str]
    body: Optional[str]
    length: int


@dataclass
class ProcessedTraffic:
    request: HttpRequest
    response: Optional[HttpResponse]
    findings: List[str]
    risk_indicators: List[str]
    metadata: Dict[str, Any]


class TrafficPreprocessor:
    """Preprocesses HTTP traffic and Burp logs for AI analysis"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.max_body_size = self.config.get('max_body_size', 10000)  # characters
        self.sensitive_patterns = self._load_sensitive_patterns()
        self.vulnerability_indicators = self._load_vulnerability_indicators()
    
    def _load_sensitive_patterns(self) -> List[str]:
        """Load patterns for detecting sensitive information"""
        return [
            r'password["\s]*[:=]["\s]*([^"\s,}]+)',
            r'api[_-]?key["\s]*[:=]["\s]*([^"\s,}]+)',
            r'access[_-]?token["\s]*[:=]["\s]*([^"\s,}]+)',
            r'secret["\s]*[:=]["\s]*([^"\s,}]+)',
            r'jwt["\s]*[:=]["\s]*([^"\s,}]+)',
            r'authorization["\s]*:["\s]*([^"\s,}]+)',
            r'cookie["\s]*:["\s]*([^"\s,}]+)',
            r'session[_-]?id["\s]*[:=]["\s]*([^"\s,}]+)',
            r'private[_-]?key["\s]*[:=]["\s]*([^"\s,}]+)',
            r'database[_-]?url["\s]*[:=]["\s]*([^"\s,}]+)',
        ]
    
    def _load_vulnerability_indicators(self) -> Dict[str, List[str]]:
        """Load indicators for common vulnerability types"""
        return {
            'sql_injection': [
                r'sql.*error',
                r'mysql.*error',
                r'oracle.*error',
                r'postgresql.*error',
                r'syntax.*error.*near',
                r'unclosed.*quotation',
                r'quoted.*string.*not.*properly.*terminated',
                r'microsoft.*ole.*db.*provider',
                r'warning.*mysql_',
                r'valid.*mysql.*result',
                r'you have an error in your sql syntax'
            ],
            'xss': [
                r'<script[^>]*>',
                r'javascript:',
                r'on\w+\s*=\s*["\'][^"\']*["\']',
                r'alert\s*\(',
                r'confirm\s*\(',
                r'prompt\s*\(',
                r'document\.cookie',
                r'document\.write',
                r'window\.location',
                r'eval\s*\('
            ],
            'file_inclusion': [
                r'failed.*open.*stream',
                r'no such file or directory',
                r'warning.*include',
                r'warning.*require',
                r'fatal error.*failed opening',
                r'\.\.\/.*\.\.\/.*\.\.\/',
                r'file_get_contents\(',
                r'fopen\(',
                r'include_once\(',
                r'require_once\('
            ],
            'command_injection': [
                r'sh:.*command not found',
                r'bash:.*command not found',
                r'cmd:.*not recognized',
                r'system\(',
                r'exec\(',
                r'shell_exec\(',
                r'passthru\(',
                r'proc_open\(',
                r'popen\(',
                r'\|\|.*&.*\|\|'
            ],
            'ssrf': [
                r'curl.*error',
                r'connection.*refused',
                r'connection.*timed.*out',
                r'internal.*server.*response',
                r'metadata\.google\.internal',
                r'169\.254\.169\.254',
                r'localhost:\d+',
                r'127\.0\.0\.1:\d+',
                r'0\.0\.0\.0:\d+',
                r'::1:\d+'
            ],
            'information_disclosure': [
                r'debug.*trace',
                r'stack.*trace',
                r'exception.*details',
                r'database.*connection.*string',
                r'mysql.*hostname',
                r'postgresql.*hostname',
                r'oracle.*hostname',
                r'server.*version',
                r'php.*version',
                r'apache.*version'
            ]
        }
    
    def process_burp_xml(self, xml_path: str) -> List[ProcessedTraffic]:
        """Process Burp Suite XML export file"""
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            processed_items = []
            
            for item in root.findall('.//item'):
                try:
                    processed_item = self._process_burp_item(item)
                    if processed_item:
                        processed_items.append(processed_item)
                except Exception as e:
                    logger.warning(f"Failed to process Burp item: {e}")
                    continue
            
            logger.info(f"Processed {len(processed_items)} items from Burp XML")
            return processed_items
            
        except Exception as e:
            logger.error(f"Failed to process Burp XML file: {e}")
            return []
    
    def _process_burp_item(self, item: ET.Element) -> Optional[ProcessedTraffic]:
        """Process individual Burp Suite item"""
        try:
            # Extract request data
            request_elem = item.find('request')
            response_elem = item.find('response')
            
            if request_elem is None:
                return None
            
            # Decode request
            request_data = self._decode_burp_data(request_elem)
            request = self._parse_http_request(request_data)
            
            # Decode response if available
            response = None
            if response_elem is not None:
                response_data = self._decode_burp_data(response_elem)
                response = self._parse_http_response(response_data)
            
            # Analyze for vulnerabilities and risks
            findings = self._analyze_for_vulnerabilities(request, response)
            risk_indicators = self._identify_risk_indicators(request, response)
            
            # Extract metadata
            metadata = self._extract_metadata(item, request, response)
            
            return ProcessedTraffic(
                request=request,
                response=response,
                findings=findings,
                risk_indicators=risk_indicators,
                metadata=metadata
            )
            
        except Exception as e:
            logger.error(f"Failed to process Burp item: {e}")
            return None
    
    def _decode_burp_data(self, element: ET.Element) -> str:
        """Decode base64 encoded Burp data"""
        if element.get('base64') == 'true':
            try:
                return base64.b64decode(element.text).decode('utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"Failed to decode base64 data: {e}")
                return element.text or ""
        return element.text or ""
    
    def _parse_http_request(self, request_data: str) -> HttpRequest:
        """Parse HTTP request from raw text"""
        lines = request_data.split('\n')
        if not lines:
            raise ValueError("Empty request data")
        
        # Parse request line
        request_line = lines[0].strip()
        parts = request_line.split(' ')
        if len(parts) < 2:
            raise ValueError("Invalid request line")
        
        method = parts[0]
        url = parts[1]
        
        # Parse headers
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Extract body
        body = None
        if body_start < len(lines):
            body_lines = lines[body_start:]
            body = '\n'.join(body_lines).strip()
            if body:
                body = self._truncate_body(body)
        
        return HttpRequest(
            method=method,
            url=url,
            headers=headers,
            body=body,
            timestamp=datetime.now()
        )
    
    def _parse_http_response(self, response_data: str) -> HttpResponse:
        """Parse HTTP response from raw text"""
        lines = response_data.split('\n')
        if not lines:
            raise ValueError("Empty response data")
        
        # Parse status line
        status_line = lines[0].strip()
        parts = status_line.split(' ')
        if len(parts) < 2:
            raise ValueError("Invalid status line")
        
        status_code = int(parts[1])
        
        # Parse headers
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Extract body
        body = None
        length = 0
        if body_start < len(lines):
            body_lines = lines[body_start:]
            body = '\n'.join(body_lines).strip()
            if body:
                length = len(body)
                body = self._truncate_body(body)
        
        return HttpResponse(
            status_code=status_code,
            headers=headers,
            body=body,
            length=length
        )
    
    def _truncate_body(self, body: str) -> str:
        """Truncate body if too large"""
        if len(body) > self.max_body_size:
            return body[:self.max_body_size] + f"\n... [truncated, original size: {len(body)} chars]"
        return body
    
    def _analyze_for_vulnerabilities(self, request: HttpRequest, response: Optional[HttpResponse]) -> List[str]:
        """Analyze request/response for vulnerability indicators"""
        findings = []
        
        # Check request for malicious patterns
        request_text = f"{request.method} {request.url}\n"
        request_text += "\n".join([f"{k}: {v}" for k, v in request.headers.items()])
        if request.body:
            request_text += f"\n\n{request.body}"
        
        # Check response for vulnerability indicators
        response_text = ""
        if response and response.body:
            response_text = response.body
        
        # Test against vulnerability patterns
        for vuln_type, patterns in self.vulnerability_indicators.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    findings.append(f"Potential {vuln_type.replace('_', ' ')}: {pattern}")
                elif re.search(pattern, request_text, re.IGNORECASE):
                    findings.append(f"Potential {vuln_type.replace('_', ' ')} in request: {pattern}")
        
        return findings
    
    def _identify_risk_indicators(self, request: HttpRequest, response: Optional[HttpResponse]) -> List[str]:
        """Identify general risk indicators"""
        indicators = []
        
        # Check for sensitive data exposure
        for pattern in self.sensitive_patterns:
            if request.body and re.search(pattern, request.body, re.IGNORECASE):
                indicators.append("Sensitive data in request body")
            
            if response and response.body and re.search(pattern, response.body, re.IGNORECASE):
                indicators.append("Sensitive data in response body")
        
        # Check for suspicious status codes
        if response:
            if response.status_code >= 500:
                indicators.append(f"Server error: {response.status_code}")
            elif response.status_code == 403:
                indicators.append("Access forbidden - potential authorization issue")
            elif response.status_code == 401:
                indicators.append("Authentication required")
        
        # Check for suspicious parameters
        if '?' in request.url:
            query_params = parse_qs(urlparse(request.url).query)
            suspicious_params = ['debug', 'test', 'admin', 'cmd', 'exec', 'file', 'path', 'url']
            
            for param in query_params:
                if any(susp in param.lower() for susp in suspicious_params):
                    indicators.append(f"Suspicious parameter: {param}")
        
        # Check for unusual headers
        suspicious_headers = ['x-debug', 'x-test', 'x-admin', 'server', 'x-powered-by']
        for header in request.headers:
            if any(susp in header.lower() for susp in suspicious_headers):
                indicators.append(f"Suspicious request header: {header}")
        
        if response:
            for header in response.headers:
                if any(susp in header.lower() for susp in suspicious_headers):
                    indicators.append(f"Information disclosure header: {header}")
        
        return indicators
    
    def _extract_metadata(self, item: ET.Element, request: HttpRequest, response: Optional[HttpResponse]) -> Dict[str, Any]:
        """Extract metadata from Burp item and request/response"""
        metadata = {}
        
        # Basic request metadata
        parsed_url = urlparse(request.url)
        metadata.update({
            'host': parsed_url.hostname,
            'port': parsed_url.port,
            'scheme': parsed_url.scheme,
            'path': parsed_url.path,
            'method': request.method,
            'has_parameters': '?' in request.url,
            'has_body': request.body is not None and len(request.body) > 0
        })
        
        # Response metadata
        if response:
            metadata.update({
                'status_code': response.status_code,
                'response_length': response.length,
                'content_type': response.headers.get('content-type', 'unknown')
            })
        
        # Burp-specific metadata
        if item is not None:
            metadata.update({
                'burp_tool': item.get('tool', 'unknown'),
                'burp_host': item.get('host', ''),
                'burp_port': item.get('port', ''),
                'burp_protocol': item.get('protocol', ''),
                'burp_timestamp': item.get('timestamp', '')
            })
        
        return metadata
    
    def process_har_file(self, har_path: str) -> List[ProcessedTraffic]:
        """Process HTTP Archive (HAR) file"""
        try:
            with open(har_path, 'r') as f:
                har_data = json.load(f)
            
            processed_items = []
            entries = har_data.get('log', {}).get('entries', [])
            
            for entry in entries:
                try:
                    processed_item = self._process_har_entry(entry)
                    if processed_item:
                        processed_items.append(processed_item)
                except Exception as e:
                    logger.warning(f"Failed to process HAR entry: {e}")
                    continue
            
            logger.info(f"Processed {len(processed_items)} entries from HAR file")
            return processed_items
            
        except Exception as e:
            logger.error(f"Failed to process HAR file: {e}")
            return []
    
    def _process_har_entry(self, entry: Dict[str, Any]) -> Optional[ProcessedTraffic]:
        """Process individual HAR entry"""
        try:
            request_data = entry.get('request', {})
            response_data = entry.get('response', {})
            
            # Build request
            method = request_data.get('method', 'GET')
            url = request_data.get('url', '')
            
            headers = {}
            for header in request_data.get('headers', []):
                headers[header.get('name', '')] = header.get('value', '')
            
            body = None
            post_data = request_data.get('postData', {})
            if post_data.get('text'):
                body = self._truncate_body(post_data['text'])
            
            request = HttpRequest(
                method=method,
                url=url,
                headers=headers,
                body=body,
                timestamp=datetime.fromisoformat(entry.get('startedDateTime', '').replace('Z', '+00:00'))
            )
            
            # Build response
            response = None
            if response_data:
                status_code = response_data.get('status', 0)
                
                resp_headers = {}
                for header in response_data.get('headers', []):
                    resp_headers[header.get('name', '')] = header.get('value', '')
                
                resp_body = None
                content = response_data.get('content', {})
                if content.get('text'):
                    resp_body = self._truncate_body(content['text'])
                
                response = HttpResponse(
                    status_code=status_code,
                    headers=resp_headers,
                    body=resp_body,
                    length=content.get('size', 0)
                )
            
            # Analyze for vulnerabilities and risks
            findings = self._analyze_for_vulnerabilities(request, response)
            risk_indicators = self._identify_risk_indicators(request, response)
            
            # Extract metadata
            metadata = {
                'har_entry': True,
                'time_taken_ms': entry.get('time', 0),
                'started_datetime': entry.get('startedDateTime', ''),
            }
            metadata.update(self._extract_metadata(None, request, response))
            
            return ProcessedTraffic(
                request=request,
                response=response,
                findings=findings,
                risk_indicators=risk_indicators,
                metadata=metadata
            )
            
        except Exception as e:
            logger.error(f"Failed to process HAR entry: {e}")
            return None
    
    def generate_summary(self, processed_traffic: List[ProcessedTraffic]) -> Dict[str, Any]:
        """Generate summary of processed traffic for AI analysis"""
        summary = {
            'total_requests': len(processed_traffic),
            'unique_hosts': set(),
            'methods_used': {},
            'status_codes': {},
            'vulnerability_types': {},
            'risk_indicators': {},
            'high_risk_items': [],
            'content_types': {}
        }
        
        for item in processed_traffic:
            # Track hosts
            if item.metadata.get('host'):
                summary['unique_hosts'].add(item.metadata['host'])
            
            # Track methods
            method = item.request.method
            summary['methods_used'][method] = summary['methods_used'].get(method, 0) + 1
            
            # Track status codes
            if item.response:
                status = item.response.status_code
                summary['status_codes'][status] = summary['status_codes'].get(status, 0) + 1
                
                # Track content types
                content_type = item.response.headers.get('content-type', 'unknown')
                content_type = content_type.split(';')[0]  # Remove charset info
                summary['content_types'][content_type] = summary['content_types'].get(content_type, 0) + 1
            
            # Track vulnerability types
            for finding in item.findings:
                vuln_type = finding.split(':')[0] if ':' in finding else finding
                summary['vulnerability_types'][vuln_type] = summary['vulnerability_types'].get(vuln_type, 0) + 1
            
            # Track risk indicators
            for indicator in item.risk_indicators:
                summary['risk_indicators'][indicator] = summary['risk_indicators'].get(indicator, 0) + 1
            
            # Identify high-risk items
            if len(item.findings) > 0 or len(item.risk_indicators) > 2:
                summary['high_risk_items'].append({
                    'url': item.request.url,
                    'method': item.request.method,
                    'findings_count': len(item.findings),
                    'risk_indicators_count': len(item.risk_indicators),
                    'findings': item.findings[:3],  # Top 3 findings
                    'indicators': item.risk_indicators[:3]  # Top 3 indicators
                })
        
        # Convert sets to lists for JSON serialization
        summary['unique_hosts'] = list(summary['unique_hosts'])
        
        return summary
    
    def export_for_ai_analysis(self, processed_traffic: List[ProcessedTraffic], output_path: str):
        """Export processed traffic in AI-friendly format"""
        try:
            export_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'total_items': len(processed_traffic),
                    'preprocessor_version': '1.0.0'
                },
                'summary': self.generate_summary(processed_traffic),
                'high_priority_items': [],
                'all_items': []
            }
            
            # Extract high-priority items for detailed analysis
            for item in processed_traffic:
                if len(item.findings) > 0 or len(item.risk_indicators) > 1:
                    export_data['high_priority_items'].append({
                        'request': {
                            'method': item.request.method,
                            'url': item.request.url,
                            'headers': item.request.headers,
                            'body': item.request.body
                        },
                        'response': {
                            'status_code': item.response.status_code if item.response else None,
                            'headers': item.response.headers if item.response else {},
                            'body': item.response.body if item.response else None
                        } if item.response else None,
                        'findings': item.findings,
                        'risk_indicators': item.risk_indicators,
                        'metadata': item.metadata
                    })
            
            # Include condensed version of all items
            for item in processed_traffic:
                export_data['all_items'].append({
                    'url': item.request.url,
                    'method': item.request.method,
                    'status_code': item.response.status_code if item.response else None,
                    'findings_count': len(item.findings),
                    'risk_indicators_count': len(item.risk_indicators),
                    'has_sensitive_data': any('sensitive' in indicator.lower() for indicator in item.risk_indicators)
                })
            
            # Write to file
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"Exported {len(processed_traffic)} processed items to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export processed traffic: {e}")
            raise


# CLI interface for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="HTTP Traffic Preprocessor")
    parser.add_argument("--burp-xml", help="Process Burp Suite XML file")
    parser.add_argument("--har", help="Process HAR file")
    parser.add_argument("--output", help="Output file for processed data", default="processed_traffic.json")
    
    args = parser.parse_args()
    
    preprocessor = TrafficPreprocessor()
    
    if args.burp_xml:
        processed = preprocessor.process_burp_xml(args.burp_xml)
        preprocessor.export_for_ai_analysis(processed, args.output)
        print(f"Processed {len(processed)} items from Burp XML")
    
    elif args.har:
        processed = preprocessor.process_har_file(args.har)
        preprocessor.export_for_ai_analysis(processed, args.output)
        print(f"Processed {len(processed)} items from HAR file")
    
    else:
        print("Please specify --burp-xml or --har file to process")
