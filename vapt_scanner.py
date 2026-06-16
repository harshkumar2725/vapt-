#!/usr/bin/env python3
"""
VAPT Scanner - Automated Vulnerability Assessment & Penetration Testing Tool
Detects OWASP Top 10:2025 vulnerabilities in web applications
"""

import requests
import re
import json
import sys
import argparse
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Tuple
import hashlib

class VAPTScanner:
    def __init__(self, url: str):
        self.url = url
        self.vulnerabilities = []
        self.headers = {
            'User-Agent': 'VAPT-Scanner/1.0'
        }
        self.payloads = self.load_payloads()
        
    def load_payloads(self) -> Dict:
        """Load vulnerability payloads"""
        return {
            'sql_injection': [
                "' OR '1'='1",
                "1' UNION SELECT NULL--",
                "1; DROP TABLE users--",
                "admin' --",
                "' OR 1=1--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<body onload=alert('XSS')>"
            ],
            'command_injection': [
                "; ls -la",
                "| whoami",
                "& ipconfig",
                "`cat /etc/passwd`",
                "$(whoami)"
            ]
        }

    def scan(self) -> Dict:
        """Execute full vulnerability scan"""
        print(f"[*] Starting VAPT scan on {self.url}")
        print(f"[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        try:
            # A01:2025 - Broken Access Control
            self.check_broken_access_control()
            
            # A02:2025 - Security Misconfiguration
            self.check_security_misconfiguration()
            
            # A03:2025 - Software Supply Chain Failures
            self.check_supply_chain()
            
            # A04:2025 - Cryptographic Failures
            self.check_cryptographic_failures()
            
            # A05:2025 - Injection
            self.check_injection()
            
            # A06:2025 - Insecure Design
            self.check_insecure_design()
            
            # A07:2025 - Authentication Failures
            self.check_authentication_failures()
            
            # A08:2025 - Software or Data Integrity Failures
            self.check_integrity_failures()
            
            # A09:2025 - Security Logging and Alerting Failures
            self.check_logging_failures()
            
            # A10:2025 - Mishandling of Exceptional Conditions
            self.check_exception_handling()
            
        except Exception as e:
            self.add_vulnerability(
                "Scanner Error",
                "Critical",
                f"Error during scanning: {str(e)}"
            )
        
        return self.generate_report()
    
    def check_broken_access_control(self):
        """A01:2025 - Broken Access Control"""
        print("[+] Checking A01:2025 - Broken Access Control...")
        
        try:
            response = requests.get(self.url, headers=self.headers, timeout=5)
            
            # Check for missing authorization headers
            if 'authorization' not in response.request.headers:
                self.add_vulnerability(
                    "Missing Authorization Header",
                    "High",
                    "API endpoints may not require authentication",
                    "A01:2025"
                )
            
            # Check for insecure direct object reference (IDOR)
            if '/api/' in self.url or '/user/' in self.url:
                self.add_vulnerability(
                    "Potential IDOR Vulnerability",
                    "Medium",
                    "Application may be vulnerable to Insecure Direct Object References",
                    "A01:2025"
                )
            
            # Check for missing CORS headers
            if 'Access-Control-Allow-Origin' not in response.headers:
                self.add_vulnerability(
                    "Missing CORS Headers",
                    "Medium",
                    "CORS not properly configured, allowing unauthorized cross-origin requests",
                    "A01:2025"
                )
                
        except Exception as e:
            print(f"[-] Error checking access control: {e}")
    
    def check_security_misconfiguration(self):
        """A02:2025 - Security Misconfiguration"""
        print("[+] Checking A02:2025 - Security Misconfiguration...")
        
        try:
            response = requests.get(self.url, headers=self.headers, timeout=5)
            
            # Check for debug information in headers
            debug_headers = ['X-Powered-By', 'Server']
            for header in debug_headers:
                if header in response.headers:
                    self.add_vulnerability(
                        f"Information Disclosure via {header} Header",
                        "Low",
                        f"Server reveals {header}: {response.headers[header]}",
                        "A02:2025"
                    )
            
            # Check for common misconfigured endpoints
            dangerous_paths = ['/admin', '/config', '/.env', '/backup', '/.git']
            for path in dangerous_paths:
                try:
                    check_resp = requests.get(urljoin(self.url, path), timeout=3)
                    if check_resp.status_code != 404:
                        self.add_vulnerability(
                            f"Exposed Sensitive Path: {path}",
                            "High",
                            f"Sensitive path {path} is accessible (Status: {check_resp.status_code})",
                            "A02:2025"
                        )
                except:
                    pass
            
            # Check SSL/TLS configuration
            if not self.url.startswith('https'):
                self.add_vulnerability(
                    "Unencrypted Connection",
                    "Critical",
                    "Application does not use HTTPS/TLS encryption",
                    "A02:2025"
                )
            
            # Check for missing security headers
            security_headers = {
                'Content-Security-Policy': 'CSP not configured',
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-Content-Type-Options': 'MIME sniffing protection missing',
                'Strict-Transport-Security': 'HSTS not configured'
            }
            
            for header, message in security_headers.items():
                if header not in response.headers:
                    self.add_vulnerability(
                        f"Missing Security Header: {header}",
                        "Medium",
                        message,
                        "A02:2025"
                    )
                    
        except Exception as e:
            print(f"[-] Error checking security misconfiguration: {e}")
    
    def check_supply_chain(self):
        """A03:2025 - Software Supply Chain Failures"""
        print("[+] Checking A03:2025 - Software Supply Chain Failures...")
        
        try:
            response = requests.get(self.url, headers=self.headers, timeout=5)
            
            # Look for version information
            vulnerable_patterns = [
                (r'jquery[\\./]?([0-9.]+)', 'jQuery'),
                (r'bootstrap[\\./]?([0-9.]+)', 'Bootstrap'),
                (r'angular[\\./]?([0-9.]+)', 'Angular'),
                (r'react[\\./]?([0-9.]+)', 'React')
            ]
            
            for pattern, lib_name in vulnerable_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    self.add_vulnerability(
                        f"Outdated Library Detected: {lib_name}",
                        "Medium",
                        f"{lib_name} version {matches[0]} detected - may contain known vulnerabilities",
                        "A03:2025"
                    )
            
            # Check for missing SRI (Subresource Integrity)
            if '<script src=' in response.text and 'integrity=' not in response.text:
                self.add_vulnerability(
                    "Missing Subresource Integrity (SRI)",
                    "Medium",
                    "External scripts loaded without SRI - vulnerable to supply chain attacks",
                    "A03:2025"
                )
                
        except Exception as e:
            print(f"[-] Error checking supply chain: {e}")
    
    def check_cryptographic_failures(self):
        """A04:2025 - Cryptographic Failures"""
        print("[+] Checking A04:2025 - Cryptographic Failures...")
        
        try:
            response = requests.get(self.url, headers=self.headers, timeout=5)
            
            # Check for weak cipher suites
            if 'http://' in self.url:
                self.add_vulnerability(
                    "Unencrypted Data Transmission",
                    "Critical",
                    "Data transmitted without TLS encryption",
                    "A04:2025"
                )
            
            # Look for hardcoded secrets in HTML
            secret_patterns = [
                r'api[_-]?key\s*[=:]\s*["\']([^\"\'\n]+)["\']',
                r'password\s*[=:]\s*["\']([^\"\'\n]+)["\']',
                r'secret\s*[=:]\s*["\']([^\"\'\n]+)["\']',
                r'token\s*[=:]\s*["\']([^\"\'\n]+)["\']'
            ]
            
            for pattern in secret_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    self.add_vulnerability(
                        "Hardcoded Secrets Detected",
                        "Critical",
                        "API keys, passwords, or tokens found in HTML/JavaScript",
                        "A04:2025"
                    )
                    break
            
            # Check for insecure hash algorithms
            if re.search(r'md5|sha1', response.text, re.IGNORECASE):
                self.add_vulnerability(
                    "Weak Hashing Algorithm",
                    "High",
                    "MD5 or SHA-1 hashing detected - use SHA-256 or stronger",
                    "A04:2025"
                )
                
        except Exception as e:
            print(f"[-] Error checking cryptographic failures: {e}")
    
    def check_injection(self):
        """A05:2025 - Injection"""
        print("[+] Checking A05:2025 - Injection...")
        
        try:
            # Test for SQL Injection
            for payload in self.payloads['sql_injection']:
                try:
                    test_url = f"{self.url}?id={payload}"
                    response = requests.get(test_url, headers=self.headers, timeout=3)
                    
                    # Check for SQL error messages
                    sql_errors = ['SQL', 'mysql_', 'ORA-', 'PostgreSQL', 'sqlite']
                    if any(error in response.text for error in sql_errors):
                        self.add_vulnerability(
                            "SQL Injection Vulnerability",
                            "Critical",
                            f"SQL injection detected with payload: {payload}",
                            "A05:2025"
                        )
                        break
                except:
                    pass
            
            # Test for XSS
            for payload in self.payloads['xss']:
                try:
                    test_url = f"{self.url}?search={payload}"
                    response = requests.get(test_url, headers=self.headers, timeout=3)
                    if payload in response.text:
                        self.add_vulnerability(
                            "Cross-Site Scripting (XSS) Vulnerability",
                            "High",
                            f"Reflected XSS detected - payload echoed in response",
                            "A05:2025"
                        )
                        break
                except:
                    pass
            
            # Test for Command Injection
            for payload in self.payloads['command_injection']:
                try:
                    test_url = f"{self.url}?cmd={payload}"
                    response = requests.get(test_url, headers=self.headers, timeout=3)
                    
                    command_indicators = ['root:', 'bin/', 'total', 'drwx']
                    if any(indicator in response.text for indicator in command_indicators):
                        self.add_vulnerability(
                            "Command Injection Vulnerability",
                            "Critical",
                            f"Command injection detected",
                            "A05:2025"
                        )
                        break
                except:
                    pass
                    
        except Exception as e:
            print(f"[-] Error checking injection vulnerabilities: {e}")
    
    def check_insecure_design(self):
        """A06:2025 - Insecure Design"""
        print("[+] Checking A06:2025 - Insecure Design...")
        
        try:
            response = requests.get(self.url, headers=self.headers, timeout=5)
            
            # Check for missing CSRF tokens
            if '<form' in response.text and 'csrf' not in response.text.lower():
                self.add_vulnerability(
                    "Missing CSRF Protection",
                    "High",
                    "Forms do not include CSRF tokens",
                    "A06:2025"
                )
            
            # Check for insecure design patterns
            if 'eval(' in response.text or 'exec(' in response.text:
                self.add_vulnerability(
                    "Use of Dangerous Functions",
                    "Critical",
                    "Code uses eval() or exec() functions - major security risk",
                    "A06:2025"
                )
            
            # Check for missing rate limiting
            self.add_vulnerability(
                "Potential Missing Rate Limiting",
                "Medium",
                "API endpoints may not implement rate limiting",
                "A06:2025"
            )
                
        except Exception as e:
            print(f"[-] Error checking insecure design: {e}")
    
    def check_authentication_failures(self):
        """A07:2025 - Authentication Failures"""
        print("[+] Checking A07:2025 - Authentication Failures...")
        
        try:
            response = requests.get(self.url, headers=self.headers, timeout=5)
            
            # Check for default credentials hints
            if re.search(r'admin|test|demo|guest', response.text, re.IGNORECASE):
                self.add_vulnerability(
                    "Potential Default Credentials",
                    "High",
                    "Application may use default credentials",
                    "A07:2025"
                )
            
            # Check for missing MFA hints
            if 'authenticator' not in response.text.lower() and 'totp' not in response.text.lower():
                self.add_vulnerability(
                    "Missing Multi-Factor Authentication",
                    "High",
                    "No evidence of MFA implementation",
                    "A07:2025"
                )
            
            # Check for session management
            if 'session' not in response.headers.get('Set-Cookie', '').lower():
                self.add_vulnerability(
                    "Weak Session Management",
                    "High",
                    "No secure session cookies detected",
                    "A07:2025"
                )
                
        except Exception as e:
            print(f"[-] Error checking authentication: {e}")
    
    def check_integrity_failures(self):
        """A08:2025 - Software or Data Integrity Failures"""
        print("[+] Checking A08:2025 - Software or Data Integrity Failures...")
        
        try:
            response = requests.get(self.url, headers=self.headers, timeout=5)
            
            # Check for missing integrity verification
            if 'checksum' not in response.text.lower() and 'hash' not in response.text.lower():
                self.add_vulnerability(
                    "No Data Integrity Verification",
                    "Medium",
                    "Data integrity mechanisms not implemented",
                    "A08:2025"
                )
            
            # Check for insecure deserialization
            if 'pickle' in response.text or 'deserialize' in response.text.lower():
                self.add_vulnerability(
                    "Insecure Deserialization",
                    "Critical",
                    "Application uses unsafe deserialization methods",
                    "A08:2025"
                )
                
        except Exception as e:
            print(f"[-] Error checking integrity failures: {e}")
    
    def check_logging_failures(self):
        """A09:2025 - Security Logging and Alerting Failures"""
        print("[+] Checking A09:2025 - Security Logging and Alerting Failures...")
        
        try:
            response = requests.get(self.url, headers=self.headers, timeout=5)
            
            # Check for logging implementation
            if 'log' not in response.text.lower():
                self.add_vulnerability(
                    "Insufficient Security Logging",
                    "Medium",
                    "Application may not implement adequate security logging",
                    "A09:2025"
                )
            
            # Check for error messages revealing information
            if 'error' in response.text.lower() and 'trace' in response.text.lower():
                self.add_vulnerability(
                    "Information Disclosure via Error Messages",
                    "Medium",
                    "Detailed error messages may disclose system information",
                    "A09:2025"
                )
                
        except Exception as e:
            print(f"[-] Error checking logging failures: {e}")
    
    def check_exception_handling(self):
        """A10:2025 - Mishandling of Exceptional Conditions"""
        print("[+] Checking A10:2025 - Mishandling of Exceptional Conditions...")
        
        try:
            # Try to trigger errors
            error_payloads = ['<>', '{{}}', '\"/>', \"';\", '1/0']
            
            for payload in error_payloads:
                try:
                    test_url = f"{self.url}?test={payload}"
                    response = requests.get(test_url, headers=self.headers, timeout=3)
                    
                    # Check for stack traces or detailed errors
                    if response.status_code >= 500:
                        self.add_vulnerability(
                            "Unhandled Exception",
                            "Medium",
                            "Application returns 5xx errors without proper handling",
                            "A10:2025"
                        )
                        break
                except:
                    pass
            
            # Check for generic error pages
            response = requests.get(f"{self.url}/nonexistent", headers=self.headers, timeout=5)
            if response.status_code == 404 and len(response.text) < 100:
                self.add_vulnerability(
                    "Generic Error Handling",
                    "Low",
                    "Application uses generic error pages (could hide issues)",
                    "A10:2025"
                )
                
        except Exception as e:
            print(f"[-] Error checking exception handling: {e}")
    
    def add_vulnerability(self, title: str, severity: str, description: str, owasp_id: str = "Unknown"):
        """Add a vulnerability to the report"""
        self.vulnerabilities.append({
            'title': title,
            'severity': severity,
            'description': description,
            'owasp_id': owasp_id,
            'timestamp': datetime.now().isoformat()
        })
        print(f"  [!] {severity}: {title}")
    
    def generate_report(self) -> Dict:
        """Generate final vulnerability report"""
        severity_count = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for vuln in self.vulnerabilities:
            severity_count[vuln['severity']] += 1
        
        report = {
            'scan_info': {
                'url': self.url,
                'timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities),
                'severity_summary': severity_count
            },
            'vulnerabilities': self.vulnerabilities
        }
        
        return report
    
    def export_html(self, filepath: str):
        """Export report as HTML"""
        report = self.generate_report()
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>VAPT Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .critical {{ background: #ff4444; color: white; }}
                .high {{ background: #ff8800; color: white; }}
                .medium {{ background: #ffbb33; color: black; }}
                .low {{ background: #00c851; color: white; }}
                .vuln-item {{ border: 1px solid #ccc; margin: 10px 0; padding: 10px; }}
                .severity {{ padding: 5px 10px; border-radius: 3px; display: inline-block; }}
            </style>
        </head>
        <body>
            <h1>VAPT Scan Report</h1>
            <p><strong>URL:</strong> {report['scan_info']['url']}</p>
            <p><strong>Scan Time:</strong> {report['scan_info']['timestamp']}</p>
            <h2>Summary</h2>
            <p>Total Vulnerabilities: {report['scan_info']['total_vulnerabilities']}</p>
            <ul>
                <li>Critical: {report['scan_info']['severity_summary']['Critical']}</li>
                <li>High: {report['scan_info']['severity_summary']['High']}</li>
                <li>Medium: {report['scan_info']['severity_summary']['Medium']}</li>
                <li>Low: {report['scan_info']['severity_summary']['Low']}</li>
            </ul>
            <h2>Vulnerabilities</h2>
        """
        
        for vuln in report['vulnerabilities']:
            html += f"""
            <div class="vuln-item">
                <h3>{vuln['title']}</h3>
                <p><span class="severity {vuln['severity'].lower()}">{vuln['severity']}</span></p>
                <p><strong>OWASP:</strong> {vuln['owasp_id']}</p>
                <p>{vuln['description']}</p>
            </div>
            """
        
        html += "</body></html>"
        
        with open(filepath, 'w') as f:
            f.write(html)
        
        print(f"\n[+] HTML report saved to {filepath}")

def main():
    parser = argparse.ArgumentParser(description='VAPT Scanner - Vulnerability Assessment Tool')
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--output', help='Output file path for HTML report')
    
    args = parser.parse_args()
    
    scanner = VAPTScanner(args.url)
    report = scanner.scan()
    
    # Print summary
    print("\n" + "="*50)
    print("SCAN SUMMARY")
    print("="*50)
    print(f"Total Vulnerabilities Found: {report['scan_info']['total_vulnerabilities']}")
    print(f"Critical: {report['scan_info']['severity_summary']['Critical']}")
    print(f"High: {report['scan_info']['severity_summary']['High']}")
    print(f"Medium: {report['scan_info']['severity_summary']['Medium']}")
    print(f"Low: {report['scan_info']['severity_summary']['Low']}")
    
    # Export HTML if requested
    if args.output:
        scanner.export_html(args.output)
    
    # Print JSON report
    print("\n" + json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
