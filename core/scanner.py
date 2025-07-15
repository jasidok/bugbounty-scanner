#!/usr/bin/env python3
"""
Comprehensive Bug Bounty Scanner Tool
A modular framework for automated security testing and vulnerability assessment
Author: Bug Bounty Automation Assistant
Version: 1.0.0
"""

import os
import sys
import json
import yaml
import requests
import subprocess
import argparse
import logging
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, urljoin
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import sqlite3
from jinja2 import Template
import xml.etree.ElementTree as ET

# Rate limiting and ethical scanning
import time
from collections import defaultdict
from threading import Lock

# Third-party libraries for enhanced functionality
try:
    import dns
    from bs4 import BeautifulSoup
    import whois
    import nmap
    import requests_cache
    from scapy.all import *
except ImportError as e:
    print(f"Missing dependencies: {e}")
    print("Install with: pip install -r requirements.txt")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class BugBountyProgram:
    """Structure for bug bounty program information"""
    name: str
    url: str
    scope: List[str]
    out_of_scope: List[str]
    program_type: str  # web, mobile, api, smart_contract
    max_reward: Optional[int] = None
    platform: Optional[str] = None  # hackerone, bugcrowd, etc.
    contact: Optional[str] = None
    policy_url: Optional[str] = None

@dataclass
class ScanResult:
    """Structure for scan results"""
    target: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    recommendations: str
    timestamp: datetime
    confidence: str
    tool_used: str

@dataclass
class ScanConfig:
    """Configuration for scanning parameters"""
    max_threads: int = 10
    delay_between_requests: float = 1.0
    timeout: int = 30
    user_agent: str = "BugBountyScanner/1.0"
    respect_robots: bool = True
    max_depth: int = 3
    rate_limit_per_second: int = 5

class RateLimiter:
    """Rate limiter to ensure ethical scanning"""
    def __init__(self, max_requests_per_second: int = 5):
        self.max_requests = max_requests_per_second
        self.requests = []
        self.lock = Lock()

    def acquire(self):
        with self.lock:
            now = time.time()
            # Remove requests older than 1 second
            self.requests = [req_time for req_time in self.requests if now - req_time < 1.0]

            if len(self.requests) >= self.max_requests:
                sleep_time = 1.0 - (now - self.requests[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    return self.acquire()

            self.requests.append(now)

class ScopeValidator:
    """Validates targets against bug bounty program scope"""
    def __init__(self, program: BugBountyProgram):
        self.program = program
        self.in_scope_patterns = self._compile_patterns(program.scope)
        self.out_of_scope_patterns = self._compile_patterns(program.out_of_scope)

    def _compile_patterns(self, patterns: List[str]) -> List[re.Pattern]:
        """Convert scope patterns to regex patterns"""
        compiled = []
        for pattern in patterns:
            # Convert wildcard patterns to regex
            regex_pattern = pattern.replace('*', '.*').replace('?', '.')
            compiled.append(re.compile(regex_pattern, re.IGNORECASE))
        return compiled

    def is_in_scope(self, target: str) -> bool:
        """Check if target is in scope"""
        # Check if target matches any in-scope pattern
        for pattern in self.in_scope_patterns:
            if pattern.match(target):
                # Check if it's explicitly out of scope
                for out_pattern in self.out_of_scope_patterns:
                    if out_pattern.match(target):
                        return False
                return True
        return False

    def validate_target(self, target: str) -> Dict[str, Any]:
        """Validate target and return detailed information"""
        return {
            'target': target,
            'in_scope': self.is_in_scope(target),
            'program': self.program.name,
            'timestamp': datetime.now().isoformat()
        }

class ProgramParser:
    """Parse bug bounty program information from various sources"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'BugBountyScanner/1.0 (Educational Research)'
        })

    def parse_hackerone_program(self, program_url: str) -> Optional[BugBountyProgram]:
        """Parse HackerOne program page"""
        try:
            response = self.session.get(program_url)
            response.raise_for_status()

            # Basic parsing - in real implementation, use proper HTML parsing
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract program information
            program_name = soup.find('h1', {'class': 'program-title'})
            if program_name:
                program_name = program_name.text.strip()

            # Extract scope information
            scope_elements = soup.find_all('td', {'class': 'scope-item'})
            scope = [elem.text.strip() for elem in scope_elements]

            return BugBountyProgram(
                name=program_name or "Unknown",
                url=program_url,
                scope=scope,
                out_of_scope=[],
                program_type="web",
                platform="hackerone"
            )

        except Exception as e:
            logger.error(f"Failed to parse HackerOne program: {e}")
            return None

    def parse_bugcrowd_program(self, program_url: str) -> Optional[BugBountyProgram]:
        """Parse Bugcrowd program page"""
        try:
            response = self.session.get(program_url)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract scope - simplified example
            scope_section = soup.find('div', {'class': 'target-groups'})
            scope = []
            if scope_section:
                targets = scope_section.find_all('div', {'class': 'target-name'})
                scope = [target.text.strip() for target in targets]

            return BugBountyProgram(
                name="Bugcrowd Program",
                url=program_url,
                scope=scope,
                out_of_scope=[],
                program_type="web",
                platform="bugcrowd"
            )

        except Exception as e:
            logger.error(f"Failed to parse Bugcrowd program: {e}")
            return None

    def parse_program_from_url(self, url: str) -> Optional[BugBountyProgram]:
        """Auto-detect and parse program from URL"""
        if "hackerone.com" in url:
            return self.parse_hackerone_program(url)
        elif "bugcrowd.com" in url:
            return self.parse_bugcrowd_program(url)
        else:
            # Generic parser for other platforms
            return self.parse_generic_program(url)

    def parse_generic_program(self, url: str) -> Optional[BugBountyProgram]:
        """Generic parser for unknown platforms"""
        try:
            response = self.session.get(url)
            response.raise_for_status()

            # Basic extraction logic
            return BugBountyProgram(
                name="Generic Program",
                url=url,
                scope=[urlparse(url).netloc],
                out_of_scope=[],
                program_type="web"
            )

        except Exception as e:
            logger.error(f"Failed to parse generic program: {e}")
            return None

class WebScanner:
    """Web application security scanner"""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.rate_limiter = RateLimiter(config.rate_limit_per_second)
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.user_agent})

    def subdomain_enumeration(self, domain: str) -> List[str]:
        """Enumerate subdomains using multiple techniques"""
        subdomains = set()

        # 1. DNS brute force with common subdomains
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'app', 'dashboard', 'portal', 'secure', 'vpn', 'blog', 'shop',
            'store', 'support', 'help', 'docs', 'cdn', 'static', 'assets'
        ]

        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            if self._resolve_domain(full_domain):
                subdomains.add(full_domain)

        # 2. Certificate transparency logs (simplified)
        ct_subdomains = self._check_certificate_transparency(domain)
        subdomains.update(ct_subdomains)

        # 3. Search engine enumeration
        search_subdomains = self._search_engine_enumeration(domain)
        subdomains.update(search_subdomains)

        return list(subdomains)

    def _resolve_domain(self, domain: str) -> bool:
        """Check if domain resolves"""
        try:
            import socket
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False

    def _check_certificate_transparency(self, domain: str) -> List[str]:
        """Check certificate transparency logs for subdomains"""
        # This would integrate with CT log APIs like crt.sh
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for cert in data:
                    name = cert.get('name_value', '')
                    if name and domain in name:
                        subdomains.add(name.strip())
                return list(subdomains)
        except Exception as e:
            logger.warning(f"Certificate transparency check failed: {e}")
        return []

    def _search_engine_enumeration(self, domain: str) -> List[str]:
        """Use search engines to find subdomains"""
        # This would implement search engine dorking
        # For ethical reasons, this is a placeholder
        return []

    def directory_fuzzing(self, url: str) -> List[str]:
        """Fuzz directories and files"""

# Common directories and files to test
        common_paths = [
            '/admin', '/login', '/dashboard', '/api', '/v1', '/v2',
            '/test', '/dev', '/staging', '/backup', '/config',
            '/wp-admin', '/wp-content', '/wp-includes',
            '/.git', '/.env', '/.htaccess', '/robots.txt',
            '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml'
        ]

        found_paths = []
        for path in common_paths:
            full_url = urljoin(url, path)
            try:
                response = self.session.get(full_url, timeout=self.config.timeout)
                if response.status_code == 200:
                    found_paths.append(full_url)
                    logger.info(f"Found: {full_url}")
            except Exception as e:
                logger.debug(f"Error testing {full_url}: {e}")

            time.sleep(self.config.delay_between_requests)

        return found_paths

    def parameter_discovery(self, url: str) -> List[str]:
        """Discover hidden parameters"""
        # Common parameters to test
        common_params = [
            'id', 'user', 'admin', 'debug', 'test', 'key', 'token',
            'callback', 'jsonp', 'redirect', 'url', 'file', 'path',
            'page', 'action', 'method', 'format', 'type', 'sort'
        ]

        found_params = []
        for param in common_params:
            test_url = f"{url}?{param}=test"
            try:
                self.rate_limiter.acquire()
                response = self.session.get(test_url, timeout=self.config.timeout)
                # Check for different behavior
                if self._check_parameter_response(response):
                    found_params.append(param)
                    logger.info(f"Found parameter: {param}")
            except Exception as e:
                logger.debug(f"Error testing parameter {param}: {e}")

            time.sleep(self.config.delay_between_requests)

        return found_params

    def _check_parameter_response(self, response: requests.Response) -> bool:
        """Check if parameter caused different behavior"""
        # This would implement more sophisticated response analysis
        return len(response.text) > 100  # Simplified check

    def vulnerability_scan(self, url: str) -> List[ScanResult]:
        """Perform vulnerability scanning"""
        results = []

        # Test for common vulnerabilities
        results.extend(self._test_xss(url))
        results.extend(self._test_sql_injection(url))
        results.extend(self._test_open_redirect(url))
        results.extend(self._test_security_headers(url))

        return results

    def _test_xss(self, url: str) -> List[ScanResult]:
        """Test for XSS vulnerabilities"""
        results = []
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "javascript:alert('XSS')",
            '<img src=x onerror=alert("XSS")>'
        ]

        for payload in xss_payloads:
            test_url = f"{url}?test={payload}"
            try:
                self.rate_limiter.acquire()
                response = self.session.get(test_url, timeout=self.config.timeout)
                if payload in response.text:
                    results.append(ScanResult(
                        target=url,
                        vulnerability_type="Cross-Site Scripting (XSS)",
                        severity="Medium",
                        description=f"Potential XSS vulnerability found with payload: {payload}",
                        evidence=f"Payload reflected in response: {payload}",
                        recommendations="Implement proper input validation and output encoding",
                        timestamp=datetime.now(),
                        confidence="Low",
                        tool_used="WebScanner"
                    ))
            except Exception as e:
                logger.debug(f"Error testing XSS payload: {e}")

            time.sleep(self.config.delay_between_requests)

        return results

    def _test_sql_injection(self, url: str) -> List[ScanResult]:
        """Test for SQL injection vulnerabilities"""
        results = []
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "' UNION SELECT NULL--"
        ]

        for payload in sql_payloads:
            test_url = f"{url}?id={payload}"
            try:
                self.rate_limiter.acquire()
                response = self.session.get(test_url, timeout=self.config.timeout)

                # Check for SQL error messages
                sql_errors = [
                    "sql syntax", "mysql", "postgresql", "oracle", "sqlite",
                    "syntax error", "ORA-", "ERROR 1064", "sqlite3.OperationalError"
                ]

                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        results.append(ScanResult(
                            target=url,
                            vulnerability_type="SQL Injection",
                            severity="High",
                            description=f"Potential SQL injection vulnerability found",
                            evidence=f"SQL error message detected: {error}",
                            recommendations="Use parameterized queries and input validation",
                            timestamp=datetime.now(),
                            confidence="Medium",
                            tool_used="WebScanner"
                        ))
                        break

            except Exception as e:
                logger.debug(f"Error testing SQL injection payload: {e}")

            time.sleep(self.config.delay_between_requests)

        return results

    def _test_open_redirect(self, url: str) -> List[ScanResult]:
        """Test for open redirect vulnerabilities"""
        results = []
        redirect_payloads = [
            "http://evil.com",
            "//evil.com",
            "https://evil.com",
            "javascript:alert('redirect')"
        ]

        redirect_params = ['redirect', 'url', 'next', 'return', 'goto']

        for param in redirect_params:
            for payload in redirect_payloads:
                test_url = f"{url}?{param}={payload}"
                try:
                    self.rate_limiter.acquire()
                    response = self.session.get(test_url, timeout=self.config.timeout, allow_redirects=False)

                    if response.status_code in [301, 302, 307, 308]:
                        location = response.headers.get('Location', '')
                        if payload in location:
                            results.append(ScanResult(
                                target=url,
                                vulnerability_type="Open Redirect",
                                severity="Medium",
                                description=f"Open redirect vulnerability found in parameter: {param}",
                                evidence=f"Redirect to: {location}",
                                recommendations="Validate redirect URLs against a whitelist",
                                timestamp=datetime.now(),
                                confidence="High",
                                tool_used="WebScanner"
                            ))

                except Exception as e:
                    logger.debug(f"Error testing open redirect: {e}")

                time.sleep(self.config.delay_between_requests)

        return results

    def _test_security_headers(self, url: str) -> List[ScanResult]:
        """Test for missing security headers"""
        results = []
        try:
            self.rate_limiter.acquire()
            response = self.session.get(url, timeout=self.config.timeout)

            # Check for important security headers
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=',
                'Content-Security-Policy': 'default-src',
                'Referrer-Policy': 'strict-origin'
            }

            for header, expected in security_headers.items():
                if header not in response.headers:
                    results.append(ScanResult(
                        target=url,
                        vulnerability_type="Missing Security Header",
                        severity="Low",
                        description=f"Missing security header: {header}",
                        evidence=f"Header {header} not present in response",
                        recommendations=f"Add {header} header to improve security",
                        timestamp=datetime.now(),
                        confidence="High",
                        tool_used="WebScanner"
                    ))

        except Exception as e:
            logger.debug(f"Error testing security headers: {e}")

        return results

class SmartContractScanner:
    """Smart contract security scanner with false positive verification"""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.common_vulnerabilities = self._load_vulnerability_patterns()
        # Import the enhanced scanner
        try:
            from modules.smart_contract_verification import EnhancedSmartContractScanner
            self.enhanced_scanner = EnhancedSmartContractScanner(config)
            self.use_enhanced = True
        except ImportError:
            logger.warning("Enhanced smart contract scanner not available, using basic scanner")
            self.use_enhanced = False

    def _load_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Load common vulnerability patterns for smart contracts"""
        return {
            "reentrancy": [
                r"\.call\.value\(",
                r"\.transfer\(",
                r"\.send\("
            ],
            "integer_overflow": [
                r"[+-]\s*\d+",
                r"SafeMath",
                r"unchecked"
            ],
            "unprotected_functions": [
                r"function.*public.*{",
                r"function.*external.*{"
            ],
            "access_control": [
                r"onlyOwner",
                r"require\(.*owner",
                r"modifier.*only"
            ]
        }

    def scan_solidity_file(self, file_path: str) -> List[ScanResult]:
        """Scan Solidity smart contract file with enhanced verification"""
        results = []

        try:
            # Use enhanced scanner if available
            if self.use_enhanced:
                enhanced_results = self.enhanced_scanner.scan_solidity_file_enhanced(file_path)
                # Convert enhanced results to ScanResult format
                for result in enhanced_results:
                    scan_result = ScanResult(
                        target=result['target'],
                        vulnerability_type=result['vulnerability_type'],
                        severity=result['severity'],
                        description=result['description'],
                        evidence=result['evidence'],
                        recommendations=self._get_recommendations(result['vulnerability_type']),
                        timestamp=datetime.now(),
                        confidence=f"High (Verified: {result.get('confidence', 0.5):.2f})",
                        tool_used="EnhancedSmartContractScanner"
                    )
                    results.append(scan_result)
                
                logger.info(f"Enhanced scanner found {len(results)} verified vulnerabilities in {file_path}")
                return results
            
            # Fallback to basic scanner
            with open(file_path, 'r') as file:
                content = file.read()

            # Analyze for common vulnerabilities (basic)
            results.extend(self._check_reentrancy(content, file_path))
            results.extend(self._check_integer_overflow(content, file_path))
            results.extend(self._check_access_control(content, file_path))
            results.extend(self._check_gas_optimization(content, file_path))

        except Exception as e:
            logger.error(f"Error scanning Solidity file {file_path}: {e}")

        return results
    
    def _get_recommendations(self, vuln_type: str) -> str:
        """Get specific recommendations for vulnerability types"""
        recommendations = {
            'Reentrancy': 'Implement ReentrancyGuard from OpenZeppelin or use checks-effects-interactions pattern',
            'Integer Overflow': 'Use Solidity 0.8.0+ with built-in overflow protection or SafeMath library',
            'Missing Access Control': 'Add appropriate access control modifiers (onlyOwner, role-based access)',
            'Potential Fund Loss': 'Use SafeERC20 for token transfers and implement proper validation',
            'Gas Optimization': 'Review loops and state variables for gas efficiency'
        }
        return recommendations.get(vuln_type, 'Review code for security best practices')

    def _check_reentrancy(self, content: str, file_path: str) -> List[ScanResult]:
        """Check for reentrancy vulnerabilities"""
        results = []

        # Look for external calls before state changes
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if re.search(r'\.call\.value\(|\.transfer\(|\.send\(', line):
                # Check if state changes happen after external call
                for j in range(i+1, min(i+10, len(lines))):
                    if re.search(r'=.*[+-]|balance.*=', lines[j]):
                        results.append(ScanResult(
                            target=file_path,
                            vulnerability_type="Reentrancy",
                            severity="High",
                            description=f"Potential reentrancy vulnerability at line {i+1}",
                            evidence=f"External call followed by state change: {line.strip()}",
                            recommendations="Use checks-effects-interactions pattern or reentrancy guard",
                            timestamp=datetime.now(),
                            confidence="Medium",
                            tool_used="SmartContractScanner"
                        ))
                        break

        return results

    def _check_integer_overflow(self, content: str, file_path: str) -> List[ScanResult]:
        """Check for integer overflow vulnerabilities"""
        results = []

        # Check if SafeMath is used
        if "SafeMath" not in content and "unchecked" not in content:
            # Look for arithmetic operations
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if re.search(r'[+-]\s*\d+|[*/]\s*\d+', line) and 'uint' in line:
                    results.append(ScanResult(
                        target=file_path,
                        vulnerability_type="Integer Overflow",
                        severity="Medium",
                        description=f"Potential integer overflow at line {i+1}",
                        evidence=f"Arithmetic operation without SafeMath: {line.strip()}",
                        recommendations="Use SafeMath library or Solidity 0.8.0+ built-in overflow protection",
                        timestamp=datetime.now(),
                        confidence="Low",
                        tool_used="SmartContractScanner"
                    ))

        return results

    def _check_access_control(self, content: str, file_path: str) -> List[ScanResult]:
        """Check for access control issues"""
        results = []

        # Look for public/external functions without access control
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if re.search(r'function.*public|function.*external', line):
                # Check if function has access control
                function_block = '\n'.join(lines[i:i+20])
                if not re.search(r'onlyOwner|require.*owner|modifier.*only', function_block):
                    results.append(ScanResult(
                        target=file_path,
                        vulnerability_type="Missing Access Control",
                        severity="Medium",
                        description=f"Public/external function without access control at line {i+1}",
                        evidence=f"Function declaration: {line.strip()}",
                        recommendations="Add appropriate access control modifiers",
                        timestamp=datetime.now(),
                        confidence="Low",
                        tool_used="SmartContractScanner"
                    ))

        return results

    def _check_gas_optimization(self, content: str, file_path: str) -> List[ScanResult]:
        """Check for gas optimization opportunities"""
        results = []

        # Look for loops that could be gas-expensive
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if re.search(r'for\s*\(|while\s*\(', line):
                results.append(ScanResult(
                    target=file_path,
                    vulnerability_type="Gas Optimization",
                    severity="Info",
                    description=f"Potential gas optimization opportunity at line {i+1}",
                    evidence=f"Loop detected: {line.strip()}",
                    recommendations="Review loop for gas optimization opportunities",
                    timestamp=datetime.now(),
                    confidence="Low",
                    tool_used="SmartContractScanner"
                ))

        return results

class APIScanner:
    """API security scanner"""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.rate_limiter = RateLimiter(config.rate_limit_per_second)
        self.session = requests.Session()

    def discover_endpoints(self, base_url: str) -> List[str]:
        """Discover API endpoints"""
        endpoints = []

        # Common API endpoint patterns
        common_endpoints = [
            '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/graphql', '/swagger',
            '/openapi.json', '/api-docs',
            '/users', '/auth', '/login', '/register',
            '/admin', '/status', '/health'
        ]

        for endpoint in common_endpoints:
            url = urljoin(base_url, endpoint)
            try:
                self.rate_limiter.acquire()
                response = self.session.get(url, timeout=self.config.timeout)
                if response.status_code == 200:
                    endpoints.append(url)
                    logger.info(f"Found API endpoint: {url}")
            except Exception as e:
                logger.debug(f"Error testing endpoint {url}: {e}")

            time.sleep(self.config.delay_between_requests)

        return endpoints

    def test_authentication(self, endpoint: str) -> List[ScanResult]:
        """Test API authentication mechanisms"""
        results = []

        # Test without authentication
        try:
            self.rate_limiter.acquire()
            response = self.session.get(endpoint, timeout=self.config.timeout)

            if response.status_code == 200:
                results.append(ScanResult(
                    target=endpoint,
                    vulnerability_type="Missing Authentication",
                    severity="High",
                    description="API endpoint accessible without authentication",
                    evidence=f"HTTP {response.status_code} response received",
                    recommendations="Implement proper authentication mechanisms",
                    timestamp=datetime.now(),
                    confidence="High",
                    tool_used="APIScanner"
                ))
        except Exception as e:
            logger.debug(f"Error testing authentication: {e}")

        # Test with common weak tokens
        weak_tokens = ['admin', 'test', '123456', 'token', 'guest']
        for token in weak_tokens:
            try:
                self.rate_limiter.acquire()
                headers = {'Authorization': f'Bearer {token}'}
                response = self.session.get(endpoint, headers=headers, timeout=self.config.timeout)

                if response.status_code == 200:
                    results.append(ScanResult(
                        target=endpoint,
                        vulnerability_type="Weak Authentication",
                        severity="High",
                        description=f"API accessible with weak token: {token}",
                        evidence=f"HTTP {response.status_code} with token: {token}",
                        recommendations="Use strong, randomly generated tokens",
                        timestamp=datetime.now(),
                        confidence="High",
                        tool_used="APIScanner"
                    ))
            except Exception as e:
                logger.debug(f"Error testing weak token: {e}")

            time.sleep(self.config.delay_between_requests)

        return results

    def test_rate_limiting(self, endpoint: str) -> List[ScanResult]:
        """Test API rate limiting"""
        results = []

        try:
            # Send multiple requests quickly
            responses = []
            for i in range(20):
                response = self.session.get(endpoint, timeout=self.config.timeout)
                responses.append(response.status_code)

            # Check if rate limiting is implemented
            if all(code == 200 for code in responses):
                results.append(ScanResult(
                    target=endpoint,
                    vulnerability_type="Missing Rate Limiting",
                    severity="Medium",
                    description="API endpoint lacks rate limiting",
                    evidence=f"20 consecutive requests all returned 200",
                    recommendations="Implement rate limiting to prevent abuse",
                    timestamp=datetime.now(),
                    confidence="High",
                    tool_used="APIScanner"
                ))

        except Exception as e:
            logger.debug(f"Error testing rate limiting: {e}")

        return results

class MobileAppScanner:
    """Mobile application security scanner"""

    def __init__(self, config: ScanConfig):
        self.config = config

    def analyze_apk(self, apk_path: str) -> List[ScanResult]:
        """Analyze Android APK file"""
        results = []

        try:
            # Extract APK information
            manifest_info = self._extract_manifest(apk_path)
            results.extend(self._analyze_manifest(manifest_info, apk_path))

            # Static analysis
            results.extend(self._static_analysis(apk_path))

        except Exception as e:
            logger.error(f"Error analyzing APK {apk_path}: {e}")

        return results

    def _extract_manifest(self, apk_path: str) -> Dict[str, Any]:
        """Extract AndroidManifest.xml information"""
        # This would use tools like aapt or androguard
        # Placeholder implementation
        return {
            'package': 'com.example.app',
            'permissions': ['android.permission.INTERNET'],
            'activities': ['MainActivity'],
            'min_sdk': 21,
            'target_sdk': 30
        }

    def _analyze_manifest(self, manifest: Dict[str, Any], apk_path: str) -> List[ScanResult]:
        """Analyze AndroidManifest.xml for security issues"""
        results = []

        # Check for dangerous permissions
        dangerous_permissions = [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.RECORD_AUDIO',
            'android.permission.CAMERA'
        ]

        for permission in manifest.get('permissions', []):
            if permission in dangerous_permissions:
                results.append(ScanResult(
                    target=apk_path,
                    vulnerability_type="Dangerous Permission",
                    severity="Medium",
                    description=f"App requests dangerous permission: {permission}",
                    evidence=f"Permission found in manifest: {permission}",
                    recommendations="Review if this permission is necessary",
                    timestamp=datetime.now(),
                    confidence="High",
                    tool_used="MobileAppScanner"
                ))

        # Check for exported activities
        if 'activities' in manifest:
            for activity in manifest['activities']:
                if activity.get('exported', False):
                    results.append(ScanResult(
                        target=apk_path,
                        vulnerability_type="Exported Activity",
                        severity="Medium",
                        description=f"Activity is exported: {activity['name']}",
                        evidence=f"android:exported=true for {activity['name']}",
                        recommendations="Review if activity should be exported",
                        timestamp=datetime.now(),
                        confidence="High",
                        tool_used="MobileAppScanner"
                    ))

        return results

    def _static_analysis(self, apk_path: str) -> List[ScanResult]:
        """Perform static analysis on APK"""
        results = []

        # This would decompile the APK and analyze the code
        # Look for hardcoded secrets, insecure crypto, etc.

        # Placeholder for hardcoded secrets detection
        results.append(ScanResult(
            target=apk_path,
            vulnerability_type="Hardcoded Secret",
            severity="High",
            description="Potential hardcoded API key found",
            evidence="String containing 'API_KEY' found in code",
            recommendations="Use secure storage for API keys",
            timestamp=datetime.now(),
            confidence="Medium",
            tool_used="MobileAppScanner"
        ))

        return results

    def analyze_ipa(self, ipa_path: str) -> List[ScanResult]:
        """Analyze iOS IPA file"""
        results = []

        try:
            # Extract and analyze iOS app
            plist_info = self._extract_plist(ipa_path)
            results.extend(self._analyze_plist(plist_info, ipa_path))

        except Exception as e:
            logger.error(f"Error analyzing IPA {ipa_path}: {e}")

        return results

    def _extract_plist(self, ipa_path: str) -> Dict[str, Any]:
        """Extract Info.plist information"""
        # This would extract and parse the Info.plist file
        return {
            'bundle_id': 'com.example.app',
            'version': '1.0.0',
            'min_os_version': '12.0'
        }

    def _analyze_plist(self, plist: Dict[str, Any], ipa_path: str) -> List[ScanResult]:
        """Analyze Info.plist for security issues"""
        results = []

        # Check for insecure configurations
        if not plist.get('NSAppTransportSecurity', {}).get('NSAllowsArbitraryLoads', False):
            results.append(ScanResult(
                target=ipa_path,
                vulnerability_type="Insecure Network Configuration",
                severity="Medium",
                description="App allows arbitrary network loads",
                evidence="NSAllowsArbitraryLoads is enabled",
                recommendations="Disable arbitrary loads and use HTTPS",
                timestamp=datetime.now(),
                confidence="High",
                tool_used="MobileAppScanner"
            ))

        return results

class ProjectManager:
    """Manages bug bounty project organization"""

    def __init__(self, base_dir: str = "./bb_projects"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)

    def create_project(self, program: BugBountyProgram) -> str:
        """Create organized project structure"""
        project_name = re.sub(r'[^a-zA-Z0-9_-]', '_', program.name)
        project_dir = self.base_dir / project_name
        project_dir.mkdir(exist_ok=True)

        # Create subdirectories
        directories = [
            'scope', 'tools', 'results', 'reports', 'evidence',
            'notes', 'recon', 'vulnerabilities', 'payloads'
        ]

        for directory in directories:
            (project_dir / directory).mkdir(exist_ok=True)

        # Create project configuration
        config_file = project_dir / 'project.json'
        with open(config_file, 'w') as f:
            json.dump(asdict(program), f, indent=2, default=str)

        # Create README
        readme_content = f"""# Bug Bounty Project: {program.name}

## Program Information
- **URL**: {program.url}
- **Type**: {program.program_type}
- **Platform**: {program.platform}

## Scope
{chr(10).join(f'- {item}' for item in program.scope)}

## Out of Scope
{chr(10).join(f'- {item}' for item in program.out_of_scope)}

## Project Structure
- `scope/` - Target scope documentation
- `tools/` - Custom tools and scripts
- `results/` - Scan results and findings
- `reports/` - Final reports and submissions
- `evidence/` - Screenshots and proof of concepts
- `notes/` - Research notes and methodology
- `recon/` - Reconnaissance data
- `vulnerabilities/` - Confirmed vulnerabilities
- `payloads/` - Custom payloads and exploits

## Getting Started
1. Review the scope carefully
2. Run initial reconnaissance
3. Document all findings
4. Follow responsible disclosure

## Important Notes
- Always stay within scope
- Respect rate limits
- Follow the program's responsible disclosure policy
- Document everything thoroughly
"""

        with open(project_dir / 'README.md', 'w') as f:
            f.write(readme_content)

        logger.info(f"Created project directory: {project_dir}")
        return str(project_dir)

    def save_results(self, project_dir: str, results: List[ScanResult]):
        """Save scan results to project"""
        results_dir = Path(project_dir) / 'results'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Save as JSON
        json_file = results_dir / f'scan_results_{timestamp}.json'
        with open(json_file, 'w') as f:
            json.dump([asdict(result) for result in results], f, indent=2, default=str)

        # Save as CSV
        csv_file = results_dir / f'scan_results_{timestamp}.csv'
        with open(csv_file, 'w') as f:
            if results:
                headers = list(asdict(results[0]).keys())
                f.write(','.join(headers) + '\n')
                for result in results:
                    row = [str(v) for v in asdict(result).values()]
                    f.write(','.join(row) + '\n')

        logger.info(f"Saved {len(results)} results to {results_dir}")

class ReportGenerator:
    """Generate professional bug bounty reports"""

    def __init__(self):
        self.templates = self._load_templates()

    def _load_templates(self) -> Dict[str, str]:
        """Load report templates"""
        return {
            'vulnerability_report': '''
# Vulnerability Report

## Summary
**Vulnerability Type**: {{vulnerability_type}}
**Severity**: {{severity}}
**Target**: {{target}}
**Confidence**: {{confidence}}

## Description
{{description}}

## Evidence
{{evidence}}

## Proof of Concept
{{proof_of_concept}}

## Impact
{{impact}}

## Remediation
{{recommendations}}

## Timeline
- **Discovered**: {{timestamp}}
- **Reported**: {{report_date}}

## Additional Information
{{additional_info}}
''',
            'executive_summary': '''
# Executive Summary

## Project Overview
- **Program**: {{program_name}}
- **Scope**: {{scope_count}} targets
- **Duration**: {{duration}}
- **Tools Used**: {{tools_used}}

## Key Findings
- **Critical**: {{critical_count}}
- **High**: {{high_count}}
- **Medium**: {{medium_count}}
- **Low**: {{low_count}}
- **Info**: {{info_count}}

## Recommendations
{{recommendations}}

## Detailed Findings
{{detailed_findings}}
'''
        }

    def generate_vulnerability_report(self, result: ScanResult) -> str:
        """Generate vulnerability report"""
        template = Template(self.templates['vulnerability_report'])
        return template.render(
            vulnerability_type=result.vulnerability_type,
            severity=result.severity,
            target=result.target,
            confidence=result.confidence,
            description=result.description,
            evidence=result.evidence,
            proof_of_concept="To be added",
            impact=self._get_impact_description(result.severity),
            recommendations=result.recommendations,
            timestamp=result.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            report_date=datetime.now().strftime('%Y-%m-%d'),
            additional_info=f"Detected by: {result.tool_used}"
        )

    def _get_impact_description(self, severity: str) -> str:
        """Get impact description based on severity"""
        impacts = {
            'Critical': 'This vulnerability could lead to complete system compromise',
            'High': 'This vulnerability could lead to significant data exposure or system access',
            'Medium': 'This vulnerability could lead to limited data exposure or functionality bypass',
            'Low': 'This vulnerability has minimal impact but should be addressed',
            'Info': 'This is an informational finding that may assist in security improvement'
        }
        return impacts.get(severity, 'Impact assessment required')

    def generate_executive_summary(self, results: List[ScanResult], program: BugBountyProgram) -> str:
        """Generate executive summary report"""
        severity_counts = defaultdict(int)
        for result in results:
            severity_counts[result.severity] += 1

        tools_used = list(set(result.tool_used for result in results))

        template = Template(self.templates['executive_summary'])
        return template.render(
            program_name=program.name,
            scope_count=len(program.scope),
            duration="Testing period",
            tools_used=', '.join(tools_used),
            critical_count=severity_counts['Critical'],
            high_count=severity_counts['High'],
            medium_count=severity_counts['Medium'],
            low_count=severity_counts['Low'],
            info_count=severity_counts['Info'],
            recommendations=self._generate_recommendations(results),
            detailed_findings=self._generate_detailed_findings(results)
        )

    def _generate_recommendations(self, results: List[ScanResult]) -> str:
        """Generate overall recommendations"""
        recommendations = set()
        for result in results:
            recommendations.add(result.recommendations)

        return '\n'.join(f"- {rec}" for rec in sorted(recommendations))

    def _generate_detailed_findings(self, results: List[ScanResult]) -> str:
        """Generate detailed findings section"""
        findings = []
        for result in results:
            findings.append(f"## {result.vulnerability_type} - {result.severity}")
            findings.append(f"**Target**: {result.target}")
            findings.append(f"**Description**: {result.description}")
            findings.append(f"**Recommendation**: {result.recommendations}")
            findings.append("")

        return '\n'.join(findings)

class BugBountyScanner:
    """Main bug bounty scanner orchestrator"""

    def __init__(self, config: ScanConfig = None):
        self.config = config or ScanConfig()
        self.parser = ProgramParser()
        self.project_manager = ProjectManager()
        self.report_generator = ReportGenerator()
        self.db_path = "bug_bounty_scanner.db"
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database for storing results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                vulnerability_type TEXT,
                severity TEXT,
                description TEXT,
                evidence TEXT,
                recommendations TEXT,
                timestamp DATETIME,
                confidence TEXT,
                tool_used TEXT,
                program_name TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS programs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                url TEXT,
                scope TEXT,
                out_of_scope TEXT,
                program_type TEXT,
                platform TEXT,
                created_at DATETIME
            )
        ''')

        conn.commit()
        conn.close()

    def scan_program(self, program_url: str, scan_types: List[str] = None) -> Dict[str, Any]:
        """Main scanning function"""
        # Parse the bug bounty program
        program = self.parser.parse_program_from_url(program_url)
        if not program:
            return {"error": "Failed to parse bug bounty program"}

        # Create project structure
        project_dir = self.project_manager.create_project(program)

        # Initialize scope validator
        scope_validator = ScopeValidator(program)

        # Determine scan types
        if scan_types is None:
            scan_types = ['web', 'api']  # Default scan types

        all_results = []

        # Perform scans based on program type and requested scans
        for target in program.scope:
            if not scope_validator.is_in_scope(target):
                logger.warning(f"Target {target} is not in scope, skipping")
                continue

            logger.info(f"Scanning target: {target}")

            if 'web' in scan_types:
                web_scanner = WebScanner(self.config)
                results = self._scan_web_target(web_scanner, target)
                all_results.extend(results)

            if 'api' in scan_types:
                api_scanner = APIScanner(self.config)
                results = self._scan_api_target(api_scanner, target)
                all_results.extend(results)

            if 'smart_contract' in scan_types:
                sc_scanner = SmartContractScanner(self.config)
                results = self._scan_smart_contract_target(sc_scanner, target)
                all_results.extend(results)

        # Save results
        self.project_manager.save_results(project_dir, all_results)
        self._save_to_database(all_results, program)

        # Generate reports
        reports = self._generate_reports(all_results, program, project_dir)

        return {
            "program": asdict(program),
            "project_dir": project_dir,
            "results_count": len(all_results),
            "severity_breakdown": self._get_severity_breakdown(all_results),
            "reports": reports
        }

    def _scan_web_target(self, scanner: WebScanner, target: str) -> List[ScanResult]:
        """Scan web target"""
        results = []

        # Ensure target is a valid URL
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        try:
            # Subdomain enumeration
            domain = urlparse(target).netloc
            subdomains = scanner.subdomain_enumeration(domain)
            logger.info(f"Found {len(subdomains)} subdomains for {domain}")

            # Scan main target and subdomains
            targets_to_scan = [target] + [f"https://{sub}" for sub in subdomains[:5]]  # Limit to first 5

            for url in targets_to_scan:
                # Directory fuzzing
                directories = scanner.directory_fuzzing(url)

                # Parameter discovery
                parameters = scanner.parameter_discovery(url)

                # Vulnerability scanning
                vuln_results = scanner.vulnerability_scan(url)
                results.extend(vuln_results)

        except Exception as e:
            logger.error(f"Error scanning web target {target}: {e}")

        return results

    def _scan_api_target(self, scanner: APIScanner, target: str) -> List[ScanResult]:
        """Scan API target"""
        results = []

        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        try:
            # Discover API endpoints
            endpoints = scanner.discover_endpoints(target)

            # Test each endpoint
            for endpoint in endpoints:
                # Test authentication
                auth_results = scanner.test_authentication(endpoint)
                results.extend(auth_results)

                # Test rate limiting
                rate_results = scanner.test_rate_limiting(endpoint)
                results.extend(rate_results)

        except Exception as e:
            logger.error(f"Error scanning API target {target}: {e}")

        return results

    def _scan_smart_contract_target(self, scanner: SmartContractScanner, target: str) -> List[ScanResult]:
        """Scan smart contract target (file, directory, or GitHub URL)"""
        results = []

        try:
            # If target is a GitHub URL, extract domain for directory scanning
            if "github.com" in target:
                # Look for local clone in current directory
                repo_name = target.split('/')[-1]
                if os.path.isdir(repo_name):
                    logger.info(f"Scanning local repository: {repo_name}")
                    results = self._scan_directory_recursive(scanner, repo_name)
                else:
                    logger.info(f"Smart contract scanning for GitHub URL {target} requires local clone")
                    
            # If target is a directory
            elif os.path.isdir(target):
                results = self._scan_directory_recursive(scanner, target)
                
            # If target is a file path
            elif os.path.isfile(target):
                results = scanner.scan_solidity_file(target)
            else:
                # If target is a contract address, this would fetch the contract
                logger.info(f"Smart contract scanning for {target} not implemented yet")

        except Exception as e:
            logger.error(f"Error scanning smart contract target {target}: {e}")

        return results
    
    def _scan_directory_recursive(self, scanner: SmartContractScanner, directory: str) -> List[ScanResult]:
        """Recursively scan directory for Solidity files"""
        results = []
        
        # Find all .sol files
        sol_files = []
        for root, dirs, files in os.walk(directory):
            # Skip common directories that shouldn't contain contracts
            dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'lib', 'cache']]
            
            for file in files:
                if file.endswith('.sol'):
                    sol_files.append(os.path.join(root, file))
        
        logger.info(f"Found {len(sol_files)} Solidity files in {directory}")
        
        # Scan each file
        for sol_file in sol_files:
            try:
                file_results = scanner.scan_solidity_file(sol_file)
                results.extend(file_results)
                logger.info(f"Scanned {sol_file}: {len(file_results)} findings")
            except Exception as e:
                logger.warning(f"Error scanning {sol_file}: {e}")
        
        return results

    def _save_to_database(self, results: List[ScanResult], program: BugBountyProgram):
        """Save results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Save program
        cursor.execute('''
            INSERT INTO programs (name, url, scope, out_of_scope, program_type, platform, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            program.name, program.url, json.dumps(program.scope),
            json.dumps(program.out_of_scope), program.program_type,
            program.platform, datetime.now()
        ))

        # Save results
        for result in results:
            cursor.execute('''
                INSERT INTO scan_results (
                    target, vulnerability_type, severity, description, evidence,
                    recommendations, timestamp, confidence, tool_used, program_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.target, result.vulnerability_type, result.severity,
                result.description, result.evidence, result.recommendations,
                result.timestamp, result.confidence, result.tool_used, program.name
            ))

        conn.commit()
        conn.close()

    def _generate_reports(self, results: List[ScanResult], program: BugBountyProgram, project_dir: str) -> Dict[str, str]:
        """Generate various reports"""
        reports = {}
        reports_dir = Path(project_dir) / 'reports'

        # Executive summary
        exec_summary = self.report_generator.generate_executive_summary(results, program)
        exec_file = reports_dir / 'executive_summary.md'
        with open(exec_file, 'w') as f:
            f.write(exec_summary)
        reports['executive_summary'] = str(exec_file)

        # Individual vulnerability reports
        vuln_reports = []
        for i, result in enumerate(results):
            vuln_report = self.report_generator.generate_vulnerability_report(result)
            vuln_file = reports_dir / f'vulnerability_{i+1}.md'
            with open(vuln_file, 'w') as f:
                f.write(vuln_report)
            vuln_reports.append(str(vuln_file))

        reports['vulnerability_reports'] = vuln_reports

        return reports

    def _get_severity_breakdown(self, results: List[ScanResult]) -> Dict[str, int]:
        """Get breakdown of findings by severity"""
        breakdown = defaultdict(int)
        for result in results:
            breakdown[result.severity] += 1
        return dict(breakdown)

    def list_programs(self) -> List[Dict[str, Any]]:
        """List all scanned programs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM programs ORDER BY created_at DESC')
        programs = cursor.fetchall()

        conn.close()

        return [
            {
                'id': p[0], 'name': p[1], 'url': p[2], 'scope': json.loads(p[3]),
                'out_of_scope': json.loads(p[4]), 'program_type': p[5],
                'platform': p[6], 'created_at': p[7]
            }
            for p in programs
        ]

    def get_results(self, program_name: str = None) -> List[Dict[str, Any]]:
        """Get scan results, optionally filtered by program"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if program_name:
            cursor.execute(
                'SELECT * FROM scan_results WHERE program_name = ? ORDER BY timestamp DESC',
                (program_name,)
            )
        else:
            cursor.execute('SELECT * FROM scan_results ORDER BY timestamp DESC')

        results = cursor.fetchall()
        conn.close()

        return [
            {
                'id': r[0], 'target': r[1], 'vulnerability_type': r[2],
                'severity': r[3], 'description': r[4], 'evidence': r[5],
                'recommendations': r[6], 'timestamp': r[7], 'confidence': r[8],
                'tool_used': r[9], 'program_name': r[10]
            }
            for r in results
        ]

def create_requirements_file():
    """Create requirements.txt file"""
    requirements = """
requests>=2.28.0
beautifulsoup4>=4.11.0
pyyaml>=6.0
jinja2>=3.1.0
dnspython>=2.2.0
python-whois>=0.7.0
python-nmap>=0.7.1
requests-cache>=0.9.0
scapy>=2.4.5
colorama>=0.4.4
rich>=12.0.0
typer>=0.7.0
"""
    with open('requirements.txt', 'w') as f:
        f.write(requirements.strip())
    print("Created requirements.txt")

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description='Comprehensive Bug Bounty Scanner')
    parser.add_argument('--program-url', required=True, help='Bug bounty program URL')
    parser.add_argument('--scan-types', nargs='+', default=['web', 'api'],
                       choices=['web', 'api', 'smart_contract', 'mobile'],
                       help='Types of scans to perform')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests')
    parser.add_argument('--rate-limit', type=int, default=5, help='Requests per second')
    parser.add_argument('--output', help='Output directory')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--create-requirements', action='store_true', help='Create requirements.txt')

    args = parser.parse_args()

    if args.create_requirements:
        create_requirements_file()
        return

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create scanner configuration
    config = ScanConfig(
        max_threads=args.threads,
        delay_between_requests=args.delay,
        rate_limit_per_second=args.rate_limit
    )

    # Initialize scanner
    scanner = BugBountyScanner(config)

    # Perform scan
    logger.info(f"Starting scan of program: {args.program_url}")
    results = scanner.scan_program(args.program_url, args.scan_types)

    if "error" in results:
        logger.error(f"Scan failed: {results['error']}")
        return

    # Display results
    print(f"\n{'='*60}")
    print(f"SCAN RESULTS")
    print(f"{'='*60}")
    print(f"Program: {results['program']['name']}")
    print(f"Total Findings: {results['results_count']}")
    print(f"Project Directory: {results['project_dir']}")
    print(f"\nSeverity Breakdown:")
    for severity, count in results['severity_breakdown'].items():
        print(f"  {severity}: {count}")

    print(f"\nReports Generated:")
    for report_type, report_path in results['reports'].items():
        if isinstance(report_path, list):
            print(f"  {report_type}: {len(report_path)} files")
        else:
            print(f"  {report_type}: {report_path}")

    print(f"\n{'='*60}")
    print("Scan completed successfully!")
    print("Remember to:")
    print("1. Review all findings carefully")
    print("2. Verify vulnerabilities before reporting")
    print("3. Follow responsible disclosure practices")
    print("4. Stay within the program's scope")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()