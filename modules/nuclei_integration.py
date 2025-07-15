"""
Nuclei Templates Integration for Bug Bounty Scanner
Integrates with Nuclei for comprehensive vulnerability scanning
"""

import subprocess
import json
import os
from pathlib import Path
from typing import List, Dict, Any
import yaml

class NucleiIntegration:
    """Integration with Nuclei vulnerability scanner"""

    def __init__(self, nuclei_path: str = "nuclei"):
        self.nuclei_path = nuclei_path
        self.templates_dir = Path.home() / "nuclei-templates"
        self.custom_templates_dir = Path("./custom_templates")
        self.custom_templates_dir.mkdir(exist_ok=True)

    def update_templates(self):
        """Update Nuclei templates"""
        try:
            result = subprocess.run([
                self.nuclei_path, "-update-templates"
            ], capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"Failed to update templates: {e}")
            return False

    def scan_target(self, target: str, severity: List[str] = None,
                   tags: List[str] = None) -> List[Dict[str, Any]]:
        """Scan target with Nuclei"""
        cmd = [
            self.nuclei_path,
            "-target", target,
            "-json",
            "-silent"
        ]

        if severity:
            cmd.extend(["-severity", ",".join(severity)])

        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                # Parse JSON output
                results = []
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                return results
        except Exception as e:
            print(f"Nuclei scan failed: {e}")

        return []

    def create_custom_template(self, template_data: Dict[str, Any]) -> str:
        """Create custom Nuclei template"""
        template_name = template_data.get('id', 'custom-template')
        template_file = self.custom_templates_dir / f"{template_name}.yaml"

        with open(template_file, 'w') as f:
            yaml.dump(template_data, f, default_flow_style=False)

        return str(template_file)

    def get_template_for_vulnerability(self, vuln_type: str) -> Dict[str, Any]:
        """Get template structure for common vulnerability types"""
        templates = {
            "xss": {
                "id": "custom-xss-test",
                "info": {
                    "name": "Custom XSS Test",
                    "author": "bug-bounty-scanner",
                    "severity": "medium",
                    "tags": ["xss", "injection"]
                },
                "requests": [{
                    "method": "GET",
                    "path": ["{{BaseURL}}/?param=<script>alert('XSS')</script>"],
                    "matchers": [{
                        "type": "word",
                        "words": ["<script>alert('XSS')</script>"],
                        "part": "body"
                    }]
                }]
            },
            "sql_injection": {
                "id": "custom-sqli-test",
                "info": {
                    "name": "Custom SQL Injection Test",
                    "author": "bug-bounty-scanner",
                    "severity": "high",
                    "tags": ["sqli", "injection"]
                },
                "requests": [{
                    "method": "GET",
                    "path": ["{{BaseURL}}/?id=' OR '1'='1"],
                    "matchers": [{
                        "type": "word",
                        "words": ["mysql", "sql", "syntax error"],
                        "part": "body",
                        "condition": "or"
                    }]
                }]
            }
        }

        return templates.get(vuln_type, {})