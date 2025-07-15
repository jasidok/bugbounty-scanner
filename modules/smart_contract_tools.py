"""
Smart Contract Analysis Tools Integration
Integrates with popular smart contract security tools
"""

import subprocess
import json
import os
import re
from pathlib import Path
from typing import List, Dict, Any
import yaml

class SmartContractTools:
    """Integration with smart contract security tools"""

    def __init__(self):
        self.tools_config = {
            "slither": {
                "command": "slither",
                "args": ["--json", "-"]
            },
            "mythril": {
                "command": "myth",
                "args": ["analyze", "--output", "json"]
            },
            "echidna": {
                "command": "echidna-test",
                "args": []
            }
        }

    def run_slither(self, contract_path: str) -> Dict[str, Any]:
        """Run Slither analysis"""
        try:
            result = subprocess.run([
                "slither", contract_path, "--json", "-"
            ], capture_output=True, text=True)

            if result.returncode == 0:
                return json.loads(result.stdout)
        except Exception as e:
            print(f"Slither analysis failed: {e}")

        return {}

    def run_mythril(self, contract_path: str) -> Dict[str, Any]:
        """Run Mythril analysis"""
        try:
            result = subprocess.run([
                "myth", "analyze", contract_path, "--output", "json"
            ], capture_output=True, text=True)

            if result.returncode == 0:
                return json.loads(result.stdout)
        except Exception as e:
            print(f"Mythril analysis failed: {e}")

        return {}

    def create_echidna_config(self, contract_path: str) -> str:
        """Create Echidna configuration"""
        config = {
            "testMode": "property",
            "timeout": 300,
            "shrinkLimit": 5000,
            "seqLen": 100
        }

        config_file = Path(contract_path).parent / "echidna.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config, f)

        return str(config_file)

    def analyze_contract_comprehensive(self, contract_path: str) -> Dict[str, Any]:
        """Run comprehensive analysis with multiple tools"""
        results = {
            "slither": self.run_slither(contract_path),
            "mythril": self.run_mythril(contract_path),
            "manual_checks": self.manual_security_checks(contract_path)
        }

        return results

    def manual_security_checks(self, contract_path: str) -> List[Dict[str, Any]]:
        """Perform manual security checks"""
        findings = []

        with open(contract_path, 'r') as f:
            content = f.read()

        # Check for common issues
        checks = [
            {
                "pattern": r"\.call\.value\(",
                "type": "Reentrancy Risk",
                "severity": "High",
                "description": "External call with value transfer"
            },
            {
                "pattern": r"tx\.origin",
                "type": "tx.origin Usage",
                "severity": "Medium",
                "description": "Use of tx.origin for authorization"
            },
            {
                "pattern": r"block\.timestamp",
                "type": "Timestamp Dependence",
                "severity": "Low",
                "description": "Dependence on block timestamp"
            }
        ]

        for check in checks:
            if re.search(check["pattern"], content):
                findings.append(check)

        return findings