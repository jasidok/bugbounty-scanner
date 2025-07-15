#!/usr/bin/env python3
"""
Smart Contract False Positive Verification Module
Enhanced vulnerability detection with false positive filtering
"""

import re
import logging
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class VerificationResult:
    """Result of false positive verification"""
    is_false_positive: bool
    reason: str
    confidence: float
    evidence: str

class SmartContractVerifier:
    """Verifies smart contract vulnerabilities to reduce false positives"""
    
    def __init__(self):
        self.solidity_version_pattern = r"pragma\s+solidity\s+([^\s;]+)"
        self.import_patterns = {
            'reentrancy_guard': r"import.*ReentrancyGuard",
            'safe_math': r"import.*SafeMath",
            'access_control': r"import.*AccessControl|import.*Ownable",
            'safe_erc20': r"import.*SafeERC20"
        }
        
    def verify_reentrancy_vulnerability(self, content: str, line_number: int) -> VerificationResult:
        """Verify if reentrancy vulnerability is a false positive"""
        lines = content.split('\n')
        
        # Check 1: Does contract inherit ReentrancyGuard?
        if re.search(self.import_patterns['reentrancy_guard'], content, re.IGNORECASE):
            if re.search(r"ReentrancyGuard", content):
                # Check if function uses nonReentrant modifier
                function_block = self._extract_function_block(lines, line_number)
                if re.search(r"nonReentrant", function_block):
                    return VerificationResult(
                        is_false_positive=True,
                        reason="Function uses ReentrancyGuard with nonReentrant modifier",
                        confidence=0.95,
                        evidence="ReentrancyGuard inheritance and nonReentrant modifier found"
                    )
        
        # Check 2: Is it a checks-effects-interactions pattern?
        if self._follows_cei_pattern(lines, line_number):
            return VerificationResult(
                is_false_positive=True,
                reason="Follows checks-effects-interactions pattern",
                confidence=0.8,
                evidence="State changes occur before external calls"
            )
            
        # Check 3: Is external call using low-level call that could be reentrancy?
        external_call_line = lines[line_number].strip()
        if ".call{" in external_call_line or ".delegatecall(" in external_call_line:
            # This could be legitimate reentrancy risk
            return VerificationResult(
                is_false_positive=False,
                reason="Low-level call without reentrancy protection",
                confidence=0.7,
                evidence=f"External call: {external_call_line}"
            )
            
        return VerificationResult(
            is_false_positive=False,
            reason="Potential reentrancy vulnerability found",
            confidence=0.6,
            evidence="External call pattern detected"
        )
    
    def verify_overflow_vulnerability(self, content: str, line_number: int) -> VerificationResult:
        """Verify if integer overflow vulnerability is a false positive"""
        # Check Solidity version
        version_match = re.search(self.solidity_version_pattern, content)
        if version_match:
            version = version_match.group(1)
            # Solidity 0.8.0+ has built-in overflow protection
            if self._is_version_gte(version, "0.8.0"):
                # Check if operation is in unchecked block
                lines = content.split('\n')
                if not self._is_in_unchecked_block(lines, line_number):
                    return VerificationResult(
                        is_false_positive=True,
                        reason="Solidity 0.8.0+ has built-in overflow protection",
                        confidence=0.98,
                        evidence=f"Solidity version {version} with checked arithmetic"
                    )
        
        # Check for SafeMath usage
        if re.search(self.import_patterns['safe_math'], content):
            lines = content.split('\n')
            line_content = lines[line_number].strip()
            if "SafeMath" in line_content or ".add(" in line_content or ".sub(" in line_content:
                return VerificationResult(
                    is_false_positive=True,
                    reason="SafeMath library is being used",
                    confidence=0.9,
                    evidence="SafeMath functions detected"
                )
        
        return VerificationResult(
            is_false_positive=False,
            reason="Potential overflow vulnerability",
            confidence=0.5,
            evidence="Arithmetic operation without overflow protection"
        )
    
    def verify_access_control_vulnerability(self, content: str, line_number: int) -> VerificationResult:
        """Verify if access control vulnerability is a false positive"""
        lines = content.split('\n')
        function_block = self._extract_function_block(lines, line_number)
        
        # Check for common access control patterns
        access_patterns = [
            r"onlyOwner",
            r"onlyManager", 
            r"onlyAdmin",
            r"require\s*\(\s*msg\.sender\s*==\s*owner",
            r"require\s*\(\s*.*\.hasRole\s*\(",
            r"modifier\s+only\w+",
            r"_checkRole\s*\(",
            r"AccessControl",
            r"auth\w*\s*\("
        ]
        
        for pattern in access_patterns:
            if re.search(pattern, function_block, re.IGNORECASE):
                return VerificationResult(
                    is_false_positive=True,
                    reason="Access control mechanism detected",
                    confidence=0.85,
                    evidence=f"Access control pattern found: {pattern}"
                )
        
        # Check if it's a view/pure function (doesn't modify state)
        if re.search(r"function.*\b(view|pure)\b", function_block):
            return VerificationResult(
                is_false_positive=True,
                reason="View/pure function doesn't require access control",
                confidence=0.9,
                evidence="Function is view or pure"
            )
            
        return VerificationResult(
            is_false_positive=False,
            reason="Missing access control on state-changing function",
            confidence=0.7,
            evidence="No access control patterns found"
        )
    
    def verify_fund_loss_vulnerability(self, content: str, line_number: int) -> VerificationResult:
        """Verify potential fund loss vulnerabilities"""
        lines = content.split('\n')
        function_block = self._extract_function_block(lines, line_number)
        
        # Check for proper transfer patterns
        transfer_patterns = [
            r"\.safeTransfer\s*\(",
            r"\.safeTransferFrom\s*\(",
            r"SafeERC20"
        ]
        
        for pattern in transfer_patterns:
            if re.search(pattern, function_block):
                return VerificationResult(
                    is_false_positive=True,
                    reason="Uses SafeERC20 for secure transfers",
                    confidence=0.9,
                    evidence="SafeERC20 transfer pattern detected"
                )
        
        # Check for withdrawal patterns with proper validation
        if re.search(r"withdraw|claim", function_block, re.IGNORECASE):
            # Look for balance checks
            if re.search(r"require\s*\(.*balance|require\s*\(.*amount", function_block):
                return VerificationResult(
                    is_false_positive=True,
                    reason="Withdrawal function has balance validation",
                    confidence=0.8,
                    evidence="Balance validation found in withdrawal function"
                )
        
        return VerificationResult(
            is_false_positive=False,
            reason="Potential fund loss vulnerability",
            confidence=0.6,
            evidence="Transfer or withdrawal pattern without proper validation"
        )
    
    def _extract_function_block(self, lines: List[str], line_number: int) -> str:
        """Extract the complete function block around a line"""
        # Find function start
        function_start = line_number
        for i in range(line_number, max(0, line_number - 20), -1):
            if re.search(r"function\s+\w+", lines[i]):
                function_start = i
                break
        
        # Find function end (simple heuristic)
        function_end = min(len(lines), line_number + 30)
        brace_count = 0
        found_opening = False
        
        for i in range(function_start, function_end):
            line = lines[i]
            if '{' in line:
                found_opening = True
                brace_count += line.count('{')
            if '}' in line:
                brace_count -= line.count('}')
            if found_opening and brace_count == 0:
                function_end = i + 1
                break
        
        return '\n'.join(lines[function_start:function_end])
    
    def _follows_cei_pattern(self, lines: List[str], external_call_line: int) -> bool:
        """Check if code follows checks-effects-interactions pattern"""
        # Look for state changes after external call
        for i in range(external_call_line + 1, min(len(lines), external_call_line + 10)):
            line = lines[i].strip()
            # Common state change patterns
            if re.search(r"=\s*[^=]|balance\s*[+-]=|\w+\s*[+-]=", line):
                return False  # State change after external call - bad pattern
        return True  # No state changes after external call - good pattern
    
    def _is_version_gte(self, version: str, target: str) -> bool:
        """Check if Solidity version is greater than or equal to target"""
        try:
            # Remove any modifiers like ^, ~, >=
            version = re.sub(r'[^\d.]', '', version)
            target = re.sub(r'[^\d.]', '', target)
            
            version_parts = [int(x) for x in version.split('.')]
            target_parts = [int(x) for x in target.split('.')]
            
            # Pad to same length
            max_len = max(len(version_parts), len(target_parts))
            version_parts.extend([0] * (max_len - len(version_parts)))
            target_parts.extend([0] * (max_len - len(target_parts)))
            
            return version_parts >= target_parts
        except:
            return False
    
    def _is_in_unchecked_block(self, lines: List[str], line_number: int) -> bool:
        """Check if line is within an unchecked block"""
        # Look backwards for unchecked block
        for i in range(line_number, max(0, line_number - 20), -1):
            if "unchecked" in lines[i] and "{" in lines[i]:
                # Found unchecked block start, check if our line is before the closing brace
                for j in range(i + 1, min(len(lines), line_number + 10)):
                    if "}" in lines[j]:
                        return j > line_number
                return True
        return False

class EnhancedSmartContractScanner:
    """Enhanced smart contract scanner with false positive verification"""
    
    def __init__(self, config):
        self.config = config
        self.verifier = SmartContractVerifier()
        self.vulnerability_patterns = self._load_vulnerability_patterns()
    
    def _load_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Load vulnerability patterns with verification rules"""
        return {
            "reentrancy": [
                r"\.call\{.*value.*\}",
                r"\.transfer\s*\(",
                r"\.send\s*\(",
                r"\.call\s*\(",
                r"\.delegatecall\s*\("
            ],
            "integer_overflow": [
                r"\+\s*\w+|\w+\s*\+",
                r"-\s*\w+|\w+\s*-",
                r"\*\s*\w+|\w+\s*\*",
                r"/\s*\w+|\w+\s*/"
            ],
            "access_control": [
                r"function.*public.*\{",
                r"function.*external.*\{"
            ],
            "fund_loss": [
                r"\.transfer\s*\(",
                r"\.send\s*\(",
                r"withdraw",
                r"claim"
            ]
        }
    
    def scan_solidity_file_enhanced(self, file_path: str) -> List[Dict]:
        """Enhanced Solidity file scanning with false positive verification"""
        results = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            # Run enhanced vulnerability checks
            results.extend(self._check_reentrancy_enhanced(content, file_path))
            results.extend(self._check_overflow_enhanced(content, file_path))
            results.extend(self._check_access_control_enhanced(content, file_path))
            results.extend(self._check_fund_loss_enhanced(content, file_path))
            
        except Exception as e:
            logger.error(f"Error scanning Solidity file {file_path}: {e}")
        
        return results
    
    def _check_reentrancy_enhanced(self, content: str, file_path: str) -> List[Dict]:
        """Enhanced reentrancy check with verification"""
        results = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in self.vulnerability_patterns["reentrancy"]:
                if re.search(pattern, line):
                    # Verify if it's a false positive
                    verification = self.verifier.verify_reentrancy_vulnerability(content, i)
                    
                    if not verification.is_false_positive:
                        results.append({
                            'target': file_path,
                            'vulnerability_type': 'Reentrancy',
                            'severity': 'High',
                            'line_number': i + 1,
                            'description': f"Potential reentrancy vulnerability at line {i+1}",
                            'evidence': f"External call: {line.strip()}",
                            'verification': verification,
                            'confidence': verification.confidence,
                            'verified': True
                        })
                    else:
                        logger.debug(f"False positive filtered: {verification.reason}")
        
        return results
    
    def _check_overflow_enhanced(self, content: str, file_path: str) -> List[Dict]:
        """Enhanced overflow check with verification"""
        results = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in self.vulnerability_patterns["integer_overflow"]:
                if re.search(pattern, line) and any(x in line for x in ['uint', 'int']):
                    # Verify if it's a false positive
                    verification = self.verifier.verify_overflow_vulnerability(content, i)
                    
                    if not verification.is_false_positive:
                        results.append({
                            'target': file_path,
                            'vulnerability_type': 'Integer Overflow',
                            'severity': 'Medium',
                            'line_number': i + 1,
                            'description': f"Potential integer overflow at line {i+1}",
                            'evidence': f"Arithmetic operation: {line.strip()}",
                            'verification': verification,
                            'confidence': verification.confidence,
                            'verified': True
                        })
                    else:
                        logger.debug(f"False positive filtered: {verification.reason}")
        
        return results
    
    def _check_access_control_enhanced(self, content: str, file_path: str) -> List[Dict]:
        """Enhanced access control check with verification"""
        results = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            if re.search(r'function.*\b(public|external)\b', line):
                # Verify if it's a false positive
                verification = self.verifier.verify_access_control_vulnerability(content, i)
                
                if not verification.is_false_positive:
                    results.append({
                        'target': file_path,
                        'vulnerability_type': 'Missing Access Control',
                        'severity': 'Medium',
                        'line_number': i + 1,
                        'description': f"Public/external function without access control at line {i+1}",
                        'evidence': f"Function: {line.strip()}",
                        'verification': verification,
                        'confidence': verification.confidence,
                        'verified': True
                    })
                else:
                    logger.debug(f"False positive filtered: {verification.reason}")
        
        return results
    
    def _check_fund_loss_enhanced(self, content: str, file_path: str) -> List[Dict]:
        """Enhanced fund loss check with verification"""
        results = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in self.vulnerability_patterns["fund_loss"]:
                if re.search(pattern, line, re.IGNORECASE):
                    # Verify if it's a false positive
                    verification = self.verifier.verify_fund_loss_vulnerability(content, i)
                    
                    if not verification.is_false_positive:
                        results.append({
                            'target': file_path,
                            'vulnerability_type': 'Potential Fund Loss',
                            'severity': 'High',
                            'line_number': i + 1,
                            'description': f"Potential fund loss vulnerability at line {i+1}",
                            'evidence': f"Transfer/withdrawal: {line.strip()}",
                            'verification': verification,
                            'confidence': verification.confidence,
                            'verified': True
                        })
                    else:
                        logger.debug(f"False positive filtered: {verification.reason}")
        
        return results

def scan_directory_for_contracts(directory_path: str) -> List[Dict]:
    """Scan directory for Solidity contracts with enhanced verification"""
    scanner = EnhancedSmartContractScanner(None)
    all_results = []
    
    for sol_file in Path(directory_path).rglob("*.sol"):
        logger.info(f"Scanning {sol_file}")
        results = scanner.scan_solidity_file_enhanced(str(sol_file))
        all_results.extend(results)
    
    return all_results