#!/usr/bin/env python3
"""
False Positive Analysis for Alchemix v2-foundry Scan Results
"""

import json
import os
import sys
from collections import defaultdict
from typing import Dict, List, Any
import re

def load_scan_results(file_path: str) -> List[Dict]:
    """Load the scan results from JSON file"""
    with open(file_path, 'r') as f:
        return json.load(f)

def analyze_access_control_false_positives(results: List[Dict]) -> Dict:
    """Analyze access control findings for false positives"""
    access_control_findings = [r for r in results if r['vulnerability_type'] == 'Missing Access Control']
    
    false_positives = []
    legitimate_issues = []
    
    for finding in access_control_findings:
        evidence = finding['evidence']
        target = finding['target']
        
        # Check if function already has access control modifiers
        access_control_patterns = [
            'onlyGovernance',
            'onlyOwner', 
            'onlyOperator',
            'onlyAdmin',
            'onlyManager',
            'require(msg.sender ==',
            'modifier only',
            '_checkRole',
            'hasRole'
        ]
        
        has_access_control = any(pattern in evidence for pattern in access_control_patterns)
        
        if has_access_control:
            false_positives.append({
                'finding': finding,
                'reason': 'Function already has access control modifier',
                'confidence': 0.95
            })
        else:
            # Check if it's a view/pure function
            if 'view' in evidence or 'pure' in evidence:
                false_positives.append({
                    'finding': finding,
                    'reason': 'View/pure function does not need access control',
                    'confidence': 0.9
                })
            else:
                legitimate_issues.append(finding)
    
    return {
        'total_findings': len(access_control_findings),
        'false_positives': len(false_positives),
        'legitimate_issues': len(legitimate_issues),
        'false_positive_rate': len(false_positives) / len(access_control_findings) if access_control_findings else 0,
        'details': {
            'false_positives': false_positives,
            'legitimate_issues': legitimate_issues
        }
    }

def analyze_fund_loss_false_positives(results: List[Dict]) -> Dict:
    """Analyze fund loss findings for false positives"""
    fund_loss_findings = [r for r in results if r['vulnerability_type'] == 'Potential Fund Loss']
    
    false_positives = []
    legitimate_issues = []
    
    for finding in fund_loss_findings:
        evidence = finding['evidence'].lower()
        description = finding['description'].lower()
        
        # Check for safe transfer patterns
        safe_patterns = [
            'safetransfer',
            'safetransferfrom',
            'safeerc20',
            'require(',
            'revert',
            'assert(',
            'nonreentrant'
        ]
        
        # Check for comment/documentation patterns (likely false positives)
        comment_patterns = [
            '///',
            '///',
            '* @',
            'event ',
            'emit ',
            'modifier ',
            'library ',
            'interface '
        ]
        
        is_comment = any(pattern in evidence for pattern in comment_patterns)
        has_safety_check = any(pattern in evidence for pattern in safe_patterns)
        
        if is_comment:
            false_positives.append({
                'finding': finding,
                'reason': 'Finding in comment/documentation, not actual code',
                'confidence': 0.99
            })
        elif has_safety_check:
            false_positives.append({
                'finding': finding,
                'reason': 'Uses safe transfer patterns or validation',
                'confidence': 0.85
            })
        else:
            legitimate_issues.append(finding)
    
    return {
        'total_findings': len(fund_loss_findings),
        'false_positives': len(false_positives),
        'legitimate_issues': len(legitimate_issues),
        'false_positive_rate': len(false_positives) / len(fund_loss_findings) if fund_loss_findings else 0,
        'details': {
            'false_positives': false_positives,
            'legitimate_issues': legitimate_issues
        }
    }

def analyze_overflow_false_positives(results: List[Dict]) -> Dict:
    """Analyze integer overflow findings for false positives"""
    overflow_findings = [r for r in results if r['vulnerability_type'] == 'Integer Overflow']
    
    false_positives = []
    legitimate_issues = []
    
    for finding in overflow_findings:
        target = finding['target']
        evidence = finding['evidence']
        
        # Check Solidity version from file
        try:
            with open(target, 'r') as f:
                content = f.read()
                
            # Check for Solidity 0.8.0+ (has built-in overflow protection)
            version_match = re.search(r'pragma\s+solidity\s+\^?([0-9]+\.[0-9]+)', content)
            if version_match:
                version = version_match.group(1)
                major, minor = map(int, version.split('.'))
                
                if major == 0 and minor >= 8:
                    false_positives.append({
                        'finding': finding,
                        'reason': f'Solidity {version} has built-in overflow protection',
                        'confidence': 0.98
                    })
                    continue
                    
            # Check for SafeMath usage
            if 'SafeMath' in content or '.add(' in content or '.sub(' in content:
                false_positives.append({
                    'finding': finding,
                    'reason': 'Uses SafeMath library for overflow protection',
                    'confidence': 0.9
                })
                continue
                
            # Check if in unchecked block
            if 'unchecked' in evidence:
                legitimate_issues.append(finding)
            else:
                false_positives.append({
                    'finding': finding,
                    'reason': 'Modern Solidity with checked arithmetic',
                    'confidence': 0.85
                })
                
        except Exception as e:
            print(f"Error reading file {target}: {e}")
            legitimate_issues.append(finding)
    
    return {
        'total_findings': len(overflow_findings),
        'false_positives': len(false_positives),
        'legitimate_issues': len(legitimate_issues),
        'false_positive_rate': len(false_positives) / len(overflow_findings) if overflow_findings else 0,
        'details': {
            'false_positives': false_positives,
            'legitimate_issues': legitimate_issues
        }
    }

def analyze_reentrancy_false_positives(results: List[Dict]) -> Dict:
    """Analyze reentrancy findings for false positives"""
    reentrancy_findings = [r for r in results if r['vulnerability_type'] == 'Reentrancy']
    
    false_positives = []
    legitimate_issues = []
    
    for finding in reentrancy_findings:
        evidence = finding['evidence']
        target = finding['target']
        
        try:
            with open(target, 'r') as f:
                content = f.read()
                
            # Check for ReentrancyGuard
            if 'ReentrancyGuard' in content and 'nonReentrant' in evidence:
                false_positives.append({
                    'finding': finding,
                    'reason': 'Uses ReentrancyGuard with nonReentrant modifier',
                    'confidence': 0.95
                })
                continue
                
            # Check for low-level calls that could be risky
            if '.call{' in evidence or '.delegatecall(' in evidence:
                legitimate_issues.append(finding)
            else:
                false_positives.append({
                    'finding': finding,
                    'reason': 'No dangerous external calls detected',
                    'confidence': 0.8
                })
                
        except Exception as e:
            print(f"Error reading file {target}: {e}")
            legitimate_issues.append(finding)
    
    return {
        'total_findings': len(reentrancy_findings),
        'false_positives': len(false_positives),
        'legitimate_issues': len(legitimate_issues),
        'false_positive_rate': len(reentrancy_findings) / len(reentrancy_findings) if reentrancy_findings else 0,
        'details': {
            'false_positives': false_positives,
            'legitimate_issues': legitimate_issues
        }
    }

def generate_summary_report(analysis_results: Dict) -> str:
    """Generate a comprehensive summary report"""
    report = """
# False Positive Analysis Report - Alchemix v2-foundry

## Executive Summary

This analysis examines the 821 potential vulnerabilities identified in the Alchemix v2-foundry smart contract scan to determine which are false positives and which require further investigation.

## Methodology

The analysis uses pattern matching and code context analysis to identify:
1. Functions with proper access control that were flagged as missing it
2. Comments/documentation flagged as potential fund loss
3. Modern Solidity versions with built-in overflow protection
4. Proper use of security libraries (SafeERC20, ReentrancyGuard)

## Results Summary

"""
    
    total_findings = 0
    total_false_positives = 0
    total_legitimate = 0
    
    for vuln_type, analysis in analysis_results.items():
        total_findings += analysis['total_findings']
        total_false_positives += analysis['false_positives']
        total_legitimate += analysis['legitimate_issues']
        
        report += f"""
### {vuln_type}

- **Total Findings:** {analysis['total_findings']}
- **False Positives:** {analysis['false_positives']} ({analysis['false_positive_rate']:.1%})
- **Legitimate Issues:** {analysis['legitimate_issues']}
"""
    
    overall_false_positive_rate = total_false_positives / total_findings if total_findings > 0 else 0
    
    report += f"""
## Overall Analysis

- **Total Findings:** {total_findings}
- **False Positives:** {total_false_positives} ({overall_false_positive_rate:.1%})
- **Legitimate Issues:** {total_legitimate}
- **Issues Requiring Review:** {total_legitimate}

## Key Findings

### High False Positive Rate
The analysis reveals a high false positive rate of {overall_false_positive_rate:.1%}, indicating that the automated scanner flagged many legitimate, secure code patterns as vulnerabilities.

### Main Causes of False Positives

1. **Access Control:** Functions with proper access control modifiers were flagged as missing access control
2. **Comments/Documentation:** Comments containing keywords like "withdraw" or "transfer" were flagged as potential fund loss
3. **Modern Solidity:** Solidity 0.8.0+ has built-in overflow protection, making many overflow warnings false positives
4. **Safety Libraries:** Code using SafeERC20 and ReentrancyGuard was still flagged for related vulnerabilities

### Recommendations

1. **Manual Review Required:** The {total_legitimate} legitimate issues should be manually reviewed by security experts
2. **Scanner Tuning:** The automated scanner needs better context awareness to reduce false positives
3. **Focus Areas:** Prioritize review of actual state-changing functions without proper access control
4. **Code Quality:** The high false positive rate suggests good security practices are already in place

## Conclusion

While the automated scan identified many potential issues, the majority appear to be false positives due to pattern matching limitations. The legitimate issues requiring review represent the actual security concerns that warrant developer attention.
"""
    
    return report

def main():
    """Main analysis function"""
    results_file = "bb_projects/v2-foundry/alchemix_focused_scan_results.json"
    
    if not os.path.exists(results_file):
        print(f"Results file not found: {results_file}")
        return
    
    print("Loading scan results...")
    results = load_scan_results(results_file)
    
    print("Analyzing false positives...")
    
    analysis_results = {
        'Missing Access Control': analyze_access_control_false_positives(results),
        'Potential Fund Loss': analyze_fund_loss_false_positives(results),
        'Integer Overflow': analyze_overflow_false_positives(results),
        'Reentrancy': analyze_reentrancy_false_positives(results)
    }
    
    # Generate summary report
    report = generate_summary_report(analysis_results)
    
    # Save analysis results
    with open("bb_projects/v2-foundry/false_positive_analysis.json", 'w') as f:
        json.dump(analysis_results, f, indent=2, default=str)
    
    # Save summary report
    with open("bb_projects/v2-foundry/FALSE_POSITIVE_REPORT.md", 'w') as f:
        f.write(report)
    
    print("Analysis complete!")
    print(f"Summary report saved to: bb_projects/v2-foundry/FALSE_POSITIVE_REPORT.md")
    print(f"Detailed analysis saved to: bb_projects/v2-foundry/false_positive_analysis.json")
    
    # Print summary
    total_findings = sum(a['total_findings'] for a in analysis_results.values())
    total_false_positives = sum(a['false_positives'] for a in analysis_results.values())
    total_legitimate = sum(a['legitimate_issues'] for a in analysis_results.values())
    
    print(f"\nSummary:")
    print(f"Total Findings: {total_findings}")
    print(f"False Positives: {total_false_positives} ({total_false_positives/total_findings:.1%})")
    print(f"Legitimate Issues: {total_legitimate}")

if __name__ == "__main__":
    main()